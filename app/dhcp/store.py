"""Durable, transactional lease state for one fixed DHCPv4 pool.

All allocation decisions happen inside a single SQLite `BEGIN IMMEDIATE`
transaction, so a concurrent handler can never observe the same free address
twice. A lease row is committed (with `synchronous=FULL`) before the caller is
allowed to emit an OFFER or ACK. Offers and bound leases are both persisted,
which is what makes offer validity and confirmed leases survive a restart.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..config import Settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    ip TEXT PRIMARY KEY,
    client_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('offered', 'bound', 'declined')),
    hostname TEXT,
    client_mac TEXT,
    xid INTEGER,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS leases_one_per_client
    ON leases(client_key) WHERE status IN ('offered', 'bound');
CREATE INDEX IF NOT EXISTS leases_expires ON leases(expires_at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    category TEXT NOT NULL,
    message_type TEXT,
    xid INTEGER,
    client_key TEXT,
    ip TEXT,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events(at);
"""


@dataclass(frozen=True)
class Lease:
    ip: str
    client_key: str
    status: str
    hostname: str | None
    client_mac: str | None
    xid: int | None
    created_at: float
    updated_at: float
    expires_at: float

    def as_dict(self, now: float) -> dict:
        return {
            "ip": self.ip,
            "client_key": self.client_key,
            "status": self.status,
            "hostname": self.hostname,
            "client_mac": self.client_mac,
            "xid": f"0x{self.xid:08x}" if self.xid is not None else None,
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
            "expires_at": iso(self.expires_at),
            "remaining_seconds": max(0, int(self.expires_at - now + 0.999)),
        }


def iso(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


@dataclass(frozen=True)
class OfferResult:
    kind: str  # "offer" | "exhausted"
    ip: str | None = None
    reused: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class RequestResult:
    kind: str  # "ack" | "nak" | "ignore"
    ip: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class SimpleResult:
    kind: str
    ip: str | None = None
    reason: str | None = None


def _fingerprint(settings: Settings) -> str:
    return json.dumps(
        {
            "pool_start": str(settings.pool_start),
            "pool_end": str(settings.pool_end),
            "subnet_mask": str(settings.subnet_mask),
            "server_id": str(settings.server_identifier),
        },
        sort_keys=True,
    )


class LeaseStore:
    """SQLite-backed lease store. Safe to call from multiple threads."""

    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.time,
        acquire_process_lock: bool = True,
    ) -> None:
        self.settings = settings
        self._clock = clock
        self._lock = threading.RLock()
        self._event_writes = 0
        self._closed = False
        self._lock_file = None
        # Drill-only switch; see inject_next_commit_failure().
        self._commit_failures_left = 0

        path = Path(settings.db_path)
        if path.parent and str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = str(path)

        if acquire_process_lock:
            self._acquire_process_lock()
        try:
            self._initialize_schema()
        except BaseException:
            self.close()
            raise

    # -- lifecycle ---------------------------------------------------------

    def _acquire_process_lock(self) -> None:
        lock_path = self.db_path + ".lock"
        handle = open(lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise RuntimeError(
                f"another DHCP server process already owns {self.db_path}"
            ) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        self._lock_file = handle

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._lock_file is not None:
            try:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock_file.close()
                self._lock_file = None

    def __enter__(self) -> "LeaseStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- sqlite plumbing ---------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.executescript(SCHEMA)
                fingerprint = _fingerprint(self.settings)
                row = conn.execute(
                    "SELECT value FROM meta WHERE key = 'pool_fingerprint'"
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO meta(key, value) VALUES ('pool_fingerprint', ?)",
                        (fingerprint,),
                    )
                elif row["value"] != fingerprint:
                    raise RuntimeError(
                        "database belongs to a different pool/server configuration; "
                        f"expected {row['value']}, got {fingerprint}. "
                        "Use a fresh DHCP_DB_PATH for a different pool."
                    )
                pool = {str(ip) for ip in self.settings.pool_ips()}
                outside = [
                    row["ip"]
                    for row in conn.execute("SELECT ip FROM leases").fetchall()
                    if row["ip"] not in pool
                ]
                if outside:
                    raise RuntimeError(
                        "database contains leases outside the configured pool: "
                        + ", ".join(sorted(outside))
                    )
            finally:
                conn.close()

    def inject_next_commit_failure(self, count: int = 1) -> None:
        """Drill hook: make the next `count` lease commits fail after SQL runs.

        The failure is raised before COMMIT, exactly like a full/failing disk:
        the transaction rolls back and the caller must not reply ACK/OFFER.
        """
        with self._lock:
            self._commit_failures_left = max(0, int(count))

    def _commit(self, conn: sqlite3.Connection) -> None:
        with self._lock:
            if self._commit_failures_left > 0:
                self._commit_failures_left -= 1
                raise OSError("injected commit failure (drill)")
        conn.execute("COMMIT")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One serialized write transaction. Commit happens before returning."""
        with self._lock:
            if self._closed:
                raise RuntimeError("lease store is closed")
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    yield conn
                    self._commit(conn)
                except BaseException:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
            finally:
                conn.close()

    def _purge_expired(self, conn: sqlite3.Connection, now: float) -> None:
        expired = conn.execute(
            "SELECT ip, client_key, status, expires_at FROM leases WHERE expires_at <= ?",
            (now,),
        ).fetchall()
        if not expired:
            return
        for row in expired:
            label = {
                "bound": "LEASE_EXPIRED",
                "offered": "OFFER_EXPIRED",
                "declined": "DECLINE_QUARANTINE_ENDED",
            }.get(row["status"], "LEASE_EXPIRED")
            conn.execute(
                "INSERT INTO events(at, category, message_type, client_key, ip, detail) "
                "VALUES (?, 'expire', ?, ?, ?, ?)",
                (
                    now,
                    label,
                    row["client_key"],
                    row["ip"],
                    json.dumps(
                        {
                            "status": row["status"],
                            "expired_at": iso(row["expires_at"]),
                        }
                    ),
                ),
            )
        conn.execute("DELETE FROM leases WHERE expires_at <= ?", (now,))

    @staticmethod
    def _row_to_lease(row: sqlite3.Row) -> Lease:
        return Lease(
            ip=row["ip"],
            client_key=row["client_key"],
            status=row["status"],
            hostname=row["hostname"],
            client_mac=row["client_mac"],
            xid=row["xid"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
        )

    def _active_for_client(
        self, conn: sqlite3.Connection, client_key: str, now: float
    ) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM leases WHERE client_key = ? "
            "AND status IN ('offered', 'bound') AND expires_at > ?",
            (client_key, now),
        ).fetchone()

    def _log_event(
        self,
        conn: sqlite3.Connection,
        *,
        now: float,
        category: str,
        message_type: str | None,
        xid: int | None,
        client_key: str | None,
        ip: str | None,
        detail: dict,
    ) -> None:
        conn.execute(
            "INSERT INTO events(at, category, message_type, xid, client_key, ip, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                now,
                category,
                message_type,
                xid,
                client_key,
                ip,
                json.dumps(detail, separators=(",", ":")),
            ),
        )
        self._event_writes += 1
        if self._event_writes % 500 == 0:
            # Keep the audit trail bounded without a separate maintenance job.
            conn.execute(
                "DELETE FROM events WHERE id <= "
                "(SELECT COALESCE(MAX(id), 0) - 5000 FROM events)"
            )

    # -- DHCP operations ---------------------------------------------------

    def offer(
        self,
        *,
        client_key: str,
        client_mac: str | None,
        hostname: str | None,
        xid: int,
    ) -> OfferResult:
        """Reserve an address for a DISCOVER, idempotently for retransmissions."""
        with self._transaction() as conn:
            now = self._clock()
            self._purge_expired(conn, now)
            existing = self._active_for_client(conn, client_key, now)
            if existing is not None:
                if existing["status"] == "offered":
                    conn.execute(
                        "UPDATE leases SET expires_at = ?, updated_at = ?, "
                        "hostname = COALESCE(?, hostname), client_mac = COALESCE(?, client_mac), "
                        "xid = ? WHERE ip = ?",
                        (
                            now + self.settings.offer_ttl,
                            now,
                            hostname,
                            client_mac,
                            xid,
                            existing["ip"],
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE leases SET updated_at = ?, "
                        "hostname = COALESCE(?, hostname), client_mac = COALESCE(?, client_mac), "
                        "xid = ? WHERE ip = ?",
                        (now, hostname, client_mac, xid, existing["ip"]),
                    )
                self._log_event(
                    conn,
                    now=now,
                    category="lease",
                    message_type="DHCPOFFER",
                    xid=xid,
                    client_key=client_key,
                    ip=existing["ip"],
                    detail={
                        "action": "reuse-reservation",
                        "status": existing["status"],
                    },
                )
                return OfferResult(
                    kind="offer",
                    ip=existing["ip"],
                    reused=True,
                )

            used = {
                row["ip"] for row in conn.execute("SELECT ip FROM leases").fetchall()
            }
            selected: str | None = None
            for candidate in self.settings.pool_ips():
                if str(candidate) not in used:
                    selected = str(candidate)
                    break
            if selected is None:
                self._log_event(
                    conn,
                    now=now,
                    category="lease",
                    message_type="DHCPOFFER",
                    xid=xid,
                    client_key=client_key,
                    ip=None,
                    detail={"action": "pool-exhausted"},
                )
                return OfferResult(kind="exhausted", reason="address pool exhausted")

            conn.execute(
                "INSERT INTO leases(ip, client_key, status, hostname, client_mac, xid, "
                "created_at, updated_at, expires_at) "
                "VALUES (?, ?, 'offered', ?, ?, ?, ?, ?, ?)",
                (
                    selected,
                    client_key,
                    hostname,
                    client_mac,
                    xid,
                    now,
                    now,
                    now + self.settings.offer_ttl,
                ),
            )
            self._log_event(
                conn,
                now=now,
                category="lease",
                message_type="DHCPOFFER",
                xid=xid,
                client_key=client_key,
                ip=selected,
                detail={"action": "reserve", "status": "offered"},
            )
            return OfferResult(kind="offer", ip=selected)

    def request(
        self,
        *,
        client_key: str,
        client_mac: str | None,
        hostname: str | None,
        xid: int,
        requested_ip: ipaddress.IPv4Address | None,
        ciaddr: ipaddress.IPv4Address,
        server_id: ipaddress.IPv4Address | None,
    ) -> RequestResult:
        """Bind/renew only a still-valid reservation owned by this client."""
        with self._transaction() as conn:
            now = self._clock()
            self._purge_expired(conn, now)

            target: ipaddress.IPv4Address | None = requested_ip
            if target is None and ciaddr != ipaddress.IPv4Address("0.0.0.0"):
                target = ciaddr

            if server_id is not None and server_id != self.settings.server_identifier:
                # The client selected another server. Withdraw only our still
                # offered reservation; never touch a bound lease here.
                if target is not None:
                    conn.execute(
                        "DELETE FROM leases WHERE ip = ? AND client_key = ? "
                        "AND status = 'offered'",
                        (str(target), client_key),
                    )
                    self._log_event(
                        conn,
                        now=now,
                        category="lease",
                        message_type="DHCPREQUEST",
                        xid=xid,
                        client_key=client_key,
                        ip=str(target),
                        detail={"action": "withdraw-offer", "other_server": str(server_id)},
                    )
                return RequestResult(
                    kind="ignore", ip=str(target) if target else None,
                    reason=f"client selected server {server_id}",
                )

            if target is None:
                self._log_event(
                    conn,
                    now=now,
                    category="lease",
                    message_type="DHCPREQUEST",
                    xid=xid,
                    client_key=client_key,
                    ip=None,
                    detail={"action": "nak", "reason": "no requested address"},
                )
                return RequestResult(kind="nak", reason="no requested address")

            row = conn.execute(
                "SELECT * FROM leases WHERE ip = ?", (str(target),)
            ).fetchone()
            if row is None:
                reason = "no valid reservation for this address"
            elif row["client_key"] != client_key:
                reason = "address is reserved for a different client"
            elif row["status"] not in ("offered", "bound"):
                reason = "address is not available for this client"
            elif row["expires_at"] <= now:
                # Normally purged above; this is defence in depth.
                reason = "reservation has expired"
            else:
                conn.execute(
                    "UPDATE leases SET status = 'bound', client_key = ?, "
                    "client_mac = COALESCE(?, client_mac), "
                    "hostname = COALESCE(?, hostname), "
                    "updated_at = ?, expires_at = ?, xid = ? WHERE ip = ?",
                    (
                        client_key,
                        client_mac,
                        hostname,
                        now,
                        now + self.settings.lease_time,
                        xid,
                        str(target),
                    ),
                )
                self._log_event(
                    conn,
                    now=now,
                    category="lease",
                    message_type="DHCPACK",
                    xid=xid,
                    client_key=client_key,
                    ip=str(target),
                    detail={
                        "action": "renew" if row["status"] == "bound" else "bind",
                        "lease_time": self.settings.lease_time,
                    },
                )
                return RequestResult(kind="ack", ip=str(target))

            self._log_event(
                conn,
                now=now,
                category="lease",
                message_type="DHCPNAK",
                xid=xid,
                client_key=client_key,
                ip=str(target),
                detail={"action": "nak", "reason": reason},
            )
            return RequestResult(kind="nak", ip=str(target), reason=reason)

    def release(
        self,
        *,
        client_key: str,
        xid: int,
        ciaddr: ipaddress.IPv4Address,
        server_id: ipaddress.IPv4Address | None,
    ) -> SimpleResult:
        with self._transaction() as conn:
            now = self._clock()
            self._purge_expired(conn, now)
            target = str(ciaddr)
            row = conn.execute(
                "SELECT * FROM leases WHERE ip = ?", (target,)
            ).fetchone()
            if server_id is not None and server_id != self.settings.server_identifier:
                reason = "release is for a different server"
                kind = "ignored"
            elif row is None:
                reason = "no active lease for this address"
                kind = "ignored"
            elif row["client_key"] != client_key:
                reason = "lease belongs to a different client"
                kind = "ignored"
            elif row["status"] not in ("offered", "bound"):
                reason = "address is not leased to a client"
                kind = "ignored"
            else:
                conn.execute("DELETE FROM leases WHERE ip = ?", (target,))
                self._log_event(
                    conn,
                    now=now,
                    category="lease",
                    message_type="DHCPRELEASE",
                    xid=xid,
                    client_key=client_key,
                    ip=target,
                    detail={"action": "release", "previous_status": row["status"]},
                )
                return SimpleResult(kind="released", ip=target)
            self._log_event(
                conn,
                now=now,
                category="lease",
                message_type="DHCPRELEASE",
                xid=xid,
                client_key=client_key,
                ip=target,
                detail={"action": "ignore-release", "reason": reason},
            )
            return SimpleResult(kind=kind, ip=target, reason=reason)

    def decline(
        self,
        *,
        client_key: str,
        xid: int,
        requested_ip: ipaddress.IPv4Address | None,
        server_id: ipaddress.IPv4Address | None,
    ) -> SimpleResult:
        """Quarantine an address this client had reserved (defensive support)."""
        with self._transaction() as conn:
            now = self._clock()
            self._purge_expired(conn, now)
            if requested_ip is None:
                return SimpleResult(kind="ignored", reason="no declined address")
            if server_id is not None and server_id != self.settings.server_identifier:
                return SimpleResult(
                    kind="ignored", ip=str(requested_ip),
                    reason="decline is for a different server",
                )
            row = conn.execute(
                "SELECT * FROM leases WHERE ip = ?", (str(requested_ip),)
            ).fetchone()
            if (
                row is None
                or row["client_key"] != client_key
                or row["status"] not in ("offered", "bound")
            ):
                self._log_event(
                    conn,
                    now=now,
                    category="lease",
                    message_type="DHCPDECLINE",
                    xid=xid,
                    client_key=client_key,
                    ip=str(requested_ip),
                    detail={"action": "ignore-decline", "reason": "not owned by client"},
                )
                return SimpleResult(
                    kind="ignored", ip=str(requested_ip),
                    reason="not owned by client",
                )
            # Keep the row occupied until the quarantine ends; client_key is
            # retained for the audit trail but the unique active index no
            # longer applies to declined rows.
            conn.execute(
                "UPDATE leases SET status = 'declined', updated_at = ?, expires_at = ? "
                "WHERE ip = ?",
                (now, now + self.settings.decline_quarantine, str(requested_ip)),
            )
            self._log_event(
                conn,
                now=now,
                category="lease",
                message_type="DHCPDECLINE",
                xid=xid,
                client_key=client_key,
                ip=str(requested_ip),
                detail={"action": "quarantine", "seconds": self.settings.decline_quarantine},
            )
            return SimpleResult(kind="quarantined", ip=str(requested_ip))

    # -- observation -------------------------------------------------------

    def list_leases(self) -> list[dict]:
        now = self._clock()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM leases WHERE expires_at > ?", (now,)
                ).fetchall()
            finally:
                conn.close()
        leases = [self._row_to_lease(row) for row in rows]
        leases.sort(key=lambda lease: int(ipaddress.IPv4Address(lease.ip)))
        return [lease.as_dict(now) for lease in leases]

    def stats(self) -> dict:
        now = self._clock()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT status, COUNT(*) AS n FROM leases "
                    "WHERE expires_at > ? GROUP BY status",
                    (now,),
                ).fetchall()
            finally:
                conn.close()
        counts = {"offered": 0, "bound": 0, "declined": 0}
        for row in rows:
            counts[row["status"]] = row["n"]
        active = sum(counts.values())
        return {
            "pool_start": str(self.settings.pool_start),
            "pool_end": str(self.settings.pool_end),
            "pool_size": self.settings.pool_size,
            "offered": counts["offered"],
            "bound": counts["bound"],
            "declined": counts["declined"],
            "used": active,
            "free": self.settings.pool_size - active,
            "lease_time": self.settings.lease_time,
            "offer_ttl": self.settings.offer_ttl,
        }

    def list_events(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            finally:
                conn.close()
        events = []
        for row in rows:
            try:
                detail = json.loads(row["detail"])
            except (TypeError, ValueError):
                detail = {"raw": row["detail"]}
            events.append(
                {
                    "id": row["id"],
                    "at": iso(row["at"]),
                    "category": row["category"],
                    "message_type": row["message_type"],
                    "xid": f"0x{row['xid']:08x}" if row["xid"] is not None else None,
                    "client_key": row["client_key"],
                    "ip": row["ip"],
                    "detail": detail,
                }
            )
        return events

    def new_xid(self) -> int:
        return uuid.uuid4().int & 0xFFFFFFFF
