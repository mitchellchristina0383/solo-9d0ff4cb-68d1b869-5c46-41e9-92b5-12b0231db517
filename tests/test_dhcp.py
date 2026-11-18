"""Protocol, lease-safety, restart and failure-injection tests."""

from __future__ import annotations

import ipaddress
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.config import Settings
from app.dhcp.packet import (
    DHCPACK,
    DHCPDISCOVER,
    DHCPNAK,
    DHCPOFFER,
    DHCPRELEASE,
    DHCPREQUEST,
    OPTION_CLIENT_ID,
    OPTION_MESSAGE_TYPE,
    OPTION_REQUESTED_IP,
    OPTION_SERVER_ID,
    build_packet,
    parse_packet,
)
from app.dhcp.server import DhcpService
from app.dhcp.store import LeaseStore

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"
SERVER = "192.0.2.2"


class FakeClock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_settings(tmpdir: str, **overrides) -> Settings:
    values = dict(
        pool_start=ipaddress.IPv4Address("192.0.2.100"),
        pool_end=ipaddress.IPv4Address("192.0.2.103"),
        subnet_mask=ipaddress.IPv4Address("255.255.255.0"),
        server_identifier=ipaddress.IPv4Address(SERVER),
        broadcast=ipaddress.IPv4Address("192.0.2.255"),
        lease_time=60,
        offer_ttl=30,
        decline_quarantine=20,
        db_path=os.path.join(tmpdir, "leases.sqlite3"),
        udp_port=0,
        sim_target_port=0,
    )
    values.update(overrides)
    return Settings(**values)


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def discover(mac: str, xid: int = 1, client_id: bool = True) -> bytes:
    options = {}
    if client_id:
        options[OPTION_CLIENT_ID] = b"\x01" + mac_bytes(mac)
    return build_packet(
        op=1, xid=xid, chaddr=mac_bytes(mac), message_type=DHCPDISCOVER,
        flags=0x8000, options=options,
    )


def request(
    mac: str,
    ip: str | None,
    *,
    xid: int = 2,
    ciaddr: str = "0.0.0.0",
    server_id: str | None = SERVER,
    client_id: bool = True,
) -> bytes:
    options = {}
    if ip is not None:
        options[OPTION_REQUESTED_IP] = ipaddress.IPv4Address(ip).packed
    if server_id is not None:
        options[OPTION_SERVER_ID] = ipaddress.IPv4Address(server_id).packed
    if client_id:
        options[OPTION_CLIENT_ID] = b"\x01" + mac_bytes(mac)
    return build_packet(
        op=1,
        xid=xid,
        chaddr=mac_bytes(mac),
        message_type=DHCPREQUEST,
        ciaddr=ipaddress.IPv4Address(ciaddr),
        flags=0x8000,
        options=options,
    )


def release(mac: str, ip: str, *, xid: int = 3, server_id: str = SERVER) -> bytes:
    return build_packet(
        op=1,
        xid=xid,
        chaddr=mac_bytes(mac),
        message_type=DHCPRELEASE,
        ciaddr=ipaddress.IPv4Address(ip),
        options={
            OPTION_SERVER_ID: ipaddress.IPv4Address(server_id).packed,
            OPTION_CLIENT_ID: b"\x01" + mac_bytes(mac),
        },
    )


class Harness:
    def __init__(self, settings: Settings, clock: FakeClock | None = None) -> None:
        self.clock = clock or FakeClock()
        self.store = LeaseStore(settings, clock=self.clock)
        self.service = DhcpService(settings, self.store)

    def send(self, data: bytes):
        parsed = parse_packet(data)
        outcome = self.service.handle(parsed)
        reply = parse_packet(outcome.reply) if outcome.reply else None
        return outcome, reply

    def close(self) -> None:
        self.store.close()


class PacketTests(unittest.TestCase):
    def test_roundtrip_and_mac(self) -> None:
        packet = parse_packet(discover(MAC_A, xid=0xDEADBEEF))
        self.assertEqual(packet.message_type, DHCPDISCOVER)
        self.assertEqual(packet.mac, MAC_A)
        self.assertEqual(packet.xid, 0xDEADBEEF)
        self.assertEqual(packet.client_key(), "mac:" + MAC_A)
        self.assertEqual(packet.option(OPTION_MESSAGE_TYPE), bytes((DHCPDISCOVER,)))

    def test_client_id_type1_matches_mac_key(self) -> None:
        with_id = parse_packet(discover(MAC_A, client_id=True))
        without_id = parse_packet(discover(MAC_A, client_id=False))
        self.assertEqual(with_id.client_key(), without_id.client_key())

    def test_bad_cookie_rejected(self) -> None:
        from app.dhcp.packet import PacketError

        with self.assertRaises(PacketError):
            parse_packet(b"\x00" * 300)

    def test_all_zero_trailing_mac_keeps_its_length(self) -> None:
        with_zero = parse_packet(discover("02:00:00:00:00:00", client_id=False))
        self.assertEqual(with_zero.mac, "02:00:00:00:00:00")
        self.assertEqual(with_zero.hlen, 6)

    def test_nak_carries_only_server_id_and_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(make_settings(tmp))
            try:
                outcome, nak = h.send(request(MAC_A, "192.0.2.100"))
                self.assertEqual(outcome.action, "nak")
                self.assertIsNotNone(nak)
                self.assertNotIn(1, nak.options)  # no subnet mask
                self.assertNotIn(3, nak.options)  # no router
                self.assertNotIn(6, nak.options)  # no DNS
                self.assertIn(54, nak.options)  # server identifier
            finally:
                h.close()


class LeaseFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = make_settings(self.tmp.name)
        self.h = Harness(self.settings)

    def tearDown(self) -> None:
        self.h.close()
        self.tmp.cleanup()

    def test_offer_then_ack_and_ownership(self) -> None:
        outcome, offer = self.h.send(discover(MAC_A))
        self.assertEqual(outcome.action, "offer")
        self.assertEqual(offer.message_type, DHCPOFFER)
        offered_ip = str(offer.yiaddr)
        self.assertEqual(offered_ip, "192.0.2.100")

        # B may not claim A's reservation.
        outcome_b, nak = self.h.send(request(MAC_B, offered_ip))
        self.assertEqual(outcome_b.action, "nak")
        self.assertEqual(nak.message_type, DHCPNAK)
        self.assertEqual(str(nak.yiaddr), "0.0.0.0")

        # A can.
        outcome_a, ack = self.h.send(request(MAC_A, offered_ip))
        self.assertEqual(outcome_a.action, "ack")
        self.assertEqual(ack.message_type, DHCPACK)
        self.assertEqual(str(ack.yiaddr), offered_ip)
        self.assertEqual(ack.option(OPTION_SERVER_ID), ipaddress.IPv4Address(SERVER).packed)
        self.assertEqual(ack.option(51)[:4], (60).to_bytes(4, "big"))

    def test_offer_holds_address_until_expiry(self) -> None:
        outcome_a, offer_a = self.h.send(discover(MAC_A))
        self.h.send(discover(MAC_B))
        leases = {lease["ip"]: lease for lease in self.h.store.list_leases()}
        self.assertEqual(leases[str(offer_a.yiaddr)]["status"], "offered")
        self.assertEqual(len(leases), 2)

        # B cannot be offered A's still-valid offer, even after retransmissions.
        stats = self.h.store.stats()
        self.assertEqual(stats["offered"], 2)

        # Expire offers; address must be reusable.
        self.h.clock.advance(31)
        outcome_c, offer_c = self.h.send(discover("02:00:00:00:00:0c"))
        self.assertEqual(outcome_c.action, "offer")
        self.assertEqual(str(offer_c.yiaddr), "192.0.2.100")

    def test_expired_offer_cannot_be_claimed(self) -> None:
        _outcome, offer = self.h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        self.h.clock.advance(31)
        outcome, nak = self.h.send(request(MAC_A, offered))
        self.assertEqual(outcome.action, "nak")
        self.assertEqual(nak.message_type, DHCPNAK)

    def test_expired_bound_lease_is_reclaimed(self) -> None:
        _o, offer = self.h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        self.h.send(request(MAC_A, offered))
        self.assertEqual(self.h.store.stats()["bound"], 1)

        self.h.clock.advance(self.settings.lease_time + 1)
        # A stale renewal after expiry must be refused.
        outcome, nak = self.h.send(request(MAC_A, None, ciaddr=offered))
        self.assertEqual(outcome.action, "nak")
        self.assertEqual(nak.message_type, DHCPNAK)

        # And the address goes to someone else without conflict.
        _o, offer_b = self.h.send(discover(MAC_B))
        self.assertEqual(str(offer_b.yiaddr), offered)
        self.assertEqual(self.h.store.stats()["used"], 1)

    def test_renew_and_release_require_ownership(self) -> None:
        outcome, offer = self.h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        self.h.send(request(MAC_A, offered))

        # Wrong owner renewal via ciaddr is NAKed.
        outcome, nak = self.h.send(request(MAC_B, None, ciaddr=offered))
        self.assertEqual(outcome.action, "nak")

        # Wrong owner release is silently ignored, lease remains.
        outcome, _ = self.h.send(release(MAC_B, offered))
        self.assertEqual(outcome.action, "ignored")
        self.assertEqual(self.h.store.stats()["bound"], 1)

        # Correct owner renews via ciaddr.
        outcome, ack = self.h.send(request(MAC_A, None, ciaddr=offered))
        self.assertEqual(outcome.action, "ack")

        # Correct owner releases.
        outcome, _ = self.h.send(release(MAC_A, offered))
        self.assertEqual(outcome.action, "released")
        self.assertEqual(self.h.store.stats()["used"], 0)

        # Old offer/lease is gone, so re-request must be NAKed.
        outcome, _ = self.h.send(request(MAC_A, offered))
        self.assertEqual(outcome.action, "nak")

    def test_other_server_selection_withdraws_offer_only(self) -> None:
        _outcome, offer = self.h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        outcome, reply = self.h.send(
            request(MAC_A, offered, server_id="192.0.2.99")
        )
        self.assertEqual(outcome.action, "ignored")
        self.assertIsNone(reply)
        self.assertEqual(self.h.store.stats()["used"], 0)

    def test_retransmitted_discover_keeps_same_offer(self) -> None:
        _o1, offer1 = self.h.send(discover(MAC_A, xid=111))
        _o2, offer2 = self.h.send(discover(MAC_A, xid=222))
        self.assertEqual(str(offer1.yiaddr), str(offer2.yiaddr))
        self.assertEqual(self.h.store.stats()["offered"], 1)

    def test_discover_retransmission_after_bind_keeps_lease(self) -> None:
        _o, offer = self.h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        self.h.send(request(MAC_A, offered))
        _o, offer2 = self.h.send(discover(MAC_A))
        self.assertEqual(str(offer2.yiaddr), offered)
        lease = self.h.store.list_leases()[0]
        self.assertEqual(lease["status"], "bound")


class ConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = make_settings(self.tmp.name)
        # Larger pool for a meaningful race.
        self.settings = make_settings(
            self.tmp.name,
            pool_start=ipaddress.IPv4Address("192.0.2.100"),
            pool_end=ipaddress.IPv4Address("192.0.2.115"),
        )
        self.h = Harness(self.settings)

    def tearDown(self) -> None:
        self.h.close()
        self.tmp.cleanup()

    def test_parallel_discovers_never_share_an_address(self) -> None:
        results: list[tuple[str, str]] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(12)

        def worker(n: int) -> None:
            mac = f"02:00:00:00:01:{n:02x}"
            try:
                barrier.wait()
                _o, reply = self.h.send(discover(mac, xid=n + 1))
                results.append((mac, str(reply.yiaddr)))
            except BaseException as exc:  # pragma: no cover - failure detail
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(12)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        ips = [ip for _mac, ip in results]
        self.assertEqual(len(ips), 12)
        self.assertEqual(len(set(ips)), 12, f"duplicate offers: {ips}")
        self.assertEqual(self.h.store.stats()["used"], 12)

    def test_parallel_same_client_gets_one_offer(self) -> None:
        results: list[str] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            _o, reply = self.h.send(discover(MAC_A))
            results.append(str(reply.yiaddr))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(self.h.store.stats()["used"], 1)

    def test_parallel_requests_for_same_offer_all_ack_same_ip(self) -> None:
        _o, offer = self.h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        replies: list[tuple[str, str]] = []
        barrier = threading.Barrier(6)

        def worker() -> None:
            barrier.wait()
            outcome, reply = self.h.send(request(MAC_A, offered))
            replies.append((outcome.action, str(reply.yiaddr)))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual({action for action, _ip in replies}, {"ack"})
        self.assertEqual({ip for _a, ip in replies}, {offered})
        self.assertEqual(self.h.store.stats()["bound"], 1)


class RestartAndFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = make_settings(self.tmp.name)
        self.clock = FakeClock()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_confirmed_lease_survives_restart_and_blocks_others(self) -> None:
        h = Harness(self.settings, self.clock)
        _o, offer = h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        h.send(request(MAC_A, offered))
        h.close()

        h2 = Harness(self.settings, self.clock)
        try:
            leases = h2.store.list_leases()
            self.assertEqual(len(leases), 1)
            self.assertEqual(leases[0]["ip"], offered)
            self.assertEqual(leases[0]["status"], "bound")

            # Another client cannot take the surviving lease.
            _o, offer_b = h2.send(discover(MAC_B))
            self.assertNotEqual(str(offer_b.yiaddr), offered)
            outcome, _ = h2.send(request(MAC_B, offered))
            self.assertEqual(outcome.action, "nak")

            # Owner can still renew after restart.
            outcome, ack = h2.send(request(MAC_A, None, ciaddr=offered))
            self.assertEqual(outcome.action, "ack")
        finally:
            h2.close()

    def test_offer_reuse_after_restart(self) -> None:
        h = Harness(self.settings, self.clock)
        _o, offer = h.send(discover(MAC_A))
        offered = str(offer.yiaddr)
        h.close()

        h2 = Harness(self.settings, self.clock)
        try:
            _o, off_a = h2.send(discover(MAC_A))
            self.assertEqual(str(off_a.yiaddr), offered)
            _o, off_b = h2.send(discover(MAC_B))
            self.assertNotEqual(str(off_b.yiaddr), offered)
        finally:
            h2.close()

    def test_second_process_lock_is_rejected(self) -> None:
        h = Harness(self.settings, self.clock)
        try:
            with self.assertRaises(RuntimeError):
                LeaseStore(self.settings, clock=self.clock)
        finally:
            h.close()
        # After closing, a fresh store may take over.
        h2 = LeaseStore(self.settings, clock=self.clock)
        h2.close()

    def test_commit_failure_sends_no_ack_and_persists_nothing(self) -> None:
        h = Harness(self.settings, self.clock)
        try:
            # A valid offer must be committed before we simulate a dying disk.
            _o, offer = h.send(discover(MAC_A))
            offered = str(offer.yiaddr)

            original = h.store._commit

            def broken_commit(conn):
                raise OSError("simulated disk failure")

            h.store._commit = broken_commit  # type: ignore[method-assign]
            outcome, reply = h.send(request(MAC_A, offered))
            self.assertIsNone(reply)
            self.assertEqual(outcome.action, "store-error")

            # The lease is still only an offer, not a bound lease.
            leases = h.store.list_leases()
            self.assertEqual(leases[0]["status"], "offered")

            h.store._commit = original  # type: ignore[method-assign]
            outcome, ack = h.send(request(MAC_A, offered))
            self.assertEqual(outcome.action, "ack")
        finally:
            h.close()

    def test_commit_failure_on_discover_sends_no_offer(self) -> None:
        h = Harness(self.settings, self.clock)
        try:
            def broken_commit(conn):
                raise OSError("simulated disk failure")

            h.store._commit = broken_commit  # type: ignore[method-assign]
            outcome, reply = h.send(discover(MAC_A))
            self.assertIsNone(reply)
            self.assertEqual(outcome.action, "store-error")
            h.store._commit = type(h.store)._commit.__get__(h.store)  # type: ignore[method-assign]
            self.assertEqual(h.store.stats()["used"], 0)
        finally:
            h.close()

    def test_store_rejects_foreign_pool_database(self) -> None:
        h = Harness(self.settings, self.clock)
        h.close()
        other = make_settings(
            self.tmp.name,
            pool_start=ipaddress.IPv4Address("192.0.2.50"),
            pool_end=ipaddress.IPv4Address("192.0.2.60"),
        )
        with self.assertRaises(RuntimeError):
            LeaseStore(other, clock=self.clock)

    def test_events_record_expiry(self) -> None:
        h = Harness(self.settings, self.clock)
        try:
            _o, offer = h.send(discover(MAC_A))
            self.h = h
            h.clock.advance(31)
            h.send(discover(MAC_B))
            events = h.store.list_events(20)
            self.assertTrue(
                any(event["message_type"] == "OFFER_EXPIRED" for event in events)
            )
        finally:
            h.close()


class PoolExhaustionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = make_settings(
            self.tmp.name,
            pool_start=ipaddress.IPv4Address("192.0.2.100"),
            pool_end=ipaddress.IPv4Address("192.0.2.101"),
        )
        self.h = Harness(self.settings)

    def tearDown(self) -> None:
        self.h.close()
        self.tmp.cleanup()

    def test_exhaustion_is_silent_and_existing_lease_intact(self) -> None:
        self.h.send(discover(MAC_A))
        self.h.send(discover(MAC_B))
        outcome, reply = self.h.send(discover("02:00:00:00:00:0c"))
        self.assertEqual(outcome.action, "pool-exhausted")
        self.assertIsNone(reply)
        self.assertEqual(self.h.store.stats()["free"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
