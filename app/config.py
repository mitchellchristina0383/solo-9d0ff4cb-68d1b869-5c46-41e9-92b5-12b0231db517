"""Runtime configuration for the isolated-lab DHCPv4 service."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _env_float(name: str, default: float) -> float:
    raw = _env(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    return value


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _ipv4(value: str, name: str) -> ipaddress.IPv4Address:
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{name} is not a valid IPv4 address: {value!r}") from exc
    return addr


@dataclass(frozen=True)
class Settings:
    """All knobs for one fixed pool. A single process serves exactly one pool."""

    pool_start: ipaddress.IPv4Address = ipaddress.IPv4Address("192.0.2.100")
    pool_end: ipaddress.IPv4Address = ipaddress.IPv4Address("192.0.2.110")
    subnet_mask: ipaddress.IPv4Address = ipaddress.IPv4Address("255.255.255.0")
    router: ipaddress.IPv4Address = ipaddress.IPv4Address("192.0.2.1")
    dns_servers: tuple[ipaddress.IPv4Address, ...] = (
        ipaddress.IPv4Address("192.0.2.53"),
    )
    server_identifier: ipaddress.IPv4Address = ipaddress.IPv4Address("192.0.2.2")
    broadcast: ipaddress.IPv4Address = ipaddress.IPv4Address("192.0.2.255")
    lease_time: int = 120
    offer_ttl: float = 60.0
    decline_quarantine: int = 300
    udp_host: str = "0.0.0.0"
    udp_port: int = 6767
    relay_port: int = 67
    db_path: str = "./data/dhcp.sqlite3"
    sim_target_host: str = "127.0.0.1"
    # 0 means "follow the port the UDP listener actually bound".
    sim_target_port: int = 0
    sim_timeout: float = 1.5
    # Off by default. When enabled, the web API exposes a drill-only endpoint
    # that makes the next lease commit fail, to demonstrate the no-ACK rule.
    allow_failure_injection: bool = False
    static_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "web")

    def __post_init__(self) -> None:
        network = ipaddress.IPv4Network(
            f"{self.pool_start}/{self.subnet_mask}", strict=False
        )
        if self.pool_start > self.pool_end:
            raise ValueError("DHCP_POOL_START must be <= DHCP_POOL_END")
        if self.pool_start not in network or self.pool_end not in network:
            raise ValueError("pool must be inside the subnet defined by DHCP_SUBNET_MASK")
        if network.network_address in (self.pool_start, self.pool_end):
            raise ValueError("pool must not include the subnet network address")
        if network.broadcast_address in (self.pool_start, self.pool_end):
            raise ValueError("pool must not include the subnet broadcast address")
        if self.server_identifier in (self.pool_start, self.pool_end):
            raise ValueError("server identifier must not be the first/last pool address")
        if int(self.pool_end) - int(self.pool_start) + 1 > 4096:
            raise ValueError("pool is too large for this teaching service (max 4096)")
        if self.server_identifier in self.pool_ips():
            raise ValueError("server identifier must not be inside the pool")
        if self.lease_time < 1:
            raise ValueError("DHCP_LEASE_TIME must be >= 1 second")
        if self.offer_ttl <= 0:
            raise ValueError("DHCP_OFFER_TTL must be > 0 seconds")
        if self.decline_quarantine < 1:
            raise ValueError("DHCP_DECLINE_QUARANTINE must be >= 1 second")
        if not (0 <= self.udp_port <= 65535 and 0 <= self.sim_target_port <= 65535):
            raise ValueError("UDP ports must be in 0..65535")
        if self.sim_timeout <= 0:
            raise ValueError("DHCP_SIM_TIMEOUT must be > 0")

    def pool_ips(self) -> tuple[ipaddress.IPv4Address, ...]:
        return tuple(
            ipaddress.IPv4Address(value)
            for value in range(int(self.pool_start), int(self.pool_end) + 1)
        )

    @property
    def pool_size(self) -> int:
        return int(self.pool_end) - int(self.pool_start) + 1

    @classmethod
    def from_env(cls) -> "Settings":
        dns_raw = _env("DHCP_DNS", "192.0.2.53")
        dns = tuple(
            _ipv4(item.strip(), "DHCP_DNS")
            for item in dns_raw.split(",")
            if item.strip()
        )
        static_dir = Path(
            _env(
                "DHCP_STATIC_DIR",
                str(Path(__file__).resolve().parent / "web"),
            )
        )
        return cls(
            pool_start=_ipv4(_env("DHCP_POOL_START", "192.0.2.100"), "DHCP_POOL_START"),
            pool_end=_ipv4(_env("DHCP_POOL_END", "192.0.2.110"), "DHCP_POOL_END"),
            subnet_mask=_ipv4(
                _env("DHCP_SUBNET_MASK", "255.255.255.0"), "DHCP_SUBNET_MASK"
            ),
            router=_ipv4(_env("DHCP_ROUTER", "192.0.2.1"), "DHCP_ROUTER"),
            dns_servers=dns,
            server_identifier=_ipv4(
                _env("DHCP_SERVER_ID", "192.0.2.2"), "DHCP_SERVER_ID"
            ),
            broadcast=_ipv4(
                _env("DHCP_BROADCAST", "192.0.2.255"), "DHCP_BROADCAST"
            ),
            lease_time=_env_int("DHCP_LEASE_TIME", 120),
            offer_ttl=_env_float("DHCP_OFFER_TTL", 60.0),
            decline_quarantine=_env_int("DHCP_DECLINE_QUARANTINE", 300),
            udp_host=_env("DHCP_UDP_HOST", "0.0.0.0"),
            udp_port=_env_int("DHCP_UDP_PORT", 6767),
            relay_port=_env_int("DHCP_RELAY_PORT", 67),
            db_path=_env("DHCP_DB_PATH", "./data/dhcp.sqlite3"),
            sim_target_host=_env("DHCP_SIM_TARGET_HOST", "127.0.0.1"),
            # 0 means "whatever UDP port the listener actually bound".
            sim_target_port=_env_int("DHCP_SIM_TARGET_PORT", 0),
            sim_timeout=_env_float("DHCP_SIM_TIMEOUT", 1.5),
            allow_failure_injection=_env(
                "DHCP_ALLOW_FAILURE_INJECTION", "0"
            ).lower()
            in ("1", "true", "yes", "on"),
            static_dir=static_dir,
        )
