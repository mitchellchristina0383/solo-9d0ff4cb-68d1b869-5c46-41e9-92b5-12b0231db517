"""End-to-end tests: real UDP datagrams plus the FastAPI web console API."""

from __future__ import annotations

import ipaddress
import os
import socket
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from app.config import Settings
from app.dhcp.packet import (
    DHCPDISCOVER,
    DHCPOFFER,
    DHCPREQUEST,
    OPTION_CLIENT_ID,
    OPTION_REQUESTED_IP,
    OPTION_SERVER_ID,
    build_packet,
    parse_packet,
)
from app.main import create_app
from tests.test_dhcp import MAC_A, MAC_B, SERVER, mac_bytes


def udp_exchange(port: int, payload: bytes, timeout: float = 2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
        data, _addr = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def discover_bytes(mac: str, xid: int) -> bytes:
    return build_packet(
        op=1,
        xid=xid,
        chaddr=mac_bytes(mac),
        message_type=DHCPDISCOVER,
        flags=0x8000,
        options={OPTION_CLIENT_ID: b"\x01" + mac_bytes(mac)},
    )


def request_bytes(mac: str, ip: str | None, xid: int, ciaddr: str = "0.0.0.0") -> bytes:
    options = {OPTION_SERVER_ID: ipaddress.IPv4Address(SERVER).packed}
    if ip:
        options[OPTION_REQUESTED_IP] = ipaddress.IPv4Address(ip).packed
    return build_packet(
        op=1,
        xid=xid,
        chaddr=mac_bytes(mac),
        message_type=DHCPREQUEST,
        ciaddr=ipaddress.IPv4Address(ciaddr),
        flags=0x8000,
        options=options,
    )


class WebAndUdpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = Settings(
            pool_start=ipaddress.IPv4Address("192.0.2.100"),
            pool_end=ipaddress.IPv4Address("192.0.2.105"),
            server_identifier=ipaddress.IPv4Address(SERVER),
            broadcast=ipaddress.IPv4Address("192.0.2.255"),
            lease_time=120,
            offer_ttl=60,
            db_path=os.path.join(self.tmp.name, "db.sqlite3"),
            udp_port=0,
            sim_target_port=0,
            sim_timeout=2.0,
        )
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def _port(self) -> int:
        return self.app.state.__dict__.get("udp_port") or self.client.get(
            "/api/health"
        ).json()["udp_port"]

    def test_web_index_and_state(self) -> None:
        index = self.client.get("/")
        self.assertEqual(index.status_code, 200)
        self.assertIn("DHCPv4", index.text)
        state = self.client.get("/api/state").json()
        self.assertEqual(state["config"]["pool_start"], "192.0.2.100")
        self.assertEqual(state["stats"]["pool_size"], 6)

    def test_udp_discover_request_roundtrip(self) -> None:
        health = self.client.get("/api/health").json()
        port = health["udp_port"]
        self.assertGreater(port, 0)
        raw = udp_exchange(port, discover_bytes(MAC_A, 0x0A0B0C0D))
        self.assertIsNotNone(raw)
        offer = parse_packet(raw)  # type: ignore[arg-type]
        self.assertEqual(offer.message_type, DHCPOFFER)
        self.assertEqual(offer.xid, 0x0A0B0C0D)
        offered = str(offer.yiaddr)
        self.assertEqual(offered, "192.0.2.100")

        ack_raw = udp_exchange(port, request_bytes(MAC_A, offered, 0x0A0B0C0E))
        self.assertIsNotNone(ack_raw)
        ack = parse_packet(ack_raw)  # type: ignore[arg-type]
        self.assertEqual(ack.message_type, 5)  # DHCPACK
        self.assertEqual(str(ack.yiaddr), offered)

        leases = self.client.get("/api/leases").json()["leases"]
        self.assertEqual(len(leases), 1)
        self.assertEqual(leases[0]["status"], "bound")
        events = self.client.get("/api/events").json()["events"]
        self.assertTrue(any(e["message_type"] == "DHCPACK" for e in events))

    def test_udp_nak_for_foreign_request(self) -> None:
        port = self.client.get("/api/health").json()["udp_port"]
        raw = udp_exchange(port, discover_bytes(MAC_A, 1))
        offered = str(parse_packet(raw).yiaddr)  # type: ignore[arg-type]
        nak_raw = udp_exchange(port, request_bytes(MAC_B, offered, 2))
        self.assertIsNotNone(nak_raw)
        self.assertEqual(parse_packet(nak_raw).message_type, 6)  # DHCPNAK

    def test_simulator_sends_real_packet_through_api(self) -> None:
        response = self.client.post(
            "/api/simulate",
            json={"kind": "DISCOVER", "mac": MAC_A, "hostname": "web-client"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["action"], "DHCPOFFER")
        self.assertEqual(data["reply"]["yiaddr"], "192.0.2.100")
        lease = self.client.get("/api/leases").json()["leases"][0]
        self.assertEqual(lease["hostname"], "web-client")
        health = self.client.get("/api/health").json()
        self.assertGreaterEqual(health["udp_received"], 1)

        ack = self.client.post(
            "/api/simulate",
            json={
                "kind": "REQUEST",
                "mac": MAC_A,
                "requested_ip": "192.0.2.100",
                "server_id": SERVER,
            },
        )
        self.assertEqual(ack.status_code, 200, ack.text)
        self.assertEqual(ack.json()["action"], "DHCPACK")

        released = self.client.post(
            "/api/simulate",
            json={"kind": "RELEASE", "mac": MAC_A, "ciaddr": "192.0.2.100"},
        )
        self.assertEqual(released.json()["note"].count("没有收到"), 1)
        leases = self.client.get("/api/leases").json()["leases"]
        self.assertEqual(leases, [])

    def test_web_state_reflects_expiry(self) -> None:
        # Not using the fake clock here: 1s offer TTL exercises the durable path.
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        settings = Settings(
            pool_start=ipaddress.IPv4Address("192.0.2.100"),
            pool_end=ipaddress.IPv4Address("192.0.2.101"),
            server_identifier=ipaddress.IPv4Address(SERVER),
            broadcast=ipaddress.IPv4Address("192.0.2.255"),
            lease_time=120,
            offer_ttl=1.0,
            db_path=os.path.join(self.tmp.name, "db.sqlite3"),
            udp_port=0,
            sim_target_port=0,
        )
        self.app = create_app(settings)
        self.client = TestClient(self.app)
        self.client.__enter__()
        first = self.client.post(
            "/api/simulate", json={"kind": "DISCOVER", "mac": MAC_A}
        ).json()
        self.assertEqual(first["reply"]["yiaddr"], "192.0.2.100")
        time.sleep(1.3)
        second = self.client.post(
            "/api/simulate", json={"kind": "DISCOVER", "mac": MAC_B}
        ).json()
        self.assertEqual(second["reply"]["yiaddr"], "192.0.2.100")
        self.assertEqual(len(self.client.get("/api/leases").json()["leases"]), 1)
        events = self.client.get("/api/events").json()["events"]
        self.assertTrue(any(e["message_type"] == "OFFER_EXPIRED" for e in events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
