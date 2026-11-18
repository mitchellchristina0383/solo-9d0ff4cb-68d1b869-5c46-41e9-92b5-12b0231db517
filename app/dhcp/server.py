"""DHCPv4 protocol handling and the unprivileged UDP responder."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from typing import Callable

from ..config import Settings
from .packet import (
    BOOTREQUEST,
    DHCPACK,
    DHCPDECLINE,
    DHCPDISCOVER,
    DHCPINFORM,
    DHCPNAK,
    DHCPOFFER,
    DHCPRELEASE,
    DHCPREQUEST,
    MESSAGE_TYPE_NAMES,
    OPTION_REQUESTED_IP,
    OPTION_SERVER_ID,
    DhcpPacket,
    PacketError,
    build_reply,
    parse_packet,
)
from .store import LeaseStore

log = logging.getLogger("dhcp.server")

ZERO = ipaddress.IPv4Address("0.0.0.0")


@dataclass
class HandlerOutcome:
    """The reply bytes to send and a note for the audit log/UI."""

    reply: bytes | None
    action: str
    ip: str | None = None
    client_key: str | None = None
    reason: str | None = None
    reply_type: int | None = None


class DhcpService:
    """Turns one parsed DHCP request into one reply, using a durable store."""

    def __init__(self, settings: Settings, store: LeaseStore) -> None:
        self.settings = settings
        self.store = store

    def _base_reply(
        self, request: DhcpPacket, *, network_options: bool = True, **kwargs
    ) -> bytes:
        # NAKs carry only server identifier and an optional message (RFC 2131).
        return build_reply(
            request,
            server_id=self.settings.server_identifier,
            subnet_mask=self.settings.subnet_mask if network_options else None,
            router=self.settings.router if network_options else None,
            dns=self.settings.dns_servers if network_options else (),
            broadcast=self.settings.broadcast if network_options else None,
            **kwargs,
        )

    def handle(self, request: DhcpPacket) -> HandlerOutcome:
        if request.op != BOOTREQUEST:
            return HandlerOutcome(None, "ignored", reason="not a BOOTREQUEST")
        if request.giaddr != ZERO:
            # A relayed request must be answered to the relay agent on port 67.
            # This lab only listens on an unprivileged port, so refuse early
            # instead of leaking a reply to the wrong peer.
            return HandlerOutcome(
                None, "ignored", reason="relayed requests are not supported by this lab"
            )
        msg_type = request.message_type
        client_key = request.client_key()
        if msg_type is None:
            return HandlerOutcome(
                None, "ignored", client_key=client_key,
                reason="missing DHCP message type",
            )
        if client_key is None:
            return HandlerOutcome(
                None, "ignored",
                reason="missing usable client identity (chaddr/client-id)",
            )

        handler = {
            DHCPDISCOVER: self._discover,
            DHCPREQUEST: self._request,
            DHCPRELEASE: self._release,
            DHCPDECLINE: self._decline,
            DHCPINFORM: self._inform,
        }.get(msg_type)
        if handler is None:
            return HandlerOutcome(
                None, "ignored", client_key=client_key,
                reason=f"unsupported message type {MESSAGE_TYPE_NAMES.get(msg_type, msg_type)}",
            )
        return handler(request, client_key)

    # -- message handlers -------------------------------------------------

    def _discover(self, request: DhcpPacket, client_key: str) -> HandlerOutcome:
        try:
            result = self.store.offer(
                client_key=client_key,
                client_mac=request.mac,
                hostname=request.hostname,
                xid=request.xid,
            )
        except Exception as exc:  # disk/commit error: silence beats double-lease
            log.exception("offer transaction failed; refusing to OFFER")
            return HandlerOutcome(
                None, "store-error", client_key=client_key, reason=str(exc)
            )
        if result.kind != "offer" or result.ip is None:
            return HandlerOutcome(
                None, "pool-exhausted", client_key=client_key,
                reason=result.reason,
            )
        reply = self._base_reply(
            request,
            message_type=DHCPOFFER,
            yiaddr=ipaddress.IPv4Address(result.ip),
            lease_time=self.settings.lease_time,
        )
        return HandlerOutcome(
            reply,
            "offer-reused" if result.reused else "offer",
            ip=result.ip,
            client_key=client_key,
            reply_type=DHCPOFFER,
        )

    def _request(self, request: DhcpPacket, client_key: str) -> HandlerOutcome:
        requested = request.option_ip(OPTION_REQUESTED_IP)
        server_id = request.option_ip(OPTION_SERVER_ID)
        try:
            result = self.store.request(
                client_key=client_key,
                client_mac=request.mac,
                hostname=request.hostname,
                xid=request.xid,
                requested_ip=requested,
                ciaddr=request.ciaddr,
                server_id=server_id,
            )
        except Exception as exc:
            log.exception("request transaction failed; refusing to ACK/NAK")
            # Silence is the safe failure: a client that got no ACK keeps
            # retrying, while a fabricated ACK could duplicate an address.
            return HandlerOutcome(
                None, "store-error", client_key=client_key, reason=str(exc)
            )
        if result.kind == "ack" and result.ip is not None:
            reply = self._base_reply(
                request,
                message_type=DHCPACK,
                yiaddr=ipaddress.IPv4Address(result.ip),
                lease_time=self.settings.lease_time,
            )
            return HandlerOutcome(
                reply, "ack", ip=result.ip, client_key=client_key, reply_type=DHCPACK
            )
        if result.kind == "nak":
            reply = self._base_reply(
                request,
                message_type=DHCPNAK,
                yiaddr=ZERO,
                network_options=False,
                message=result.reason or "address not available",
            )
            return HandlerOutcome(
                reply, "nak", ip=result.ip, client_key=client_key,
                reason=result.reason, reply_type=DHCPNAK,
            )
        return HandlerOutcome(
            None, "ignored", ip=result.ip, client_key=client_key, reason=result.reason
        )

    def _release(self, request: DhcpPacket, client_key: str) -> HandlerOutcome:
        try:
            result = self.store.release(
                client_key=client_key,
                xid=request.xid,
                ciaddr=request.ciaddr,
                server_id=request.option_ip(OPTION_SERVER_ID),
            )
        except Exception as exc:
            log.exception("release transaction failed")
            return HandlerOutcome(
                None, "store-error", client_key=client_key, reason=str(exc)
            )
        return HandlerOutcome(
            None, result.kind, ip=result.ip, client_key=client_key, reason=result.reason
        )

    def _decline(self, request: DhcpPacket, client_key: str) -> HandlerOutcome:
        try:
            result = self.store.decline(
                client_key=client_key,
                xid=request.xid,
                requested_ip=request.option_ip(OPTION_REQUESTED_IP),
                server_id=request.option_ip(OPTION_SERVER_ID),
            )
        except Exception as exc:
            log.exception("decline transaction failed")
            return HandlerOutcome(
                None, "store-error", client_key=client_key, reason=str(exc)
            )
        return HandlerOutcome(
            None, result.kind, ip=result.ip, client_key=client_key, reason=result.reason
        )

    def _inform(self, request: DhcpPacket, client_key: str) -> HandlerOutcome:
        if request.ciaddr == ZERO:
            return HandlerOutcome(
                None, "ignored", client_key=client_key,
                reason="DHCPINFORM without ciaddr",
            )
        reply = self._base_reply(
            request,
            message_type=DHCPACK,
            yiaddr=ZERO,
        )
        return HandlerOutcome(
            reply, "inform-ack", ip=str(request.ciaddr), client_key=client_key,
            reply_type=DHCPACK,
        )


@dataclass
class DatagramResult:
    reply: bytes | None
    outcome: HandlerOutcome
    error: str | None = None


class UdpDhcpServer:
    """asyncio datagram endpoint for the unprivileged DHCP lab port."""

    def __init__(
        self,
        service: DhcpService,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        self.service = service
        self._on_change = on_change
        self.transport: asyncio.DatagramTransport | None = None
        self.received = 0
        self.replied = 0
        self.dropped = 0
        self._started = asyncio.Event()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: _Protocol(self),
            local_addr=(self.service.settings.udp_host, self.service.settings.udp_port),
        )
        self._started.set()

    async def wait_started(self) -> None:
        await self._started.wait()

    @property
    def port(self) -> int:
        """Actual bound port (useful when configured with port 0 in tests)."""
        if self.transport is None:
            return self.service.settings.udp_port
        return self.transport.get_extra_info("sockname")[1]

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, server: UdpDhcpServer) -> None:
        self.server = server

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.server.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        result = process_datagram(self.server.service, data)
        server = self.server
        server.received += 1
        if server._on_change is not None:
            server._on_change()
        if result.reply is None:
            server.dropped += 1
            return
        if server.transport is not None:
            server.transport.sendto(result.reply, addr)
            server.replied += 1

    def error_received(self, exc: Exception) -> None:
        log.warning("UDP error: %s", exc)


def process_datagram(service: DhcpService, data: bytes) -> DatagramResult:
    """Synchronous parse/handle step shared by UDP and the web simulator."""
    try:
        request = parse_packet(data)
    except PacketError as exc:
        return DatagramResult(
            None,
            HandlerOutcome(None, "malformed", reason=str(exc)),
            error=str(exc),
        )
    try:
        outcome = service.handle(request)
    except Exception as exc:  # last-resort guard: never crash the listener
        log.exception("unhandled error while processing DHCP packet")
        return DatagramResult(
            None,
            HandlerOutcome(None, "error", reason=str(exc)),
            error=str(exc),
        )
    return DatagramResult(outcome.reply, outcome)
