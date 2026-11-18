"""DHCPv4 wire-format codec (RFC 2131 / RFC 2132), deliberately small.

Only the BOOTP/DHCP fields and options needed by this lab server are handled.
Unknown options are preserved while parsing and exposed in the JSON summary.
Option overload (RFC 2132 section 9.3) is not supported.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Iterable, Mapping

BOOTREQUEST = 1
BOOTREPLY = 2

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

OPTION_PAD = 0
OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS = 6
OPTION_HOSTNAME = 12
OPTION_BROADCAST = 28
OPTION_REQUESTED_IP = 50
OPTION_LEASE_TIME = 51
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_ID = 54
OPTION_PARAMETER_LIST = 55
OPTION_MESSAGE = 56
OPTION_RENEWAL_TIME = 58
OPTION_REBINDING_TIME = 59
OPTION_CLIENT_ID = 61
OPTION_RELAY_AGENT = 82

MAGIC_COOKIE = b"\x63\x82\x53\x63"
HEADER_LEN = 236
MIN_PACKET_LEN = 300

MESSAGE_TYPE_NAMES = {
    DHCPDISCOVER: "DHCPDISCOVER",
    DHCPOFFER: "DHCPOFFER",
    DHCPREQUEST: "DHCPREQUEST",
    DHCPDECLINE: "DHCPDECLINE",
    DHCPACK: "DHCPACK",
    DHCPNAK: "DHCPNAK",
    DHCPRELEASE: "DHCPRELEASE",
    DHCPINFORM: "DHCPINFORM",
}


class PacketError(ValueError):
    """Raised when a datagram is not a valid DHCPv4 message."""


def _ip(raw: bytes) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(raw)


def _pack_ip(value: ipaddress.IPv4Address) -> bytes:
    return value.packed


@dataclass
class DhcpPacket:
    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: ipaddress.IPv4Address
    yiaddr: ipaddress.IPv4Address
    siaddr: ipaddress.IPv4Address
    giaddr: ipaddress.IPv4Address
    chaddr: bytes
    sname: bytes = b""
    file: bytes = b""
    options: dict[int, list[bytes]] = field(default_factory=dict)

    @property
    def mac(self) -> str | None:
        if self.htype != 1 or not 1 <= self.hlen <= len(self.chaddr):
            return None
        return self.chaddr[: self.hlen].hex(":")

    @property
    def message_type(self) -> int | None:
        raw = self.option(OPTION_MESSAGE_TYPE)
        if raw is None or len(raw) != 1:
            return None
        return raw[0]

    def option(self, code: int) -> bytes | None:
        values = self.options.get(code)
        return values[0] if values else None

    def option_ip(self, code: int) -> ipaddress.IPv4Address | None:
        raw = self.option(code)
        if raw is None or len(raw) != 4:
            return None
        return _ip(raw)

    @property
    def hostname(self) -> str | None:
        raw = self.option(OPTION_HOSTNAME)
        if not raw:
            return None
        # DHCP host names are opaque bytes, but clients in the lab send ASCII.
        return raw.decode("utf-8", errors="replace").strip("\x00 ")[:64] or None

    @property
    def client_id_raw(self) -> bytes | None:
        return self.option(OPTION_CLIENT_ID)

    @property
    def broadcast_requested(self) -> bool:
        return bool(self.flags & 0x8000)

    def client_key(self) -> str | None:
        """Stable identity for lease ownership.

        A type-1 client identifier carries an Ethernet MAC (RFC 2132); it is
        canonicalised to the same key as a client that only sent chaddr.
        Other client identifiers are treated as opaque keys.
        """
        client_id = self.client_id_raw
        if client_id:
            if len(client_id) == 7 and client_id[0] == 1:
                return "mac:" + client_id[1:].hex(":")
            return "id:" + client_id.hex()
        mac = self.mac
        return "mac:" + mac if mac else None

    def summary(self, *, include_hex: bool = False) -> dict:
        options: dict[str, object] = {}
        for code in sorted(self.options):
            values = self.options[code]
            rendered = [_render_option(code, value) for value in values]
            options[str(code)] = rendered[0] if len(rendered) == 1 else rendered
        result: dict[str, object] = {
            "op": "BOOTREQUEST" if self.op == BOOTREQUEST else "BOOTREPLY",
            "message_type": self.message_type,
            "message_type_name": MESSAGE_TYPE_NAMES.get(self.message_type, "UNKNOWN"),
            "xid": f"0x{self.xid:08x}",
            "flags": self.flags,
            "broadcast": self.broadcast_requested,
            "ciaddr": str(self.ciaddr),
            "yiaddr": str(self.yiaddr),
            "siaddr": str(self.siaddr),
            "giaddr": str(self.giaddr),
            "chaddr": self.mac or self.chaddr[: self.hlen].hex(),
            "hostname": self.hostname,
            "client_key": self.client_key(),
            "options": options,
        }
        if include_hex:
            result["hex"] = self.to_bytes().hex()
        return result


def _render_option(code: int, value: bytes) -> object:
    if code in (OPTION_SUBNET_MASK, OPTION_ROUTER, OPTION_DNS, OPTION_BROADCAST,
                OPTION_REQUESTED_IP, OPTION_SERVER_ID):
        if len(value) == 4:
            return str(_ip(value))
        if len(value) % 4 == 0:
            return [str(_ip(value[i : i + 4])) for i in range(0, len(value), 4)]
    if code in (OPTION_LEASE_TIME, OPTION_RENEWAL_TIME, OPTION_REBINDING_TIME):
        if len(value) == 4:
            return struct.unpack("!I", value)[0]
    if code == OPTION_MESSAGE_TYPE and len(value) == 1:
        return MESSAGE_TYPE_NAMES.get(value[0], value[0])
    if code in (OPTION_HOSTNAME, OPTION_MESSAGE):
        return value.decode("utf-8", errors="replace")
    return value.hex()


def parse_packet(data: bytes) -> DhcpPacket:
    if len(data) < HEADER_LEN + 4:
        raise PacketError(f"short DHCP packet ({len(data)} bytes)")
    if data[236:240] != MAGIC_COOKIE:
        raise PacketError("missing DHCP magic cookie")
    (
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        bootfile,
    ) = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", data[:HEADER_LEN])
    if op not in (BOOTREQUEST, BOOTREPLY):
        raise PacketError(f"invalid BOOTP op {op}")
    if hlen > 16:
        raise PacketError(f"invalid hardware address length {hlen}")

    options: dict[int, list[bytes]] = {}
    index = HEADER_LEN + 4
    while index < len(data):
        code = data[index]
        index += 1
        if code == OPTION_PAD:
            continue
        if code == 255:  # END
            break
        if index >= len(data):
            raise PacketError(f"truncated option {code}")
        length = data[index]
        index += 1
        if index + length > len(data):
            raise PacketError(f"truncated option {code} value")
        value = data[index : index + length]
        index += length
        options.setdefault(code, []).append(value)

    return DhcpPacket(
        op=op,
        htype=htype,
        hlen=hlen,
        hops=hops,
        xid=xid,
        secs=secs,
        flags=flags,
        ciaddr=_ip(ciaddr),
        yiaddr=_ip(yiaddr),
        siaddr=_ip(siaddr),
        giaddr=_ip(giaddr),
        chaddr=chaddr,
        sname=sname,
        file=bootfile,
        options=options,
    )


def encode_option(code: int, value: bytes) -> bytes:
    if not 0 <= code <= 255:
        raise ValueError(f"bad DHCP option code {code}")
    if len(value) > 255:
        raise ValueError(f"option {code} value too long")
    return bytes((code, len(value))) + value


def encode_options(options: Mapping[int, bytes | Iterable[bytes]]) -> bytes:
    chunks: list[bytes] = []
    for code in sorted(options):
        value = options[code]
        if isinstance(value, (bytes, bytearray)):
            chunks.append(encode_option(code, bytes(value)))
        else:
            for part in value:
                chunks.append(encode_option(code, part))
    chunks.append(bytes((255,)))
    return b"".join(chunks)


def build_packet(
    *,
    op: int,
    xid: int,
    chaddr: bytes,
    message_type: int,
    yiaddr: ipaddress.IPv4Address = ipaddress.IPv4Address("0.0.0.0"),
    ciaddr: ipaddress.IPv4Address = ipaddress.IPv4Address("0.0.0.0"),
    siaddr: ipaddress.IPv4Address = ipaddress.IPv4Address("0.0.0.0"),
    giaddr: ipaddress.IPv4Address = ipaddress.IPv4Address("0.0.0.0"),
    flags: int = 0,
    htype: int = 1,
    hlen: int | None = None,
    options: Mapping[int, bytes | Iterable[bytes]] | None = None,
) -> bytes:
    if len(chaddr) > 16:
        raise ValueError("chaddr must be at most 16 bytes")
    provided_len = len(chaddr)
    chaddr = chaddr.ljust(16, b"\x00")
    if hlen is None:
        # Use the caller-provided address length verbatim. Trimming trailing
        # zero octets would corrupt MACs such as 02:00:00:00:00:00.
        hlen = provided_len
    all_options: dict[int, bytes | Iterable[bytes]] = {
        OPTION_MESSAGE_TYPE: bytes((message_type,))
    }
    if options:
        all_options.update(options)
    option_bytes = encode_options(all_options)
    packet = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        op,
        htype,
        hlen,
        0,
        xid,
        0,
        flags,
        _pack_ip(ciaddr),
        _pack_ip(yiaddr),
        _pack_ip(siaddr),
        _pack_ip(giaddr),
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    packet += MAGIC_COOKIE + option_bytes
    if len(packet) < MIN_PACKET_LEN:
        packet += b"\x00" * (MIN_PACKET_LEN - len(packet))
    return packet


def build_reply(
    request: DhcpPacket,
    *,
    message_type: int,
    yiaddr: ipaddress.IPv4Address,
    server_id: ipaddress.IPv4Address,
    lease_time: int | None = None,
    subnet_mask: ipaddress.IPv4Address | None = None,
    router: ipaddress.IPv4Address | None = None,
    dns: Iterable[ipaddress.IPv4Address] = (),
    broadcast: ipaddress.IPv4Address | None = None,
    message: str | None = None,
) -> bytes:
    options: dict[int, bytes | Iterable[bytes]] = {
        OPTION_SERVER_ID: server_id.packed,
    }
    if lease_time is not None:
        options[OPTION_LEASE_TIME] = struct.pack("!I", lease_time)
        options[OPTION_RENEWAL_TIME] = struct.pack("!I", max(1, lease_time // 2))
        options[OPTION_REBINDING_TIME] = struct.pack("!I", max(1, lease_time * 7 // 8))
    if subnet_mask is not None:
        options[OPTION_SUBNET_MASK] = subnet_mask.packed
    if router is not None:
        options[OPTION_ROUTER] = router.packed
    dns_list = list(dns)
    if dns_list:
        options[OPTION_DNS] = b"".join(addr.packed for addr in dns_list)
    if broadcast is not None:
        options[OPTION_BROADCAST] = broadcast.packed
    if message:
        options[OPTION_MESSAGE] = message.encode("utf-8")[:255]
    return build_packet(
        op=BOOTREPLY,
        xid=request.xid,
        chaddr=request.chaddr,
        message_type=message_type,
        yiaddr=yiaddr,
        giaddr=request.giaddr,
        flags=request.flags,
        htype=request.htype,
        hlen=request.hlen,
        options=options,
    )
