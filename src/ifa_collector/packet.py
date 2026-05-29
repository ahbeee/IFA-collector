from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from .models import FlowKey

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_GRE = 47
UDP_PORT_VXLAN = 4789
UDP_PORT_GENEVE = 6081


@dataclass(frozen=True)
class PacketCursor:
    payload: bytes
    network_offset: int
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    tunnel_vni: int | None = None
    l4_offset: int | None = None

    @property
    def flow_key(self) -> FlowKey:
        return FlowKey(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            protocol=self.protocol,
            src_port=self.src_port,
            dst_port=self.dst_port,
            tunnel_vni=self.tunnel_vni,
        )


def decode_packet(data: bytes) -> PacketCursor:
    if len(data) < 14:
        raise ValueError("ethernet frame is truncated")
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14
    if ethertype == 0x8100:
        if len(data) < 18:
            raise ValueError("802.1Q frame is truncated")
        ethertype = struct.unpack("!H", data[16:18])[0]
        offset = 18

    if ethertype == ETHERTYPE_IPV4:
        return _decode_ipv4(data, offset, None)
    if ethertype == ETHERTYPE_IPV6:
        return _decode_ipv6(data, offset, None)
    raise ValueError(f"unsupported ethertype 0x{ethertype:04x}")


def _decode_ipv4(data: bytes, offset: int, tunnel_vni: int | None) -> PacketCursor:
    if len(data) < offset + 20:
        raise ValueError("ipv4 header is truncated")
    version_ihl = data[offset]
    ihl = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or ihl < 20:
        raise ValueError("invalid ipv4 header")
    if len(data) < offset + ihl:
        raise ValueError("ipv4 options are truncated")

    protocol = data[offset + 9]
    src_ip = str(ipaddress.IPv4Address(data[offset + 12 : offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(data[offset + 16 : offset + 20]))
    payload_offset = offset + ihl
    return _decode_l4(data, payload_offset, protocol, src_ip, dst_ip, tunnel_vni)


def _decode_ipv6(data: bytes, offset: int, tunnel_vni: int | None) -> PacketCursor:
    if len(data) < offset + 40:
        raise ValueError("ipv6 header is truncated")
    if data[offset] >> 4 != 6:
        raise ValueError("invalid ipv6 header")
    protocol = data[offset + 6]
    src_ip = str(ipaddress.IPv6Address(data[offset + 8 : offset + 24]))
    dst_ip = str(ipaddress.IPv6Address(data[offset + 24 : offset + 40]))
    payload_offset = offset + 40
    return _decode_l4(data, payload_offset, protocol, src_ip, dst_ip, tunnel_vni)


def _decode_l4(
    data: bytes,
    offset: int,
    protocol: int,
    src_ip: str,
    dst_ip: str,
    tunnel_vni: int | None,
) -> PacketCursor:
    if protocol == IPPROTO_UDP:
        if len(data) < offset + 8:
            raise ValueError("udp header is truncated")
        src_port, dst_port = struct.unpack("!HH", data[offset : offset + 4])
        payload_offset = offset + 8
        if dst_port == UDP_PORT_VXLAN or src_port == UDP_PORT_VXLAN:
            return _decode_vxlan(data, payload_offset)
        if dst_port == UDP_PORT_GENEVE or src_port == UDP_PORT_GENEVE:
            return _decode_geneve(data, payload_offset)
        return PacketCursor(data[payload_offset:], offset, protocol, src_ip, dst_ip, src_port, dst_port, tunnel_vni, offset)

    if protocol == IPPROTO_TCP:
        if len(data) < offset + 20:
            raise ValueError("tcp header is truncated")
        src_port, dst_port = struct.unpack("!HH", data[offset : offset + 4])
        return PacketCursor(data[offset + ((data[offset + 12] >> 4) * 4) :], offset, protocol, src_ip, dst_ip, src_port, dst_port, tunnel_vni, offset)

    if protocol == IPPROTO_GRE:
        return _decode_gre(data, offset)

    return PacketCursor(data[offset:], offset, protocol, src_ip, dst_ip, tunnel_vni=tunnel_vni)


def _decode_vxlan(data: bytes, offset: int) -> PacketCursor:
    if len(data) < offset + 8:
        raise ValueError("vxlan header is truncated")
    vni = int.from_bytes(data[offset + 4 : offset + 7], "big")
    inner = data[offset + 8 :]
    cursor = decode_packet(inner)
    return PacketCursor(
        payload=cursor.payload,
        network_offset=cursor.network_offset,
        protocol=cursor.protocol,
        src_ip=cursor.src_ip,
        dst_ip=cursor.dst_ip,
        src_port=cursor.src_port,
        dst_port=cursor.dst_port,
        tunnel_vni=vni,
        l4_offset=cursor.l4_offset,
    )


def _decode_geneve(data: bytes, offset: int) -> PacketCursor:
    if len(data) < offset + 8:
        raise ValueError("geneve header is truncated")
    opt_len = (data[offset] & 0x3F) * 4
    protocol_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
    vni = int.from_bytes(data[offset + 4 : offset + 7], "big")
    inner_offset = offset + 8 + opt_len
    if protocol_type == ETHERTYPE_IPV4:
        return _decode_ipv4(data, inner_offset, vni)
    if protocol_type == ETHERTYPE_IPV6:
        return _decode_ipv6(data, inner_offset, vni)
    if protocol_type == 0x6558:
        cursor = decode_packet(data[inner_offset:])
        return PacketCursor(cursor.payload, cursor.network_offset, cursor.protocol, cursor.src_ip, cursor.dst_ip, cursor.src_port, cursor.dst_port, vni, cursor.l4_offset)
    raise ValueError(f"unsupported geneve protocol type 0x{protocol_type:04x}")


def _decode_gre(data: bytes, offset: int) -> PacketCursor:
    if len(data) < offset + 4:
        raise ValueError("gre header is truncated")
    flags = struct.unpack("!H", data[offset : offset + 2])[0]
    protocol_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
    gre_len = 4
    if flags & 0x8000:
        gre_len += 4
    if flags & 0x2000:
        gre_len += 4
    if flags & 0x1000:
        gre_len += 4
    inner_offset = offset + gre_len
    if protocol_type == ETHERTYPE_IPV4:
        return _decode_ipv4(data, inner_offset, None)
    if protocol_type == ETHERTYPE_IPV6:
        return _decode_ipv6(data, inner_offset, None)
    if protocol_type == 0x6558:
        return decode_packet(data[inner_offset:])
    raise ValueError(f"unsupported gre protocol type 0x{protocol_type:04x}")
