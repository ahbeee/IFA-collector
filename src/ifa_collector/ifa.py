from __future__ import annotations

import struct

from .models import (
    HopMetadata,
    IfaChecksumHeader,
    IfaFragmentHeader,
    IfaHeader,
    IfaMetadataHeader,
    ParsedIfaPacket,
)
from .packet import FlowKey, PacketCursor, decode_packet
from .schema import SchemaRegistry


def parse_ifa_from_frame(data: bytes, registry: SchemaRegistry) -> ParsedIfaPacket:
    cursor = decode_packet(data)
    return parse_ifa_payload(cursor.payload, registry, cursor, data)


def parse_ifa_payload(
    payload: bytes,
    registry: SchemaRegistry,
    cursor: PacketCursor | None = None,
    raw_packet: bytes | None = None,
    wrapper: dict[str, object] | None = None,
) -> ParsedIfaPacket:
    if len(payload) < 8:
        raise ValueError("IFA payload is too short")

    first, next_header, flags, max_length_words = struct.unpack("!BBBB", payload[:4])
    ifa_header = IfaHeader(
        version=first >> 4,
        gns=first & 0x0F,
        next_header=next_header,
        flags=flags,
        max_length_words=max_length_words,
    )
    if ifa_header.version != 2:
        raise ValueError(f"unsupported IFA version {ifa_header.version}")

    offset = 4
    checksum_header = None
    fragment_header = None

    if ifa_header.has_checksum:
        if len(payload) < offset + 4:
            raise ValueError("IFA checksum header is truncated")
        checksum, reserved = struct.unpack("!HH", payload[offset : offset + 4])
        checksum_header = IfaChecksumHeader(checksum=checksum, reserved=reserved)
        offset += 4

    if ifa_header.has_metadata_fragment:
        if len(payload) < offset + 4:
            raise ValueError("IFA fragmentation header is truncated")
        word = struct.unpack("!I", payload[offset : offset + 4])[0]
        fragment_header = IfaFragmentHeader(
            packet_id=(word >> 6) & 0x03FF_FFFF,
            fragment_id=(word >> 1) & 0x1F,
            last=bool(word & 0x01),
        )
        offset += 4

    if len(payload) < offset + 4:
        raise ValueError("IFA metadata header is truncated")

    request_vector, action_vector, hop_limit, current_length_words = struct.unpack("!BBBB", payload[offset : offset + 4])
    metadata_header = IfaMetadataHeader(
        request_vector=request_vector,
        action_vector=action_vector,
        hop_limit=hop_limit,
        current_length_words=current_length_words,
    )
    offset += 4

    metadata_end = offset + metadata_header.current_length_bytes
    raw_metadata_stack = payload[offset:metadata_end]
    post_metadata_payload = payload[metadata_end:]
    errors: list[str] = []
    if len(raw_metadata_stack) < metadata_header.current_length_bytes:
        errors.append("metadata stack is shorter than current_length")

    hops = decode_metadata_stack(ifa_header, raw_metadata_stack, registry, errors)

    return ParsedIfaPacket(
        flow_key=cursor.flow_key if cursor else _decode_clipped_flow_key(post_metadata_payload),
        ifa_header=ifa_header,
        metadata_header=metadata_header,
        checksum_header=checksum_header,
        fragment_header=fragment_header,
        hops=hops,
        raw_metadata_stack=raw_metadata_stack,
        post_metadata_payload=post_metadata_payload,
        raw_packet=raw_packet or payload,
        errors=errors,
        wrapper=wrapper,
    )


def _decode_clipped_flow_key(data: bytes) -> FlowKey | None:
    if len(data) < 18:
        return None

    candidates = [data]
    clip_len = int.from_bytes(data[:4], "big")
    if 14 <= clip_len <= len(data) - 4:
        candidates.insert(0, data[4 : 4 + clip_len])

    for candidate in candidates:
        try:
            return decode_packet(candidate).flow_key
        except ValueError:
            continue
    return None


def decode_metadata_stack(
    ifa_header: IfaHeader,
    raw_metadata_stack: bytes,
    registry: SchemaRegistry,
    errors: list[str],
) -> list[HopMetadata]:
    hops: list[HopMetadata] = []
    offset = 0
    while offset < len(raw_metadata_stack):
        schema = registry.match(ifa_header.version, ifa_header.gns, raw_metadata_stack[offset:])
        if not schema:
            remaining = raw_metadata_stack[offset:]
            for word_offset in range(0, len(remaining), 4):
                chunk = remaining[word_offset : word_offset + 4]
                hops.append(HopMetadata(raw=chunk, fields={"raw_hex": chunk.hex()}, schema_id=None))
            if remaining:
                errors.append(f"no metadata schema for GNS {ifa_header.gns}; emitted raw words")
            break

        end = offset + schema.hop_metadata_size
        if end > len(raw_metadata_stack):
            errors.append(f"truncated hop metadata for schema {schema.schema_id}")
            hops.append(HopMetadata(raw=raw_metadata_stack[offset:], fields={"raw_hex": raw_metadata_stack[offset:].hex()}, schema_id=None))
            break

        hops.append(schema.decode_hop(raw_metadata_stack[offset:end]))
        offset = end

    return hops
