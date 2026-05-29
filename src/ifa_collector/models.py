from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int | None = None
    dst_port: int | None = None
    tunnel_vni: int | None = None


@dataclass(frozen=True)
class IfaHeader:
    version: int
    gns: int
    next_header: int
    flags: int
    max_length_words: int

    @property
    def has_metadata_fragment(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def has_tail_stamp(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def is_inband(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def has_turnaround(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def has_checksum(self) -> bool:
        return bool(self.flags & 0x01)


@dataclass(frozen=True)
class IfaMetadataHeader:
    request_vector: int
    action_vector: int
    hop_limit: int
    current_length_words: int

    @property
    def current_length_bytes(self) -> int:
        return self.current_length_words * 4


@dataclass(frozen=True)
class IfaChecksumHeader:
    checksum: int
    reserved: int


@dataclass(frozen=True)
class IfaFragmentHeader:
    packet_id: int
    fragment_id: int
    last: bool


@dataclass
class HopMetadata:
    raw: bytes
    fields: dict[str, Any] = field(default_factory=dict)
    schema_id: str | None = None


@dataclass
class ParsedIfaPacket:
    flow_key: FlowKey | None
    ifa_header: IfaHeader
    metadata_header: IfaMetadataHeader
    checksum_header: IfaChecksumHeader | None
    fragment_header: IfaFragmentHeader | None
    hops: list[HopMetadata]
    raw_metadata_stack: bytes
    post_metadata_payload: bytes
    raw_packet: bytes
    errors: list[str] = field(default_factory=list)
    wrapper: dict[str, Any] | None = None
