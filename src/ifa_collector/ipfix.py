from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class IpfixHeader:
    version: int
    length: int
    export_time: int
    sequence_number: int
    observation_domain_id: int


@dataclass(frozen=True)
class IpfixSet:
    set_id: int
    length: int
    payload: bytes


@dataclass(frozen=True)
class IpfixMessage:
    header: IpfixHeader
    sets: list[IpfixSet]


def is_ipfix_message(data: bytes) -> bool:
    return len(data) >= 16 and data[:2] == b"\x00\x0a"


def parse_ipfix_message(data: bytes) -> IpfixMessage:
    if len(data) < 16:
        raise ValueError("IPFIX message is truncated")

    version, length, export_time, sequence_number, observation_domain_id = struct.unpack("!HHIII", data[:16])
    if version != 10:
        raise ValueError(f"unsupported IPFIX version {version}")
    if length > len(data):
        raise ValueError("IPFIX message length exceeds UDP payload")

    sets: list[IpfixSet] = []
    offset = 16
    while offset + 4 <= length:
        set_id, set_length = struct.unpack("!HH", data[offset : offset + 4])
        if set_length < 4:
            raise ValueError("invalid IPFIX set length")
        end = offset + set_length
        if end > length:
            raise ValueError("IPFIX set exceeds message length")
        sets.append(IpfixSet(set_id=set_id, length=set_length, payload=data[offset + 4 : end]))
        offset = end

    return IpfixMessage(
        header=IpfixHeader(
            version=version,
            length=length,
            export_time=export_time,
            sequence_number=sequence_number,
            observation_domain_id=observation_domain_id,
        ),
        sets=sets,
    )
