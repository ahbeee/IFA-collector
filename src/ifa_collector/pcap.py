from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class PcapRecord:
    timestamp_ns: int
    data: bytes


def read_pcap(path: Path, ignore_truncated_tail: bool = False) -> Iterator[PcapRecord]:
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise ValueError("pcap global header is truncated")

        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
            ns_resolution = False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
            ns_resolution = False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
            ns_resolution = True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
            ns_resolution = True
        else:
            raise ValueError(f"unsupported pcap magic {magic.hex()}")

        while True:
            record_header = handle.read(16)
            if not record_header:
                return
            if len(record_header) != 16:
                raise ValueError("pcap record header is truncated")

            sec, subsec, captured_len, _original_len = struct.unpack(endian + "IIII", record_header)
            data = handle.read(captured_len)
            if len(data) != captured_len:
                if ignore_truncated_tail:
                    return
                raise ValueError("pcap record body is truncated")

            timestamp_ns = sec * 1_000_000_000 + (subsec if ns_resolution else subsec * 1_000)
            yield PcapRecord(timestamp_ns=timestamp_ns, data=data)
