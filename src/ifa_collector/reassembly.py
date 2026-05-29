from __future__ import annotations

import time
from dataclasses import dataclass, field

from .models import ParsedIfaPacket


@dataclass
class FragmentSet:
    created_at: float
    fragments: dict[int, ParsedIfaPacket] = field(default_factory=dict)
    last_seen: bool = False


class FragmentReassembler:
    def __init__(self, timeout_seconds: float = 3.0):
        self.timeout_seconds = timeout_seconds
        self._sets: dict[tuple[int, int], FragmentSet] = {}

    def add(self, packet: ParsedIfaPacket) -> ParsedIfaPacket | None:
        if packet.fragment_header is None:
            return packet

        device_id = _first_device_id(packet)
        key = (device_id, packet.fragment_header.packet_id)
        fragment_set = self._sets.setdefault(key, FragmentSet(created_at=time.monotonic()))
        fragment_set.fragments[packet.fragment_header.fragment_id] = packet
        fragment_set.last_seen = fragment_set.last_seen or packet.fragment_header.last

        if not fragment_set.last_seen:
            return None

        last_id = max(fragment_set.fragments)
        if any(fragment_id not in fragment_set.fragments for fragment_id in range(last_id + 1)):
            return None

        del self._sets[key]
        # Full metadata merge is schema-dependent; for now return the last packet and keep
        # the complete fragment set available through raw packet archives in callers.
        return packet

    def expire(self) -> list[FragmentSet]:
        now = time.monotonic()
        expired_keys = [
            key for key, value in self._sets.items() if now - value.created_at > self.timeout_seconds
        ]
        expired = [self._sets.pop(key) for key in expired_keys]
        return expired


def _first_device_id(packet: ParsedIfaPacket) -> int:
    for hop in packet.hops:
        value = hop.fields.get("device_id")
        if isinstance(value, int):
            return value
    return 0
