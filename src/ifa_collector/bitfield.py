from __future__ import annotations


def read_bits(data: bytes, offset_bits: int, width_bits: int) -> int:
    if offset_bits < 0 or width_bits <= 0:
        raise ValueError("offset_bits must be >= 0 and width_bits must be > 0")

    total_bits = len(data) * 8
    if offset_bits + width_bits > total_bits:
        raise ValueError("bit field exceeds input length")

    value = int.from_bytes(data, "big")
    shift = total_bits - offset_bits - width_bits
    mask = (1 << width_bits) - 1
    return (value >> shift) & mask
