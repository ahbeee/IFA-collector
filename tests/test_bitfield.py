from ifa_collector.bitfield import read_bits


def test_read_bits_across_byte_boundary() -> None:
    assert read_bits(bytes.fromhex("12345678"), 4, 12) == 0x234


def test_read_bits_last_nibble() -> None:
    assert read_bits(bytes.fromhex("12345678"), 28, 4) == 0x8
