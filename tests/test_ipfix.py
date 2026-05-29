from ifa_collector.cli import _parse_udp_payload
from ifa_collector.schema import SchemaRegistry


def test_parse_ipfix_wrapped_ifa_payload() -> None:
    ifa = bytes(
        [
            0x2F,
            17,
            0,
            255,
            0xFF,
            0xFF,
            30,
            1,
        ]
    ) + bytes.fromhex("1000403f")
    set_payload = (257).to_bytes(2, "big") + (len(ifa) + 4).to_bytes(2, "big") + ifa
    ipfix = (
        (10).to_bytes(2, "big")
        + (16 + len(set_payload)).to_bytes(2, "big")
        + (123).to_bytes(4, "big")
        + (456).to_bytes(4, "big")
        + (0x12345678).to_bytes(4, "big")
        + set_payload
    )

    parsed = _parse_udp_payload(ipfix, SchemaRegistry())[0]

    assert parsed.wrapper["type"] == "ipfix"
    assert parsed.wrapper["set_id"] == 257
    assert parsed.ifa_header.version == 2
    assert parsed.raw_metadata_stack == bytes.fromhex("1000403f")
    assert parsed.post_metadata_payload == b""
