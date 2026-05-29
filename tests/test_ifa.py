from ifa_collector.ifa import parse_ifa_payload
from ifa_collector.schema import SchemaRegistry


def test_parse_ifa_payload_without_schema_emits_raw_words() -> None:
    payload = bytes(
        [
            0x2F,  # version 2, GNS 15
            17,  # next header UDP
            0,
            80,
            0,
            0,
            10,
            2,  # current length 8 bytes
        ]
    ) + bytes.fromhex("1000403f deadbeef")

    parsed = parse_ifa_payload(payload, SchemaRegistry())

    assert parsed.ifa_header.version == 2
    assert parsed.metadata_header.current_length_bytes == 8
    assert parsed.post_metadata_payload == b""
    assert len(parsed.hops) == 2
    assert parsed.hops[0].fields["raw_hex"] == "1000403f"
    assert parsed.errors == ["no metadata schema for GNS 15; emitted raw words"]
