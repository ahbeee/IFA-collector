from ifa_collector.schema import MetadataSchema, SchemaRegistry


def test_decode_aruba_style_hop() -> None:
    schema = MetadataSchema.from_dict(
        {
            "id": "test",
            "vendor": "test",
            "ifa_version": 2,
            "gns": 15,
            "lns": 1,
            "hop_metadata_size": 4,
            "fields": [
                {"name": "lns", "offset_bits": 0, "width_bits": 4},
                {"name": "device_id", "offset_bits": 4, "width_bits": 20},
                {"name": "ip_ttl", "offset_bits": 24, "width_bits": 8},
            ],
        }
    )

    hop = schema.decode_hop(bytes.fromhex("1000403f"))

    assert hop.fields["lns"] == 1
    assert hop.fields["device_id"] == 64
    assert hop.fields["ip_ttl"] == 63


def test_schema_registry_exports_schema_details() -> None:
    schema = MetadataSchema.from_dict(
        {
            "id": "test",
            "vendor": "test",
            "ifa_version": 2,
            "gns": 15,
            "lns": 1,
            "hop_metadata_size": 4,
            "fields": [{"name": "lns", "offset_bits": 0, "width_bits": 4}],
        }
    )

    payload = SchemaRegistry([schema]).as_dict()

    assert payload["schemas"][0]["id"] == "test"
    assert payload["schemas"][0]["fields"][0] == {"name": "lns", "offset_bits": 0, "width_bits": 4}
