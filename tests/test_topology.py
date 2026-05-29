from ifa_collector.topology import parse_targets


def test_parse_targets_deduplicates_mixed_input():
    assert parse_targets("192.0.2.1, 192.0.2.1 192.0.2.2") == ["192.0.2.1", "192.0.2.2"]


def test_parse_targets_supports_cidr_and_range():
    assert parse_targets("192.0.2.0/30 192.0.2.5-192.0.2.6") == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.5",
        "192.0.2.6",
    ]
