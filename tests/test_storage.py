import sqlite3
from pathlib import Path

from ifa_collector.inventory import Inventory
from ifa_collector.models import FlowKey, HopMetadata, IfaHeader, IfaMetadataHeader, ParsedIfaPacket
from ifa_collector.storage import SqliteStore


def test_sqlite_store_inserts_flow_and_hops(tmp_path: Path) -> None:
    inventory = Inventory.load(Path("inventory/lab_topology.json"))
    packet = ParsedIfaPacket(
        flow_key=FlowKey("1.1.1.1", "4.4.4.4", 17, 12345, 5000),
        ifa_header=IfaHeader(2, 15, 17, 0, 255),
        metadata_header=IfaMetadataHeader(255, 255, 30, 24),
        checksum_header=None,
        fragment_header=None,
        hops=[
            HopMetadata(b"", {"device_id": 1002, "ingress_logical_port": 79, "egress_logical_port": 3, "ip_ttl": 61}),
            HopMetadata(b"", {"device_id": 1003, "ingress_logical_port": 91, "egress_logical_port": 95, "ip_ttl": 62}),
            HopMetadata(b"", {"device_id": 1001, "ingress_logical_port": 3, "egress_logical_port": 79, "ip_ttl": 63}),
        ],
        raw_metadata_stack=b"abc",
        post_metadata_payload=b"def",
        raw_packet=b"abcdef",
        wrapper={
            "sequence_number": 10,
            "observation_domain_id": 305419896,
            "set_id": 257,
            "transport": {"src_ip": "10.0.0.1", "src_port": 9070, "dst_ip": "192.0.2.1", "dst_port": 9090},
        },
    )
    db_path = tmp_path / "ifa.sqlite"
    store = SqliteStore(db_path)
    store.insert_packet(123, packet, inventory)
    store.commit()
    store.close()

    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM ifa_records").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM hops").fetchone()[0] == 3
    path = conn.execute("SELECT resolved_traffic_path FROM ifa_records").fetchone()[0]
    assert path.startswith("Border1(Ethernet0->Ethernet48)")


def test_sqlite_store_re_resolves_existing_hops(tmp_path: Path) -> None:
    packet = ParsedIfaPacket(
        flow_key=FlowKey("1.1.1.1", "4.4.4.4", 17, 12345, 5000),
        ifa_header=IfaHeader(2, 15, 17, 0, 255),
        metadata_header=IfaMetadataHeader(255, 255, 30, 24),
        checksum_header=None,
        fragment_header=None,
        hops=[
            HopMetadata(b"", {"device_id": 1002, "ingress_logical_port": 79, "egress_logical_port": 3}),
            HopMetadata(b"", {"device_id": 1003, "ingress_logical_port": 91, "egress_logical_port": 95}),
            HopMetadata(b"", {"device_id": 1001, "ingress_logical_port": 3, "egress_logical_port": 79}),
        ],
        raw_metadata_stack=b"abc",
        post_metadata_payload=b"def",
        raw_packet=b"abcdef",
        wrapper={"sequence_number": 10, "observation_domain_id": 305419896, "set_id": 257, "transport": {}},
    )
    db_path = tmp_path / "ifa.sqlite"
    store = SqliteStore(db_path)
    store.insert_packet(123, packet, Inventory())
    store.commit()

    conn = sqlite3.connect(db_path)
    before_path = conn.execute("SELECT resolved_traffic_path FROM ifa_records").fetchone()[0]
    before_iface = conn.execute("SELECT ingress_interface FROM hops WHERE device_id = 1001").fetchone()[0]
    conn.close()
    assert before_path.startswith("1001(3->79)")
    assert before_iface is None

    result = store.re_resolve_inventory(Inventory.load(Path("inventory/lab_topology.json")))
    store.close()

    conn = sqlite3.connect(db_path)
    after_path = conn.execute("SELECT resolved_traffic_path FROM ifa_records").fetchone()[0]
    after_iface = conn.execute("SELECT ingress_interface FROM hops WHERE device_id = 1001").fetchone()[0]
    conn.close()
    assert result == {"records": 1, "hops": 3}
    assert after_path.startswith("Border1(Ethernet0->Ethernet48)")
    assert after_iface == "Ethernet0"
