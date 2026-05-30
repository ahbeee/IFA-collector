import sqlite3
from pathlib import Path

from ifa_collector.query import QueryStore


def test_query_store_lists_exporters_and_paths(tmp_path: Path) -> None:
    db = tmp_path / "ifa.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE exporters (
            exporter_key TEXT PRIMARY KEY, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
            observation_domain_id INTEGER, first_sequence INTEGER, last_sequence INTEGER, records INTEGER,
            gaps INTEGER, duplicate_or_reordered INTEGER, last_seen_ns INTEGER
        );
        CREATE TABLE flows (
            flow_key TEXT PRIMARY KEY, src_ip TEXT, dst_ip TEXT, protocol INTEGER, src_port INTEGER,
            dst_port INTEGER, tunnel_vni INTEGER, records INTEGER, first_seen_ns INTEGER, last_seen_ns INTEGER
        );
        CREATE TABLE ifa_records (
            id INTEGER PRIMARY KEY, timestamp_ns INTEGER, exporter_key TEXT, sequence_number INTEGER,
            observation_domain_id INTEGER, set_id INTEGER, flow_key TEXT, metadata_path TEXT,
            traffic_path TEXT, resolved_traffic_path TEXT, hop_count INTEGER, raw_metadata_hex TEXT,
            clipped_packet_hex TEXT
        );
        CREATE TABLE hops (
            id INTEGER PRIMARY KEY, record_id INTEGER, metadata_index INTEGER, traffic_index INTEGER,
            device_id INTEGER, device_name TEXT, model TEXT, ingress_logical_port INTEGER,
            ingress_interface TEXT, egress_logical_port INTEGER, egress_interface TEXT, ttl INTEGER,
            raw_hex TEXT, fields_json TEXT
        );
        CREATE TABLE parse_errors (id INTEGER PRIMARY KEY, timestamp_ns INTEGER, error TEXT, count INTEGER);
        INSERT INTO exporters VALUES ('exp', '10.0.0.1', 9070, '192.0.2.1', 9090, 1, 1, 2, 2, 0, 0, 20);
        INSERT INTO flows VALUES ('flow', '1.1.1.1', '4.4.4.4', 17, 1, 2, NULL, 1, 10, 20);
        INSERT INTO ifa_records VALUES (1, 10, 'exp', 1, 1, 257, 'flow', '2 -> 1', '1 -> 2', 'A -> B', 2, '', '');
        INSERT INTO hops VALUES (1, 1, 0, 0, 1001, 'A', 'model', 3, 'Ethernet0', 79, 'Ethernet48', 63, '', '{}');
        INSERT INTO hops VALUES (2, 1, 1, 1, 1002, NULL, NULL, 3, NULL, 79, NULL, 62, '', '{}');
        """
    )
    conn.commit()
    conn.close()

    store = QueryStore(db)
    assert store.exporters()[0]["exporter_key"] == "exp"
    flow = store.flows()[0]
    assert flow["flow_key"] == "flow"
    assert flow["paths"] == 1
    assert flow["min_hops"] == 2
    assert flow["max_hops"] == 2
    path = store.paths()[0]
    assert path["resolved_traffic_path"] == "A -> B"
    assert path["flows"] == 1
    assert path["min_hops"] == 2
    assert path["max_hops"] == 2
    assert path["total_hops"] == 2
    assert path["unresolved_devices"] == 1
    assert path["unresolved_ingress_ports"] == 1
    assert path["unresolved_egress_ports"] == 1
    assert store.resolution_summary() == {
        "hops": 2,
        "unresolved_devices": 1,
        "unresolved_ingress_ports": 1,
        "unresolved_egress_ports": 1,
    }
    unresolved = store.unresolved_hops()
    assert len(unresolved) == 1
    assert unresolved[0]["record_id"] == 1
    assert unresolved[0]["device_id"] == 1002
    assert unresolved[0]["ingress_logical_port"] == 3
    assert unresolved[0]["egress_logical_port"] == 79
    detail = store.path_detail("A -> B")
    assert detail["path"]["records"] == 1
    assert detail["sample_record"]["flow_key"] == "flow"
    assert [hop["device_id"] for hop in detail["sample_record"]["hops"]] == [1001, 1002]
    store.close()
