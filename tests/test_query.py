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
            id INTEGER PRIMARY KEY, import_id INTEGER, timestamp_ns INTEGER, exporter_key TEXT, sequence_number INTEGER,
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
        CREATE TABLE parse_errors (id INTEGER PRIMARY KEY, import_id INTEGER, timestamp_ns INTEGER, error TEXT, count INTEGER);
        CREATE TABLE import_runs (
            id INTEGER PRIMARY KEY, imported_at_ns INTEGER, source TEXT,
            parsed_ifa_records INTEGER, parse_errors INTEGER
        );
        INSERT INTO exporters VALUES ('exp', '10.0.0.1', 9070, '192.0.2.1', 9090, 1, 1, 2, 2, 0, 0, 20);
        INSERT INTO flows VALUES ('flow', '1.1.1.1', '4.4.4.4', 17, 1, 2, NULL, 2, 10, 30);
        INSERT INTO ifa_records VALUES (1, 1, 10, 'exp', 1, 1, 257, 'flow', '2 -> 1', '1 -> 2', 'A -> B', 2, '', '');
        INSERT INTO ifa_records VALUES (2, 2, 30, 'exp', 2, 1, 257, 'flow', '3', '3', 'C', 1, '', '');
        INSERT INTO parse_errors VALUES (1, 1, 11, 'bad packet', 1);
        INSERT INTO hops VALUES (1, 1, 0, 0, 1001, 'A', 'model', 3, 'Ethernet0', 79, 'Ethernet48', 63, '', '{}');
        INSERT INTO hops VALUES (2, 1, 1, 1, 1002, NULL, NULL, 3, NULL, 79, NULL, 62, '', '{}');
        INSERT INTO hops VALUES (3, 2, 0, 0, 1003, 'C', 'model', 11, 'Ethernet11', 12, 'Ethernet12', 61, '', '{}');
        INSERT INTO import_runs VALUES (1, 123000000000, 'sample.pcap', 2, 1);
        INSERT INTO import_runs VALUES (2, 124000000000, 'sample-2.pcap', 1, 0);
        """
    )
    conn.commit()
    conn.close()

    store = QueryStore(db)
    assert store.exporters()[0]["exporter_key"] == "exp"
    exporter_one = store.exporters(import_id=1)[0]
    assert exporter_one["records"] == 1
    assert exporter_one["first_sequence"] == 1
    assert exporter_one["last_sequence"] == 1
    assert exporter_one["first_seen_ns"] == 10
    assert exporter_one["last_seen_ns"] == 10
    assert store.exporters()[0]["first_seen_ns"] == 10
    flow = store.flows()[0]
    assert flow["flow_key"] == "flow"
    assert flow["paths"] == 2
    assert flow["min_hops"] == 1
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
        "hops": 3,
        "unresolved_devices": 1,
        "unresolved_ingress_ports": 1,
        "unresolved_egress_ports": 1,
    }
    assert store.resolution_summary(import_id=1) == {
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
    assert detail["flows"][0]["flow_key"] == "flow"
    assert detail["flows"][0]["records"] == 1
    assert detail["flows"][0]["first_sequence"] == 1
    assert detail["flows"][0]["last_sequence"] == 1
    assert detail["sample_record"]["flow_key"] == "flow"
    assert [hop["device_id"] for hop in detail["sample_record"]["hops"]] == [1001, 1002]
    assert [record["id"] for record in detail["sample_records"]] == [1]
    assert [hop["device_id"] for hop in detail["sample_records"][0]["hops"]] == [1001, 1002]
    flow_detail = store.flow_detail("flow", import_id=1)
    assert flow_detail["flow"]["records"] == 1
    assert len(flow_detail["paths"]) == 1
    assert flow_detail["paths"][0]["resolved_traffic_path"] == "A -> B"
    assert flow_detail["paths"][0]["first_seen_ns"] == 10
    assert flow_detail["paths"][0]["last_seen_ns"] == 10
    assert [record["id"] for record in flow_detail["sample_records"]] == [1]
    recent = store.recent_records(import_id=1)
    assert recent[0]["id"] == 1
    assert recent[0]["resolved_traffic_path"] == "A -> B"
    assert [hop["device_id"] for hop in recent[0]["hops"]] == [1001, 1002]
    imports = store.import_runs()
    import_one = next(item for item in imports if item["id"] == 1)
    assert import_one["source"] == "sample.pcap"
    assert import_one["parsed_ifa_records"] == 2
    assert import_one["parse_errors"] == 1
    assert store.flows(import_id=1)[0]["records"] == 1
    assert store.paths(import_id=1)[0]["records"] == 1
    assert store.recent_records(import_id=1)[0]["import_id"] == 1
    assert store.errors(import_id=1)[0]["error"] == "bad packet"
    store.close()
