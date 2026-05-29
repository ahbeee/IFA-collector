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
        """
    )
    conn.commit()
    conn.close()

    store = QueryStore(db)
    assert store.exporters()[0]["exporter_key"] == "exp"
    assert store.flows()[0]["flow_key"] == "flow"
    assert store.paths()[0]["resolved_traffic_path"] == "A -> B"
    store.close()
