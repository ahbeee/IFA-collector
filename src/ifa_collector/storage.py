from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .inventory import Inventory


class SqliteStore:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

    def close(self) -> None:
        self.conn.close()

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS exporters (
                exporter_key TEXT PRIMARY KEY,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                observation_domain_id INTEGER,
                first_sequence INTEGER,
                last_sequence INTEGER,
                records INTEGER NOT NULL DEFAULT 0,
                gaps INTEGER NOT NULL DEFAULT 0,
                duplicate_or_reordered INTEGER NOT NULL DEFAULT 0,
                last_seen_ns INTEGER
            );

            CREATE TABLE IF NOT EXISTS flows (
                flow_key TEXT PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                protocol INTEGER,
                src_port INTEGER,
                dst_port INTEGER,
                tunnel_vni INTEGER,
                records INTEGER NOT NULL DEFAULT 0,
                first_seen_ns INTEGER,
                last_seen_ns INTEGER
            );

            CREATE TABLE IF NOT EXISTS ifa_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns INTEGER,
                exporter_key TEXT,
                sequence_number INTEGER,
                observation_domain_id INTEGER,
                set_id INTEGER,
                flow_key TEXT,
                metadata_path TEXT,
                traffic_path TEXT,
                resolved_traffic_path TEXT,
                hop_count INTEGER,
                raw_metadata_hex TEXT,
                clipped_packet_hex TEXT,
                FOREIGN KEY(exporter_key) REFERENCES exporters(exporter_key),
                FOREIGN KEY(flow_key) REFERENCES flows(flow_key)
            );

            CREATE TABLE IF NOT EXISTS hops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL,
                metadata_index INTEGER NOT NULL,
                traffic_index INTEGER NOT NULL,
                device_id INTEGER,
                device_name TEXT,
                model TEXT,
                ingress_logical_port INTEGER,
                ingress_interface TEXT,
                egress_logical_port INTEGER,
                egress_interface TEXT,
                ttl INTEGER,
                raw_hex TEXT,
                fields_json TEXT,
                FOREIGN KEY(record_id) REFERENCES ifa_records(id)
            );

            CREATE TABLE IF NOT EXISTS parse_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns INTEGER,
                error TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        self.conn.commit()

    def insert_error(self, timestamp_ns: int, error: str) -> None:
        self.conn.execute(
            "INSERT INTO parse_errors(timestamp_ns, error, count) VALUES (?, ?, 1)",
            (timestamp_ns, error),
        )

    def insert_packet(self, timestamp_ns: int | None, packet: Any, inventory: Inventory) -> None:
        wrapper = packet.wrapper or {}
        exporter_key = _exporter_key(wrapper)
        sequence = wrapper.get("sequence_number")
        observation_domain_id = wrapper.get("observation_domain_id")
        transport = wrapper.get("transport") or {}
        self._upsert_exporter(exporter_key, transport, observation_domain_id, sequence, timestamp_ns)

        flow_key = _flow_key(packet.flow_key)
        if packet.flow_key:
            self._upsert_flow(flow_key, packet.flow_key, timestamp_ns)

        metadata_path = " -> ".join(str(hop.fields.get("device_id", "?")) for hop in packet.hops)
        traffic_path = " -> ".join(str(hop.fields.get("device_id", "?")) for hop in reversed(packet.hops))
        resolved_traffic_path = _resolved_path_key(packet.hops, inventory)

        cursor = self.conn.execute(
            """
            INSERT INTO ifa_records(
                timestamp_ns, exporter_key, sequence_number, observation_domain_id, set_id, flow_key,
                metadata_path, traffic_path, resolved_traffic_path, hop_count,
                raw_metadata_hex, clipped_packet_hex
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp_ns,
                exporter_key,
                sequence,
                observation_domain_id,
                wrapper.get("set_id"),
                flow_key,
                metadata_path,
                traffic_path,
                resolved_traffic_path,
                len(packet.hops),
                packet.raw_metadata_stack.hex(),
                packet.post_metadata_payload.hex(),
            ),
        )
        record_id = int(cursor.lastrowid)

        resolved_metadata = inventory.resolve_hops(packet.hops)
        hop_count = len(packet.hops)
        for metadata_index, hop in enumerate(packet.hops):
            resolved = resolved_metadata[metadata_index]
            self.conn.execute(
                """
                INSERT INTO hops(
                    record_id, metadata_index, traffic_index, device_id, device_name, model,
                    ingress_logical_port, ingress_interface, egress_logical_port, egress_interface,
                    ttl, raw_hex, fields_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    metadata_index,
                    hop_count - metadata_index - 1,
                    hop.fields.get("device_id"),
                    resolved.get("device_name"),
                    resolved.get("model"),
                    resolved["ingress"].get("logical_port"),
                    resolved["ingress"].get("interface"),
                    resolved["egress"].get("logical_port"),
                    resolved["egress"].get("interface"),
                    hop.fields.get("ip_ttl"),
                    hop.raw.hex(),
                    json.dumps(hop.fields, sort_keys=True),
                ),
            )

    def commit(self) -> None:
        self.conn.commit()

    def clear_runtime_data(self) -> None:
        self.conn.executescript(
            """
            DELETE FROM hops;
            DELETE FROM ifa_records;
            DELETE FROM flows;
            DELETE FROM exporters;
            DELETE FROM parse_errors;
            """
        )
        self.conn.commit()

    def _upsert_exporter(
        self,
        exporter_key: str,
        transport: dict[str, Any],
        observation_domain_id: int | None,
        sequence: int | None,
        timestamp_ns: int | None,
    ) -> None:
        row = self.conn.execute(
            "SELECT last_sequence FROM exporters WHERE exporter_key = ?",
            (exporter_key,),
        ).fetchone()
        gap = 0
        duplicate = 0
        if row and sequence is not None and row[0] is not None:
            previous = int(row[0])
            if sequence > previous + 1:
                gap = sequence - previous - 1
            elif sequence <= previous:
                duplicate = 1

        self.conn.execute(
            """
            INSERT INTO exporters(
                exporter_key, src_ip, src_port, dst_ip, dst_port, observation_domain_id,
                first_sequence, last_sequence, records, gaps, duplicate_or_reordered, last_seen_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(exporter_key) DO UPDATE SET
                last_sequence = excluded.last_sequence,
                records = exporters.records + 1,
                gaps = exporters.gaps + excluded.gaps,
                duplicate_or_reordered = exporters.duplicate_or_reordered + excluded.duplicate_or_reordered,
                last_seen_ns = excluded.last_seen_ns
            """,
            (
                exporter_key,
                transport.get("src_ip"),
                transport.get("src_port"),
                transport.get("dst_ip"),
                transport.get("dst_port"),
                observation_domain_id,
                sequence,
                sequence,
                gap,
                duplicate,
                timestamp_ns,
            ),
        )

    def _upsert_flow(self, flow_key: str, flow: Any, timestamp_ns: int | None) -> None:
        self.conn.execute(
            """
            INSERT INTO flows(
                flow_key, src_ip, dst_ip, protocol, src_port, dst_port, tunnel_vni,
                records, first_seen_ns, last_seen_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(flow_key) DO UPDATE SET
                records = flows.records + 1,
                last_seen_ns = excluded.last_seen_ns
            """,
            (
                flow_key,
                flow.src_ip,
                flow.dst_ip,
                flow.protocol,
                flow.src_port,
                flow.dst_port,
                flow.tunnel_vni,
                timestamp_ns,
                timestamp_ns,
            ),
        )


def _flow_key(flow: Any) -> str | None:
    return str(flow) if flow else None


def _exporter_key(wrapper: dict[str, Any]) -> str:
    transport = wrapper.get("transport") or {}
    src = transport.get("src_ip", "?")
    sport = transport.get("src_port", "?")
    dst = transport.get("dst_ip", "?")
    dport = transport.get("dst_port", "?")
    odid = wrapper.get("observation_domain_id", "?")
    return f"{src}:{sport}->{dst}:{dport}/odid={odid}"


def _resolved_path_key(hops: list[Any], inventory: Inventory) -> str:
    labels = []
    for hop in inventory.resolve_hops(hops, traffic_order=True):
        name = hop["device_name"] or str(hop["device_id"])
        ingress = hop["ingress"]["interface"] or hop["ingress"]["logical_port"]
        egress = hop["egress"]["interface"] or hop["egress"]["logical_port"]
        labels.append(f"{name}({ingress}->{egress})")
    return " -> ".join(labels)
