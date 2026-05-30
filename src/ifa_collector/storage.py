from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .inventory import Inventory
from .models import HopMetadata


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
                import_id INTEGER,
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
                FOREIGN KEY(import_id) REFERENCES import_runs(id),
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
                import_id INTEGER,
                timestamp_ns INTEGER,
                error TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(import_id) REFERENCES import_runs(id)
            );

            CREATE TABLE IF NOT EXISTS import_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imported_at_ns INTEGER NOT NULL,
                source TEXT,
                parsed_ifa_records INTEGER NOT NULL DEFAULT 0,
                parse_errors INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        _ensure_column(self.conn, "ifa_records", "import_id", "INTEGER")
        _ensure_column(self.conn, "parse_errors", "import_id", "INTEGER")
        self.conn.commit()

    def insert_error(self, timestamp_ns: int, error: str, import_id: int | None = None) -> None:
        self.conn.execute(
            "INSERT INTO parse_errors(import_id, timestamp_ns, error, count) VALUES (?, ?, ?, 1)",
            (import_id, timestamp_ns, error),
        )

    def record_import_run(self, imported_at_ns: int, source: str | None, parsed_ifa_records: int, parse_errors: int) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO import_runs(imported_at_ns, source, parsed_ifa_records, parse_errors)
            VALUES (?, ?, ?, ?)
            """,
            (imported_at_ns, source, parsed_ifa_records, parse_errors),
        )
        return int(cursor.lastrowid)

    def update_import_run(self, import_id: int, parsed_ifa_records: int, parse_errors: int) -> None:
        self.conn.execute(
            """
            UPDATE import_runs
            SET parsed_ifa_records = ?, parse_errors = ?
            WHERE id = ?
            """,
            (parsed_ifa_records, parse_errors, import_id),
        )

    def insert_packet(self, timestamp_ns: int | None, packet: Any, inventory: Inventory, import_id: int | None = None) -> None:
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
                import_id, timestamp_ns, exporter_key, sequence_number, observation_domain_id, set_id, flow_key,
                metadata_path, traffic_path, resolved_traffic_path, hop_count,
                raw_metadata_hex, clipped_packet_hex
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
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
            DELETE FROM import_runs;
            """
        )
        self.conn.commit()

    def delete_import_run(self, import_id: int) -> dict[str, int]:
        records = int(
            self.conn.execute(
                "SELECT COUNT(*) FROM ifa_records WHERE import_id = ?",
                (import_id,),
            ).fetchone()[0]
            or 0
        )
        hops = int(
            self.conn.execute(
                """
                SELECT COUNT(*)
                FROM hops AS h
                JOIN ifa_records AS r ON r.id = h.record_id
                WHERE r.import_id = ?
                """,
                (import_id,),
            ).fetchone()[0]
            or 0
        )
        errors = int(
            self.conn.execute(
                "SELECT COUNT(*) FROM parse_errors WHERE import_id = ?",
                (import_id,),
            ).fetchone()[0]
            or 0
        )

        self.conn.execute(
            "DELETE FROM hops WHERE record_id IN (SELECT id FROM ifa_records WHERE import_id = ?)",
            (import_id,),
        )
        self.conn.execute("DELETE FROM ifa_records WHERE import_id = ?", (import_id,))
        self.conn.execute("DELETE FROM parse_errors WHERE import_id = ?", (import_id,))
        deleted_imports = self.conn.execute("DELETE FROM import_runs WHERE id = ?", (import_id,)).rowcount
        self._rebuild_aggregate_counts()
        self.conn.commit()
        return {"imports": int(deleted_imports or 0), "records": records, "hops": hops, "errors": errors}

    def re_resolve_inventory(self, inventory: Inventory) -> dict[str, int]:
        hop_rows = self.conn.execute(
            """
            SELECT id, record_id, device_id, ingress_logical_port, egress_logical_port, fields_json
            FROM hops
            ORDER BY record_id, metadata_index
            """
        ).fetchall()

        hops_by_record: dict[int, list[dict[str, Any]]] = {}
        updated_hops = 0
        for hop_id, record_id, device_id, ingress_port, egress_port, fields_json in hop_rows:
            fields = _stored_hop_fields(fields_json)
            fields["device_id"] = device_id
            fields["ingress_logical_port"] = ingress_port
            fields["egress_logical_port"] = egress_port
            resolved = inventory.resolve_hop(HopMetadata(b"", fields))
            ingress = resolved["ingress"]
            egress = resolved["egress"]
            self.conn.execute(
                """
                UPDATE hops
                SET device_name = ?, model = ?, ingress_interface = ?, egress_interface = ?
                WHERE id = ?
                """,
                (
                    resolved.get("device_name"),
                    resolved.get("model"),
                    ingress.get("interface"),
                    egress.get("interface"),
                    hop_id,
                ),
            )
            updated_hops += 1
            hops_by_record.setdefault(int(record_id), []).append(
                {
                    "device_id": device_id,
                    "device_name": resolved.get("device_name"),
                    "ingress_logical_port": ingress_port,
                    "ingress_interface": ingress.get("interface"),
                    "egress_logical_port": egress_port,
                    "egress_interface": egress.get("interface"),
                }
            )

        updated_records = 0
        for record_id, hops in hops_by_record.items():
            path = _stored_resolved_path_key(list(reversed(hops)))
            self.conn.execute(
                "UPDATE ifa_records SET resolved_traffic_path = ? WHERE id = ?",
                (path, record_id),
            )
            updated_records += 1

        self.conn.commit()
        return {"records": updated_records, "hops": updated_hops}

    def _rebuild_aggregate_counts(self) -> None:
        self.conn.execute(
            """
            UPDATE flows
            SET
                records = COALESCE((SELECT COUNT(*) FROM ifa_records WHERE flow_key = flows.flow_key), 0),
                first_seen_ns = (SELECT MIN(timestamp_ns) FROM ifa_records WHERE flow_key = flows.flow_key),
                last_seen_ns = (SELECT MAX(timestamp_ns) FROM ifa_records WHERE flow_key = flows.flow_key)
            """
        )
        self.conn.execute("DELETE FROM flows WHERE records = 0")

        exporter_stats = {}
        for row in self.conn.execute(
            """
            SELECT exporter_key, sequence_number, timestamp_ns
            FROM ifa_records
            WHERE exporter_key IS NOT NULL
            ORDER BY exporter_key, sequence_number
            """
        ):
            key = row[0]
            stats = exporter_stats.setdefault(
                key,
                {
                    "records": 0,
                    "first_sequence": None,
                    "last_sequence": None,
                    "gaps": 0,
                    "duplicate_or_reordered": 0,
                    "last_seen_ns": None,
                },
            )
            sequence = row[1]
            stats["records"] += 1
            if stats["last_seen_ns"] is None or (row[2] is not None and row[2] > stats["last_seen_ns"]):
                stats["last_seen_ns"] = row[2]
            if sequence is None:
                continue
            if stats["first_sequence"] is None:
                stats["first_sequence"] = sequence
            previous = stats["last_sequence"]
            if previous is not None:
                if sequence > previous + 1:
                    stats["gaps"] += sequence - previous - 1
                elif sequence <= previous:
                    stats["duplicate_or_reordered"] += 1
            stats["last_sequence"] = sequence

        for key, stats in exporter_stats.items():
            self.conn.execute(
                """
                UPDATE exporters
                SET first_sequence = ?, last_sequence = ?, records = ?, gaps = ?,
                    duplicate_or_reordered = ?, last_seen_ns = ?
                WHERE exporter_key = ?
                """,
                (
                    stats["first_sequence"],
                    stats["last_sequence"],
                    stats["records"],
                    stats["gaps"],
                    stats["duplicate_or_reordered"],
                    stats["last_seen_ns"],
                    key,
                ),
            )
        self.conn.execute(
            """
            DELETE FROM exporters
            WHERE NOT EXISTS (
                SELECT 1 FROM ifa_records WHERE ifa_records.exporter_key = exporters.exporter_key
            )
            """
        )

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


def _stored_hop_fields(fields_json: str | None) -> dict[str, Any]:
    if not fields_json:
        return {}
    try:
        value = json.loads(fields_json)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _stored_resolved_path_key(hops: list[dict[str, Any]]) -> str:
    labels = []
    for hop in hops:
        name = hop.get("device_name") or str(hop.get("device_id"))
        ingress = hop.get("ingress_interface") or hop.get("ingress_logical_port")
        egress = hop.get("egress_interface") or hop.get("egress_logical_port")
        labels.append(f"{name}({ingress}->{egress})")
    return " -> ".join(labels)


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
