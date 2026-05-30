from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class QueryStore:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._ensure_optional_schema()

    def close(self) -> None:
        self.conn.close()

    def _ensure_optional_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS import_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imported_at_ns INTEGER NOT NULL,
                source TEXT,
                parsed_ifa_records INTEGER NOT NULL DEFAULT 0,
                parse_errors INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        _ensure_column(self.conn, "ifa_records", "import_id", "INTEGER")
        _ensure_column(self.conn, "parse_errors", "import_id", "INTEGER")
        self.conn.commit()

    def exporters(self, import_id: int | None = None) -> list[dict[str, Any]]:
        if import_id is not None:
            return _rows_to_dicts(
                self.conn.execute(
                    """
                    SELECT
                        r.exporter_key,
                        e.src_ip, e.src_port, e.dst_ip, e.dst_port, r.observation_domain_id,
                        MIN(r.sequence_number) AS first_sequence,
                        MAX(r.sequence_number) AS last_sequence,
                        COUNT(*) AS records,
                        CASE
                            WHEN MIN(r.sequence_number) IS NULL OR MAX(r.sequence_number) IS NULL THEN 0
                            ELSE MAX(r.sequence_number) - MIN(r.sequence_number) + 1 - COUNT(DISTINCT r.sequence_number)
                        END AS gaps,
                        COUNT(r.sequence_number) - COUNT(DISTINCT r.sequence_number) AS duplicate_or_reordered,
                        MAX(r.timestamp_ns) AS last_seen_ns
                    FROM ifa_records AS r
                    LEFT JOIN exporters AS e ON e.exporter_key = r.exporter_key
                    WHERE r.import_id = ? AND r.exporter_key IS NOT NULL
                    GROUP BY r.exporter_key, e.src_ip, e.src_port, e.dst_ip, e.dst_port, r.observation_domain_id
                    ORDER BY records DESC
                    """,
                    (import_id,),
                )
            )
        return _rows_to_dicts(
            self.conn.execute(
                """
                SELECT
                    exporter_key, src_ip, src_port, dst_ip, dst_port, observation_domain_id,
                    first_sequence, last_sequence, records, gaps, duplicate_or_reordered, last_seen_ns
                FROM exporters
                ORDER BY records DESC
                """
            )
        )

    def flows(self, limit: int = 20, import_id: int | None = None) -> list[dict[str, Any]]:
        if import_id is not None:
            return _rows_to_dicts(
                self.conn.execute(
                    """
                    SELECT
                        r.flow_key, f.src_ip, f.dst_ip, f.protocol, f.src_port, f.dst_port, f.tunnel_vni,
                        COUNT(DISTINCT r.id) AS records,
                        MIN(r.timestamp_ns) AS first_seen_ns,
                        MAX(r.timestamp_ns) AS last_seen_ns,
                        COUNT(DISTINCT r.resolved_traffic_path) AS paths,
                        MIN(r.hop_count) AS min_hops,
                        MAX(r.hop_count) AS max_hops
                    FROM ifa_records AS r
                    LEFT JOIN flows AS f ON f.flow_key = r.flow_key
                    WHERE r.import_id = ?
                    GROUP BY r.flow_key
                    ORDER BY records DESC
                    LIMIT ?
                    """,
                    (import_id, limit),
                )
            )
        return _rows_to_dicts(
            self.conn.execute(
                """
                SELECT
                    f.flow_key, f.src_ip, f.dst_ip, f.protocol, f.src_port, f.dst_port, f.tunnel_vni,
                    f.records, f.first_seen_ns, f.last_seen_ns,
                    COUNT(DISTINCT r.resolved_traffic_path) AS paths,
                    MIN(r.hop_count) AS min_hops,
                    MAX(r.hop_count) AS max_hops
                FROM flows AS f
                LEFT JOIN ifa_records AS r ON r.flow_key = f.flow_key
                GROUP BY f.flow_key
                ORDER BY f.records DESC
                LIMIT ?
                """,
                (limit,),
            )
        )

    def paths(self, limit: int = 20, import_id: int | None = None) -> list[dict[str, Any]]:
        where = "WHERE r.import_id = ?" if import_id is not None else ""
        params: tuple[Any, ...] = (import_id, limit) if import_id is not None else (limit,)
        return _rows_to_dicts(
            self.conn.execute(
                f"""
                SELECT
                    r.resolved_traffic_path, r.traffic_path, r.metadata_path,
                    COUNT(DISTINCT r.id) AS records,
                    COUNT(DISTINCT r.flow_key) AS flows,
                    MIN(r.hop_count) AS min_hops,
                    MAX(r.hop_count) AS max_hops,
                    COUNT(h.id) AS total_hops,
                    SUM(CASE WHEN h.device_name IS NULL THEN 1 ELSE 0 END) AS unresolved_devices,
                    SUM(CASE WHEN h.ingress_logical_port IS NOT NULL AND h.ingress_interface IS NULL THEN 1 ELSE 0 END) AS unresolved_ingress_ports,
                    SUM(CASE WHEN h.egress_logical_port IS NOT NULL AND h.egress_interface IS NULL THEN 1 ELSE 0 END) AS unresolved_egress_ports
                FROM ifa_records AS r
                LEFT JOIN hops AS h ON h.record_id = r.id
                {where}
                GROUP BY r.resolved_traffic_path, r.traffic_path, r.metadata_path
                ORDER BY records DESC
                LIMIT ?
                """,
                params,
            )
        )

    def resolution_summary(self, import_id: int | None = None) -> dict[str, int]:
        join = "JOIN ifa_records AS r ON r.id = h.record_id" if import_id is not None else ""
        where = "WHERE r.import_id = ?" if import_id is not None else ""
        params: tuple[Any, ...] = (import_id,) if import_id is not None else ()
        row = self.conn.execute(
            f"""
            SELECT
                COUNT(*) AS hops,
                SUM(CASE WHEN device_name IS NULL THEN 1 ELSE 0 END) AS unresolved_devices,
                SUM(CASE WHEN ingress_logical_port IS NOT NULL AND ingress_interface IS NULL THEN 1 ELSE 0 END) AS unresolved_ingress_ports,
                SUM(CASE WHEN egress_logical_port IS NOT NULL AND egress_interface IS NULL THEN 1 ELSE 0 END) AS unresolved_egress_ports
            FROM hops AS h
            {join}
            {where}
            """,
            params,
        ).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def unresolved_hops(self, limit: int = 100, import_id: int | None = None) -> list[dict[str, Any]]:
        import_filter = "AND r.import_id = ?" if import_id is not None else ""
        params: tuple[Any, ...] = (import_id, limit) if import_id is not None else (limit,)
        return _rows_to_dicts(
            self.conn.execute(
                f"""
                SELECT
                    h.record_id, h.traffic_index, h.device_id,
                    h.ingress_logical_port, h.ingress_interface,
                    h.egress_logical_port, h.egress_interface,
                    r.flow_key, r.resolved_traffic_path, r.sequence_number, r.exporter_key
                FROM hops AS h
                JOIN ifa_records AS r ON r.id = h.record_id
                WHERE (h.device_name IS NULL
                   OR (h.ingress_logical_port IS NOT NULL AND h.ingress_interface IS NULL)
                   OR (h.egress_logical_port IS NOT NULL AND h.egress_interface IS NULL))
                   {import_filter}
                ORDER BY h.record_id DESC, h.traffic_index ASC
                LIMIT ?
                """,
                params,
            )
        )

    def flow_detail(self, flow_key: str, limit: int = 10, import_id: int | None = None) -> dict[str, Any]:
        if import_id is not None:
            flow = self.conn.execute(
                """
                SELECT
                    r.flow_key, f.src_ip, f.dst_ip, f.protocol, f.src_port, f.dst_port, f.tunnel_vni,
                    COUNT(*) AS records,
                    MIN(r.timestamp_ns) AS first_seen_ns,
                    MAX(r.timestamp_ns) AS last_seen_ns
                FROM ifa_records AS r
                LEFT JOIN flows AS f ON f.flow_key = r.flow_key
                WHERE r.flow_key = ? AND r.import_id = ?
                GROUP BY r.flow_key, f.src_ip, f.dst_ip, f.protocol, f.src_port, f.dst_port, f.tunnel_vni
                """,
                (flow_key, import_id),
            ).fetchone()
        else:
            flow = self.conn.execute(
                """
                SELECT flow_key, src_ip, dst_ip, protocol, src_port, dst_port, tunnel_vni,
                       records, first_seen_ns, last_seen_ns
                FROM flows
                WHERE flow_key = ?
                """,
                (flow_key,),
            ).fetchone()
        if flow is None:
            raise ValueError(f"flow not found: {flow_key}")

        import_filter = "AND import_id = ?" if import_id is not None else ""
        flow_params: tuple[Any, ...] = (flow_key, import_id) if import_id is not None else (flow_key,)
        paths = _rows_to_dicts(
            self.conn.execute(
                f"""
                SELECT
                    resolved_traffic_path, traffic_path, metadata_path,
                    COUNT(*) AS records,
                    MIN(timestamp_ns) AS first_seen_ns,
                    MAX(timestamp_ns) AS last_seen_ns,
                    MIN(hop_count) AS min_hops,
                    MAX(hop_count) AS max_hops
                FROM ifa_records
                WHERE flow_key = ?
                {import_filter}
                GROUP BY resolved_traffic_path, traffic_path, metadata_path
                ORDER BY records DESC
                """,
                flow_params,
            )
        )

        records = []
        for record in self.conn.execute(
            f"""
            SELECT id, timestamp_ns, exporter_key, sequence_number, traffic_path, resolved_traffic_path
            FROM ifa_records
            WHERE flow_key = ?
            {import_filter}
            ORDER BY id
            LIMIT ?
            """,
            (*flow_params, limit),
        ):
            hops = _rows_to_dicts(
                self.conn.execute(
                    """
                    SELECT traffic_index, device_id, device_name, model,
                           ingress_logical_port, ingress_interface,
                           egress_logical_port, egress_interface,
                           ttl, raw_hex, fields_json
                    FROM hops
                    WHERE record_id = ?
                    ORDER BY traffic_index
                    """,
                    (record["id"],),
                )
            )
            item = dict(record)
            item["hops"] = hops
            records.append(item)

        return {"flow": dict(flow), "paths": paths, "sample_records": records}

    def path_detail(self, resolved_traffic_path: str, import_id: int | None = None, limit: int = 5) -> dict[str, Any]:
        import_filter = "AND import_id = ?" if import_id is not None else ""
        params: tuple[Any, ...] = (resolved_traffic_path, import_id) if import_id is not None else (resolved_traffic_path,)
        path = self.conn.execute(
            f"""
            SELECT
                resolved_traffic_path, traffic_path, metadata_path,
                COUNT(DISTINCT id) AS records,
                COUNT(DISTINCT flow_key) AS flows,
                MIN(hop_count) AS min_hops,
                MAX(hop_count) AS max_hops
            FROM ifa_records
            WHERE resolved_traffic_path = ?
              {import_filter}
            GROUP BY resolved_traffic_path, traffic_path, metadata_path
            ORDER BY records DESC
            LIMIT 1
            """,
            params,
        ).fetchone()
        if path is None:
            raise ValueError(f"path not found: {resolved_traffic_path}")

        flow_rows = _rows_to_dicts(
            self.conn.execute(
                f"""
                SELECT
                    flow_key,
                    COUNT(*) AS records,
                    MIN(timestamp_ns) AS first_seen_ns,
                    MAX(timestamp_ns) AS last_seen_ns,
                    MIN(sequence_number) AS first_sequence,
                    MAX(sequence_number) AS last_sequence
                FROM ifa_records
                WHERE resolved_traffic_path = ?
                  {import_filter}
                GROUP BY flow_key
                ORDER BY records DESC, flow_key
                """,
                params,
            )
        )

        record_params: tuple[Any, ...] = (resolved_traffic_path, import_id) if import_id is not None else (resolved_traffic_path,)
        sample_records = []
        for record in self.conn.execute(
            f"""
            SELECT id, timestamp_ns, exporter_key, sequence_number, flow_key, resolved_traffic_path
            FROM ifa_records
            WHERE resolved_traffic_path = ?
              {import_filter}
            ORDER BY id DESC
            LIMIT ?
            """,
            (*record_params, limit),
        ):
            sample_record = dict(record)
            sample_record["hops"] = _rows_to_dicts(
                self.conn.execute(
                    """
                    SELECT traffic_index, device_id, device_name, model,
                           ingress_logical_port, ingress_interface,
                           egress_logical_port, egress_interface,
                           ttl, raw_hex, fields_json
                    FROM hops
                    WHERE record_id = ?
                    ORDER BY traffic_index
                    """,
                    (sample_record["id"],),
                )
            )
            sample_records.append(sample_record)

        return {
            "path": dict(path),
            "flows": flow_rows,
            "sample_record": sample_records[0] if sample_records else None,
            "sample_records": sample_records,
        }

    def recent_records(self, limit: int = 20, import_id: int | None = None) -> list[dict[str, Any]]:
        where = "WHERE import_id = ?" if import_id is not None else ""
        params: tuple[Any, ...] = (import_id, limit) if import_id is not None else (limit,)
        records = []
        for record in self.conn.execute(
            f"""
            SELECT id, timestamp_ns, exporter_key, sequence_number, flow_key, hop_count,
                   import_id, traffic_path, resolved_traffic_path
            FROM ifa_records
            {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            params,
        ):
            item = dict(record)
            item["hops"] = _rows_to_dicts(
                self.conn.execute(
                    """
                    SELECT traffic_index, device_id, device_name,
                           ingress_logical_port, ingress_interface,
                           egress_logical_port, egress_interface, ttl
                    FROM hops
                    WHERE record_id = ?
                    ORDER BY traffic_index
                    """,
                    (record["id"],),
                )
            )
            records.append(item)
        return records

    def import_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        return _rows_to_dicts(
            self.conn.execute(
                """
                SELECT id, imported_at_ns, source, parsed_ifa_records, parse_errors
                FROM import_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
        )

    def errors(self, limit: int = 20, import_id: int | None = None) -> list[dict[str, Any]]:
        where = "WHERE import_id = ?" if import_id is not None else ""
        params: tuple[Any, ...] = (import_id, limit) if import_id is not None else (limit,)
        return _rows_to_dicts(
            self.conn.execute(
                f"""
                SELECT error, COUNT(*) AS occurrences, MIN(timestamp_ns) AS first_seen_ns, MAX(timestamp_ns) AS last_seen_ns
                FROM parse_errors
                {where}
                GROUP BY error
                ORDER BY occurrences DESC
                LIMIT ?
                """,
                params,
            )
        )


def _rows_to_dicts(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(row) for row in cursor.fetchall()]


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if not table_exists:
        return
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
