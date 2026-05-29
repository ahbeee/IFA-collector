from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class QueryStore:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        self.conn.close()

    def exporters(self) -> list[dict[str, Any]]:
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

    def flows(self, limit: int = 20) -> list[dict[str, Any]]:
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

    def paths(self, limit: int = 20) -> list[dict[str, Any]]:
        return _rows_to_dicts(
            self.conn.execute(
                """
                SELECT
                    resolved_traffic_path, traffic_path, metadata_path,
                    COUNT(*) AS records,
                    COUNT(DISTINCT flow_key) AS flows,
                    MIN(hop_count) AS min_hops,
                    MAX(hop_count) AS max_hops
                FROM ifa_records
                GROUP BY resolved_traffic_path, traffic_path, metadata_path
                ORDER BY records DESC
                LIMIT ?
                """,
                (limit,),
            )
        )

    def flow_detail(self, flow_key: str, limit: int = 10) -> dict[str, Any]:
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

        paths = _rows_to_dicts(
            self.conn.execute(
                """
                SELECT
                    resolved_traffic_path, traffic_path, metadata_path,
                    COUNT(*) AS records,
                    MIN(hop_count) AS min_hops,
                    MAX(hop_count) AS max_hops
                FROM ifa_records
                WHERE flow_key = ?
                GROUP BY resolved_traffic_path, traffic_path, metadata_path
                ORDER BY records DESC
                """,
                (flow_key,),
            )
        )

        records = []
        for record in self.conn.execute(
            """
            SELECT id, timestamp_ns, exporter_key, sequence_number, traffic_path, resolved_traffic_path
            FROM ifa_records
            WHERE flow_key = ?
            ORDER BY id
            LIMIT ?
            """,
            (flow_key, limit),
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

    def errors(self, limit: int = 20) -> list[dict[str, Any]]:
        return _rows_to_dicts(
            self.conn.execute(
                """
                SELECT error, COUNT(*) AS occurrences, MIN(timestamp_ns) AS first_seen_ns, MAX(timestamp_ns) AS last_seen_ns
                FROM parse_errors
                GROUP BY error
                ORDER BY occurrences DESC
                LIMIT ?
                """,
                (limit,),
            )
        )


def _rows_to_dicts(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(row) for row in cursor.fetchall()]
