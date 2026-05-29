from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path
from typing import Any

from .ifa import parse_ifa_from_frame, parse_ifa_payload
from .inventory import Inventory
from .ipfix import is_ipfix_message, parse_ipfix_message
from .packet import decode_packet
from .pcap import read_pcap
from .query import QueryStore
from .schema import SchemaRegistry
from .storage import SqliteStore
from .topology import RestconfAuth, RestconfDevice, scan_topology, scan_topology_devices
from .web import serve


def main() -> None:
    parser = argparse.ArgumentParser(prog="ifa-collector")
    parser.add_argument("--schema-dir", action="append", type=Path, default=[])
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_pcap = subparsers.add_parser("parse-pcap", help="parse IFA packets from a pcap file")
    parse_pcap.add_argument("pcap", type=Path)
    parse_pcap.add_argument("--limit", type=int, default=0)
    parse_pcap.add_argument("--pretty", action="store_true")
    parse_pcap.add_argument("--summary", action="store_true", help="print aggregate IFA/IPFIX summary")
    parse_pcap.add_argument("--inventory", type=Path, help="JSON inventory for device and port resolution")

    listen_udp = subparsers.add_parser("listen-udp", help="listen for raw IFA payloads over UDP")
    listen_udp.add_argument("--host", default="0.0.0.0")
    listen_udp.add_argument("--port", type=int, required=True)
    listen_udp.add_argument("--pretty", action="store_true")

    ingest_pcap = subparsers.add_parser("ingest-pcap", help="ingest parsed IFA records into SQLite")
    ingest_pcap.add_argument("pcap", type=Path)
    ingest_pcap.add_argument("--db", type=Path, required=True)
    ingest_pcap.add_argument("--inventory", type=Path, help="JSON inventory for device and port resolution")

    query = subparsers.add_parser("query", help="query an ingested SQLite database")
    query.add_argument("--db", type=Path, required=True)
    query.add_argument("--pretty", action="store_true")
    query_sub = query.add_subparsers(dest="query_command", required=True)

    query_exporters = query_sub.add_parser("exporters")
    query_exporters.add_argument("--pretty", action="store_true")
    flows = query_sub.add_parser("flows")
    flows.add_argument("--limit", type=int, default=20)
    flows.add_argument("--pretty", action="store_true")
    paths = query_sub.add_parser("paths")
    paths.add_argument("--limit", type=int, default=20)
    paths.add_argument("--pretty", action="store_true")
    detail = query_sub.add_parser("flow-detail")
    detail.add_argument("flow_key")
    detail.add_argument("--limit", type=int, default=10)
    detail.add_argument("--pretty", action="store_true")
    errors = query_sub.add_parser("errors")
    errors.add_argument("--limit", type=int, default=20)
    errors.add_argument("--pretty", action="store_true")

    serve_cmd = subparsers.add_parser("serve", help="serve a small web UI for an ingested SQLite database")
    serve_cmd.add_argument("--db", type=Path, required=True)
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8080)
    serve_cmd.add_argument("--topology-file", type=Path, default=Path("topology/topology.json"))

    scan_topology_cmd = subparsers.add_parser("scan-topology", help="scan SONiC RESTCONF LLDP topology")
    scan_topology_cmd.add_argument("targets", help="IP, CIDR, range, or comma/space separated targets")
    scan_topology_cmd.add_argument("--username")
    scan_topology_cmd.add_argument("--password")
    scan_topology_cmd.add_argument("--rest-port", type=int, default=443)
    scan_topology_cmd.add_argument("--path-prefix", default="/restconf/data")
    scan_topology_cmd.add_argument("--verify-tls", action="store_true")
    scan_topology_cmd.add_argument("--timeout", type=float, default=10)
    scan_topology_cmd.add_argument("--no-ping", action="store_true", help="skip ICMP reachability check before RESTCONF")
    scan_topology_cmd.add_argument("--ping-timeout-ms", type=int, default=500)
    scan_topology_cmd.add_argument("--output", type=Path, default=Path("topology/topology.json"))
    scan_topology_cmd.add_argument(
        "--device",
        action="append",
        default=[],
        help="scan one device with explicit credentials: host,username,password; may be repeated",
    )

    args = parser.parse_args()
    registry = _load_registry(args.schema_dir)

    if args.command == "parse-pcap":
        inventory = Inventory.load(args.inventory)
        _parse_pcap(args.pcap, registry, inventory, args.limit, args.pretty, args.summary)
    elif args.command == "listen-udp":
        _listen_udp(args.host, args.port, registry, args.pretty)
    elif args.command == "ingest-pcap":
        inventory = Inventory.load(args.inventory)
        _ingest_pcap(args.pcap, args.db, registry, inventory)
    elif args.command == "query":
        _query_db(args)
    elif args.command == "serve":
        serve(args.db, args.host, args.port, args.topology_file)
    elif args.command == "scan-topology":
        if args.device:
            payload = scan_topology_devices(_device_specs(args), args.output)
        else:
            if not args.username or not args.password:
                raise ValueError("--username and --password are required unless --device is used")
            auth = RestconfAuth(
                username=args.username,
                password=args.password,
                port=args.rest_port,
                path_prefix=args.path_prefix,
                verify_tls=args.verify_tls,
                timeout=args.timeout,
            )
            payload = scan_topology(
                args.targets,
                auth,
                args.output,
                ping_first=not args.no_ping,
                ping_timeout_ms=args.ping_timeout_ms,
            )
        _emit({"output": str(args.output), "summary": payload["summary"], "errors": payload["errors"]}, pretty=True)


def _load_registry(paths: list[Path]) -> SchemaRegistry:
    registry = SchemaRegistry.load_default()
    if paths:
        for schema in SchemaRegistry.load(paths)._schemas:
            registry.add(schema)
    return registry


def _parse_pcap(
    path: Path,
    registry: SchemaRegistry,
    inventory: Inventory,
    limit: int,
    pretty: bool,
    summary: bool,
) -> None:
    count = 0
    errors: dict[str, int] = {}
    hop_paths: dict[str, int] = {}
    traffic_paths: dict[str, int] = {}
    resolved_traffic_paths: dict[str, int] = {}
    flows: dict[str, int] = {}
    sequences: dict[str, list[int]] = {}
    for record in read_pcap(path, ignore_truncated_tail=True):
        try:
            parsed_packets = _parse_frame(record.data, registry)
        except ValueError as exc:
            errors[str(exc)] = errors.get(str(exc), 0) + 1
            if not summary:
                _emit({"timestamp_ns": record.timestamp_ns, "parsed": False, "error": str(exc)}, pretty)
            continue

        for parsed in parsed_packets:
            path_key = " -> ".join(str(hop.fields.get("device_id", "?")) for hop in parsed.hops)
            hop_paths[path_key] = hop_paths.get(path_key, 0) + 1
            traffic_key = " -> ".join(str(hop.fields.get("device_id", "?")) for hop in reversed(parsed.hops))
            traffic_paths[traffic_key] = traffic_paths.get(traffic_key, 0) + 1
            resolved_path = _resolved_path_key(parsed.hops, inventory)
            resolved_traffic_paths[resolved_path] = resolved_traffic_paths.get(resolved_path, 0) + 1
            if parsed.flow_key:
                flow_key = str(parsed.flow_key)
                flows[flow_key] = flows.get(flow_key, 0) + 1
            if parsed.wrapper and "sequence_number" in parsed.wrapper:
                exporter_key = _exporter_key(parsed.wrapper)
                sequences.setdefault(exporter_key, []).append(int(parsed.wrapper["sequence_number"]))
            if not summary:
                _emit(_packet_to_dict(record.timestamp_ns, parsed, inventory), pretty)
            count += 1
            if limit and count >= limit:
                if summary:
                    _emit(
                        _summary_to_dict(
                            count,
                            errors,
                            hop_paths,
                            traffic_paths,
                            resolved_traffic_paths,
                            flows,
                            sequences,
                        ),
                        pretty,
                    )
                return
    if summary:
        _emit(
            _summary_to_dict(count, errors, hop_paths, traffic_paths, resolved_traffic_paths, flows, sequences),
            pretty,
        )


def _listen_udp(host: str, port: int, registry: SchemaRegistry, pretty: bool) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    while True:
        data, peer = sock.recvfrom(65535)
        try:
            for parsed in _parse_udp_payload(data, registry):
                payload: dict[str, Any] = _packet_to_dict(None, parsed)
                payload["peer"] = {"host": peer[0], "port": peer[1]}
                _emit(payload, pretty)
        except ValueError as exc:
            _emit({"peer": {"host": peer[0], "port": peer[1]}, "parsed": False, "error": str(exc)}, pretty)


def _ingest_pcap(path: Path, db_path: Path, registry: SchemaRegistry, inventory: Inventory) -> None:
    store = SqliteStore(db_path)
    parsed = 0
    errors = 0
    try:
        for record in read_pcap(path, ignore_truncated_tail=True):
            try:
                packets = _parse_frame(record.data, registry)
            except ValueError as exc:
                store.insert_error(record.timestamp_ns, str(exc))
                errors += 1
                continue
            for packet in packets:
                store.insert_packet(record.timestamp_ns, packet, inventory)
                parsed += 1
                if parsed % 5000 == 0:
                    store.commit()
        store.commit()
    finally:
        store.close()
    _emit({"db": str(db_path), "parsed_ifa_records": parsed, "parse_errors": errors}, pretty=True)


def _query_db(args: Any) -> None:
    store = QueryStore(args.db)
    try:
        if args.query_command == "exporters":
            payload = {"exporters": store.exporters()}
        elif args.query_command == "flows":
            payload = {"flows": store.flows(args.limit)}
        elif args.query_command == "paths":
            payload = {"paths": store.paths(args.limit)}
        elif args.query_command == "flow-detail":
            payload = store.flow_detail(args.flow_key, args.limit)
        elif args.query_command == "errors":
            payload = {"errors": store.errors(args.limit)}
        else:
            raise ValueError(f"unknown query command {args.query_command}")
    finally:
        store.close()
    _emit(payload, args.pretty)


def _parse_frame(data: bytes, registry: SchemaRegistry) -> list[Any]:
    cursor = decode_packet(data)
    if is_ipfix_message(cursor.payload):
        return _parse_ipfix_ifa(cursor.payload, registry, raw_packet=data, transport=cursor.flow_key.__dict__)
    return [parse_ifa_from_frame(data, registry)]


def _parse_udp_payload(data: bytes, registry: SchemaRegistry) -> list[Any]:
    if is_ipfix_message(data):
        return _parse_ipfix_ifa(data, registry, raw_packet=data, transport=None)
    return [parse_ifa_payload(data, registry)]


def _parse_ipfix_ifa(
    data: bytes,
    registry: SchemaRegistry,
    raw_packet: bytes,
    transport: dict[str, Any] | None,
) -> list[Any]:
    message = parse_ipfix_message(data)
    parsed_packets = []
    for item in message.sets:
        if item.set_id < 256:
            continue
        wrapper = {
            "type": "ipfix",
            "version": message.header.version,
            "export_time": message.header.export_time,
            "sequence_number": message.header.sequence_number,
            "observation_domain_id": message.header.observation_domain_id,
            "set_id": item.set_id,
            "set_length": item.length,
            "transport": transport,
        }
        parsed_packets.append(parse_ifa_payload(item.payload, registry, raw_packet=raw_packet, wrapper=wrapper))
    if not parsed_packets:
        raise ValueError("IPFIX message contains no data sets")
    return parsed_packets


def _packet_to_dict(timestamp_ns: int | None, packet: Any, inventory: Inventory | None = None) -> dict[str, Any]:
    inventory = inventory or Inventory()
    return {
        "timestamp_ns": timestamp_ns,
        "parsed": True,
        "wrapper": packet.wrapper,
        "flow_key": packet.flow_key.__dict__ if packet.flow_key else None,
        "ifa_header": packet.ifa_header.__dict__,
        "metadata_header": packet.metadata_header.__dict__,
        "checksum_header": packet.checksum_header.__dict__ if packet.checksum_header else None,
        "fragment_header": packet.fragment_header.__dict__ if packet.fragment_header else None,
        "hop_count": len(packet.hops),
        "metadata_path": [hop.fields.get("device_id") for hop in packet.hops],
        "traffic_path": [hop.fields.get("device_id") for hop in reversed(packet.hops)],
        "resolved_metadata_path": inventory.resolve_hops(packet.hops),
        "resolved_traffic_path": inventory.resolve_hops(packet.hops, traffic_order=True),
        "hops": [
            {
                "schema_id": hop.schema_id,
                "raw_hex": hop.raw.hex(),
                "fields": hop.fields,
            }
            for hop in packet.hops
        ],
        "post_metadata_payload_len": len(packet.post_metadata_payload),
        "post_metadata_payload_hex": packet.post_metadata_payload[:96].hex(),
        "errors": packet.errors,
    }


def _summary_to_dict(
    parsed_records: int,
    errors: dict[str, int],
    hop_paths: dict[str, int],
    traffic_paths: dict[str, int],
    resolved_traffic_paths: dict[str, int],
    flows: dict[str, int],
    sequences: dict[str, list[int]],
) -> dict[str, Any]:
    sequence_summary = {}
    for key, values in sequences.items():
        sequence_gaps = 0
        duplicate_or_reordered = 0
        for previous, current in zip(values, values[1:]):
            if current == previous + 1:
                continue
            if current <= previous:
                duplicate_or_reordered += 1
            else:
                sequence_gaps += current - previous - 1
        sequence_summary[key] = {
            "first": values[0] if values else None,
            "last": values[-1] if values else None,
            "gaps": sequence_gaps,
            "duplicate_or_reordered": duplicate_or_reordered,
            "records": len(values),
        }

    return {
        "parsed_ifa_records": parsed_records,
        "ipfix_sequences": sequence_summary,
        "metadata_order_paths": hop_paths,
        "traffic_order_paths": traffic_paths,
        "resolved_traffic_paths": resolved_traffic_paths,
        "flows": flows,
        "non_ifa_or_parse_errors": errors,
    }


def _exporter_key(wrapper: dict[str, Any]) -> str:
    transport = wrapper.get("transport") or {}
    src = transport.get("src_ip", "?")
    sport = transport.get("src_port", "?")
    dst = transport.get("dst_ip", "?")
    dport = transport.get("dst_port", "?")
    odid = wrapper.get("observation_domain_id", "?")
    return f"{src}:{sport}->{dst}:{dport}/odid={odid}"


def _emit(payload: dict[str, Any], pretty: bool) -> None:
    print(json.dumps(payload, indent=2 if pretty else None, sort_keys=True))


def _device_specs(args: Any) -> list[RestconfDevice]:
    devices = []
    for spec in args.device:
        parts = [part.strip() for part in spec.split(",", 2)]
        if len(parts) != 3 or not all(parts):
            raise ValueError("--device must be host,username,password")
        devices.append(
            RestconfDevice(
                host=parts[0],
                auth=RestconfAuth(
                    username=parts[1],
                    password=parts[2],
                    port=args.rest_port,
                    path_prefix=args.path_prefix,
                    verify_tls=args.verify_tls,
                    timeout=args.timeout,
                ),
            )
        )
    return devices


def _resolved_path_key(hops: list[Any], inventory: Inventory) -> str:
    resolved = inventory.resolve_hops(hops, traffic_order=True)
    labels = []
    for hop in resolved:
        name = hop["device_name"] or str(hop["device_id"])
        ingress = hop["ingress"]["interface"] or hop["ingress"]["logical_port"]
        egress = hop["egress"]["interface"] or hop["egress"]["logical_port"]
        labels.append(f"{name}({ingress}->{egress})")
    return " -> ".join(labels)


if __name__ == "__main__":
    main()
