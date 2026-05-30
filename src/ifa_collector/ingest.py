from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ifa import parse_ifa_from_frame, parse_ifa_payload
from .inventory import Inventory
from .ipfix import is_ipfix_message, parse_ipfix_message
from .packet import decode_packet
from .pcap import read_pcap
from .schema import SchemaRegistry
from .storage import SqliteStore


@dataclass
class IngestResult:
    parsed_ifa_records: int = 0
    parse_errors: int = 0
    source: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "parsed_ifa_records": self.parsed_ifa_records,
            "parse_errors": self.parse_errors,
        }


@dataclass
class CollectorState:
    running: bool = False
    host: str = "0.0.0.0"
    port: int | None = None
    started_at: float | None = None
    packets: int = 0
    parsed_ifa_records: int = 0
    parse_errors: int = 0
    last_packet_time: float | None = None
    last_error: str | None = None
    last_peer: str | None = None

    def as_dict(self) -> dict[str, Any]:
        now = time.time()
        uptime = (now - self.started_at) if self.started_at else 0.0
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "started_at": self.started_at,
            "uptime_seconds": uptime,
            "packets_per_second": (self.packets / uptime) if uptime > 0 else 0,
            "records_per_second": (self.parsed_ifa_records / uptime) if uptime > 0 else 0,
            "packets": self.packets,
            "parsed_ifa_records": self.parsed_ifa_records,
            "parse_errors": self.parse_errors,
            "last_packet_time": self.last_packet_time,
            "last_error": self.last_error,
            "last_peer": self.last_peer,
        }


def ingest_pcap(
    path: Path,
    db_path: Path,
    registry: SchemaRegistry,
    inventory: Inventory | None = None,
) -> IngestResult:
    inventory = inventory or Inventory()
    result = IngestResult(source=str(path))
    store = SqliteStore(db_path)
    try:
        for record in read_pcap(path, ignore_truncated_tail=True):
            try:
                packets = parse_frame(record.data, registry)
            except ValueError as exc:
                store.insert_error(record.timestamp_ns, str(exc))
                result.parse_errors += 1
                continue
            for packet in packets:
                store.insert_packet(record.timestamp_ns, packet, inventory)
                result.parsed_ifa_records += 1
                if result.parsed_ifa_records % 5000 == 0:
                    store.commit()
        store.commit()
    finally:
        store.close()
    return result


def parse_frame(data: bytes, registry: SchemaRegistry) -> list[Any]:
    cursor = decode_packet(data)
    if is_ipfix_message(cursor.payload):
        return parse_ipfix_ifa(cursor.payload, registry, raw_packet=data, transport=cursor.flow_key.__dict__)
    return [parse_ifa_from_frame(data, registry)]


def parse_udp_payload(data: bytes, registry: SchemaRegistry, peer: tuple[str, int] | None = None) -> list[Any]:
    if is_ipfix_message(data):
        transport = {"src_ip": peer[0], "src_port": peer[1], "dst_ip": None, "dst_port": None} if peer else None
        return parse_ipfix_ifa(data, registry, raw_packet=data, transport=transport)
    return [parse_ifa_payload(data, registry)]


def parse_ipfix_ifa(
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


class UdpIngestCollector:
    def __init__(self, db_path: Path, registry: SchemaRegistry, inventory: Inventory | None = None):
        self.db_path = db_path
        self.registry = registry
        self.inventory = inventory or Inventory()
        self.state = CollectorState()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def start(self, host: str, port: int) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise ValueError("collector is already running")
            self._stop.clear()
            self.state = CollectorState(running=True, host=host, port=port, started_at=time.time())
            self._thread = threading.Thread(target=self._run, name="ifa-udp-collector", daemon=True)
            self._thread.start()
            return self.state.as_dict()

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        sock = self._sock
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._thread
        if thread:
            thread.join(timeout=2)
        with self._lock:
            self.state.running = False
            return self.state.as_dict()

    def status(self) -> dict[str, Any]:
        with self._lock:
            if self._thread and not self._thread.is_alive():
                self.state.running = False
            status = self.state.as_dict()
            status["inventory"] = self.inventory.stats()
            return status

    def _run(self) -> None:
        store = SqliteStore(self.db_path)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        self._sock = sock
        try:
            sock.bind((self.state.host, int(self.state.port or 0)))
            while not self._stop.is_set():
                try:
                    data, peer = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                now_ns = time.time_ns()
                parsed_count = 0
                peer_text = f"{peer[0]}:{peer[1]}"
                try:
                    for packet in parse_udp_payload(data, self.registry, peer=peer):
                        store.insert_packet(now_ns, packet, self.inventory)
                        parsed_count += 1
                    store.commit()
                    with self._lock:
                        self.state.packets += 1
                        self.state.parsed_ifa_records += parsed_count
                        self.state.last_packet_time = time.time()
                        self.state.last_peer = peer_text
                        self.state.last_error = None
                except ValueError as exc:
                    store.insert_error(now_ns, str(exc))
                    store.commit()
                    with self._lock:
                        self.state.packets += 1
                        self.state.parse_errors += 1
                        self.state.last_packet_time = time.time()
                        self.state.last_peer = peer_text
                        self.state.last_error = str(exc)
        except Exception as exc:
            with self._lock:
                self.state.last_error = str(exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            store.close()
            with self._lock:
                self.state.running = False
