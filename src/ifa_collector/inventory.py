from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import HopMetadata


@dataclass(frozen=True)
class PortInfo:
    logical_port: int
    interface: str | None = None
    front_panel: str | None = None
    speed: str | None = None
    peer_device_id: int | None = None
    peer_port: int | None = None
    peer_name: str | None = None


@dataclass(frozen=True)
class DeviceInfo:
    device_id: int
    name: str
    model: str | None = None
    role: str | None = None
    loopback_ip: str | None = None
    ports: dict[int, PortInfo] = field(default_factory=dict)


class Inventory:
    def __init__(self, devices: dict[int, DeviceInfo] | None = None):
        self.devices = devices or {}

    @classmethod
    def load(cls, path: Path | None) -> "Inventory":
        if path is None:
            return cls()
        with path.open("r", encoding="utf-8") as handle:
            doc = json.load(handle)

        devices = {}
        for key, value in doc.get("devices", {}).items():
            device_id = int(key)
            ports = {}
            for port_key, port_value in value.get("ports", {}).items():
                logical_port = int(port_key)
                ports[logical_port] = PortInfo(
                    logical_port=logical_port,
                    interface=port_value.get("interface"),
                    front_panel=port_value.get("front_panel"),
                    speed=port_value.get("speed"),
                    peer_device_id=int(port_value["peer_device_id"]) if port_value.get("peer_device_id") is not None else None,
                    peer_port=int(port_value["peer_port"]) if port_value.get("peer_port") is not None else None,
                    peer_name=port_value.get("peer_name"),
                )
            devices[device_id] = DeviceInfo(
                device_id=device_id,
                name=value.get("name", str(device_id)),
                model=value.get("model"),
                role=value.get("role"),
                loopback_ip=value.get("loopback_ip"),
                ports=ports,
            )
        return cls(devices)

    def update_from_topology(self, topology: dict[str, Any]) -> None:
        for node in topology.get("graph", {}).get("nodes", []):
            if not isinstance(node, dict):
                continue
            metadata = dict(node.get("metadata") or {})
            if not metadata:
                continue
            metadata.setdefault("hostname", node.get("id"))
            self.upsert_device_metadata(metadata)

    def update_from_tam_devices(self, devices: list[dict[str, Any]]) -> None:
        for device in devices:
            self.upsert_device_metadata(device)

    def upsert_device_metadata(self, metadata: dict[str, Any]) -> None:
        device_id = _int_or_none(metadata.get("switch_id"))
        if device_id is None:
            return
        existing = self.devices.get(device_id)
        ports = dict(existing.ports) if existing else {}
        for interface in (metadata.get("interfaces") or {}).values():
            for logical_port in _logical_ports(interface):
                ports[logical_port] = PortInfo(
                    logical_port=logical_port,
                    interface=interface.get("name"),
                    front_panel=interface.get("alias"),
                    speed=_format_speed(interface.get("speed")),
                    peer_device_id=ports.get(logical_port).peer_device_id if logical_port in ports else None,
                    peer_port=ports.get(logical_port).peer_port if logical_port in ports else None,
                    peer_name=ports.get(logical_port).peer_name if logical_port in ports else None,
                )
        self.devices[device_id] = DeviceInfo(
            device_id=device_id,
            name=metadata.get("hostname") or (existing.name if existing else str(device_id)),
            model=metadata.get("product_name") or metadata.get("platform") or (existing.model if existing else None),
            role=existing.role if existing else None,
            loopback_ip=existing.loopback_ip if existing else None,
            ports=ports,
        )

    def stats(self) -> dict[str, int]:
        return {
            "devices": len(self.devices),
            "logical_ports": sum(len(device.ports) for device in self.devices.values()),
        }

    def resolve_hops(self, hops: list[HopMetadata], traffic_order: bool = False) -> list[dict[str, Any]]:
        ordered = list(reversed(hops)) if traffic_order else hops
        return [self.resolve_hop(hop) for hop in ordered]

    def resolve_hop(self, hop: HopMetadata) -> dict[str, Any]:
        device_id = _int_or_none(hop.fields.get("device_id"))
        ingress_port = _int_or_none(
            hop.fields.get("ingress_logical_port", hop.fields.get("inferred_ingress_port_id"))
        )
        egress_port = _int_or_none(
            hop.fields.get("egress_logical_port", hop.fields.get("inferred_egress_port_id"))
        )
        device = self.devices.get(device_id) if device_id is not None else None

        return {
            "device_id": device_id,
            "device_name": device.name if device else None,
            "model": device.model if device else None,
            "role": device.role if device else None,
            "ingress": _resolve_port(device, ingress_port),
            "egress": _resolve_port(device, egress_port),
        }


def _resolve_port(device: DeviceInfo | None, logical_port: int | None) -> dict[str, Any]:
    port = device.ports.get(logical_port) if device and logical_port is not None else None
    return {
        "logical_port": logical_port,
        "interface": port.interface if port else None,
        "front_panel": port.front_panel if port else None,
        "speed": port.speed if port else None,
        "peer_device_id": port.peer_device_id if port else None,
        "peer_port": port.peer_port if port else None,
        "peer_name": port.peer_name if port else None,
    }


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _logical_ports(interface: dict[str, Any]) -> list[int]:
    ports = []
    for value in str(interface.get("lanes") or "").split(","):
        port = _int_or_none(value.strip())
        if port is not None:
            ports.append(port)
    return ports


def _format_speed(value: Any) -> str | None:
    speed = _int_or_none(value)
    if speed is None:
        return str(value) if value else None
    if speed >= 1000 and speed % 1000 == 0:
        return f"{speed // 1000}G"
    return f"{speed}M"
