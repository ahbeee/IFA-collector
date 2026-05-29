from __future__ import annotations

from typing import Any

from .restconf import RestconfClient
from .topology import RestconfDevice


TAM_PATHS = {
    "ifa_status": "openconfig-tam:tam/features-state/feature-state=IFA/state/op-status",
    "features": "openconfig-tam:tam/features-state/feature-state",
    "switch": "openconfig-tam:tam/switch",
    "collectors": "openconfig-tam:tam/collectors",
    "flowgroups": "openconfig-tam:tam/flowgroups",
    "ifa_sessions": "openconfig-tam:tam/ifa-sessions",
}


def read_tam_devices(devices: list[RestconfDevice]) -> dict[str, Any]:
    results = []
    errors = []
    for device in devices:
        client = RestconfClient(
            host=device.host,
            username=device.auth.username,
            password=device.auth.password,
            port=device.auth.port,
            path_prefix=device.auth.path_prefix,
            verify_tls=device.auth.verify_tls,
            timeout=device.auth.timeout,
        )
        try:
            payloads = {name: client.get_json(path) for name, path in TAM_PATHS.items()}
        except Exception as exc:
            errors.append({"host": device.host, "error": str(exc)})
            continue
        results.append(_normalize_device(device.host, payloads))
    return {"devices": results, "errors": errors, "summary": {"devices": len(results), "errors": len(errors)}}


def _normalize_device(host: str, payloads: dict[str, dict[str, Any]]) -> dict[str, Any]:
    switch_state = _state(payloads["switch"].get("openconfig-tam:switch", {}))
    return {
        "host": host,
        "switch_id": switch_state.get("switch-id"),
        "enterprise_id": switch_state.get("enterprise-id"),
        "ifa_status": payloads["ifa_status"].get("openconfig-tam:op-status"),
        "features": _features(payloads["features"]),
        "collectors": _collectors(payloads["collectors"]),
        "flowgroups": _flowgroups(payloads["flowgroups"]),
        "ifa_sessions": _ifa_sessions(payloads["ifa_sessions"]),
    }


def _state(item: dict[str, Any]) -> dict[str, Any]:
    return item.get("state") or item.get("config") or {}


def _features(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items = _list(payload, "openconfig-tam:feature-state")
    rows = []
    for item in items:
        state = _state(item)
        rows.append(
            {
                "feature": _short_enum(state.get("feature-ref") or item.get("feature-ref")),
                "status": state.get("op-status"),
            }
        )
    return rows


def _collectors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    root = payload.get("openconfig-tam:collectors", {})
    rows = []
    for item in _list(root, "collector"):
        state = _state(item)
        rows.append(
            {
                "name": state.get("name") or item.get("name"),
                "ip": state.get("ip"),
                "port": state.get("port"),
                "protocol": state.get("protocol"),
            }
        )
    return rows


def _flowgroups(payload: dict[str, Any]) -> list[dict[str, Any]]:
    root = payload.get("openconfig-tam:flowgroups", {})
    rows = []
    for item in _list(root, "flowgroup"):
        state = _state(item)
        ipv4 = _state(item.get("ipv4", {}))
        stats = state.get("statistics", {})
        rows.append(
            {
                "name": state.get("name") or item.get("name"),
                "id": state.get("id"),
                "priority": state.get("priority"),
                "src_ip": ipv4.get("source-address"),
                "dst_ip": ipv4.get("destination-address"),
                "protocol": _short_enum(ipv4.get("protocol")),
                "packets": _to_int(stats.get("packets")),
                "bytes": _to_int(stats.get("bytes")),
            }
        )
    return rows


def _ifa_sessions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    root = payload.get("openconfig-tam:ifa-sessions", {})
    rows = []
    for item in _list(root, "ifa-session"):
        state = _state(item)
        rows.append(
            {
                "name": state.get("name") or item.get("name"),
                "flowgroup": state.get("flowgroup"),
                "collector": state.get("collector"),
                "sampler": state.get("sample-rate"),
                "node_type": state.get("node-type"),
            }
        )
    return rows


def _list(root: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(root, dict):
        return []
    items = root.get(key, [])
    return items if isinstance(items, list) else []


def _short_enum(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).split(":")[-1].replace("IP_", "")


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
