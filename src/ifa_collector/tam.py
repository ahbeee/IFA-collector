from __future__ import annotations

from typing import Any

from .restconf import RestconfClient
from .topology import RestconfDevice


TAM_PATHS = {
    "ifa_status": "openconfig-tam:tam/features-state/feature-state=IFA/state/op-status",
    "features": "openconfig-tam:tam/features-state/feature-state",
    "switch": "openconfig-tam:tam/switch",
    "collectors": "openconfig-tam:tam/collectors",
    "samplers": "openconfig-tam:tam/samplers",
    "flowgroups": "openconfig-tam:tam/flowgroups",
    "ifa_sessions": "openconfig-tam:tam/ifa-sessions",
    "vrfs": "sonic-vrf:sonic-vrf/VRF/VRF_LIST",
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
        "samplers": _samplers(payloads["samplers"]),
        "flowgroups": _flowgroups(payloads["flowgroups"]),
        "ifa_sessions": _ifa_sessions(payloads["ifa_sessions"]),
        "vrfs": _vrfs(payloads["vrfs"]),
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
                "vrf": state.get("vrf"),
            }
        )
    return rows


def _samplers(payload: dict[str, Any]) -> list[dict[str, Any]]:
    root = payload.get("openconfig-tam:samplers", {})
    rows = []
    for item in _list(root, "sampler"):
        state = _state(item)
        rows.append(
            {
                "name": state.get("name") or item.get("name"),
                "sampling_rate": state.get("sampling-rate"),
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


def _vrfs(payload: dict[str, Any]) -> list[str]:
    rows = []
    for item in _list(payload, "sonic-vrf:VRF_LIST"):
        name = item.get("vrf_name")
        if name:
            rows.append(str(name))
    return rows


def collector_payload(name: str, ip: str, port: int, protocol: str, vrf: str | None = None) -> dict[str, Any]:
    config: dict[str, Any] = {"name": name, "ip": ip, "port": int(port), "protocol": protocol.upper()}
    if vrf:
        config["vrf"] = vrf
    return {"openconfig-tam:collectors": {"collector": [{"name": name, "config": config}]}}


def sampler_payload(name: str, sampling_rate: int) -> dict[str, Any]:
    return {
        "openconfig-tam:samplers": {
            "sampler": [{"name": name, "config": {"name": name, "sampling-rate": int(sampling_rate)}}]
        }
    }


def flowgroup_payload(
    name: str,
    flowgroup_id: int,
    priority: int,
    src_ip: str,
    dst_ip: str,
    protocol: str,
) -> dict[str, Any]:
    return {
        "openconfig-tam:flowgroups": {
            "flowgroup": [
                {
                    "name": name,
                    "config": {"name": name, "id": int(flowgroup_id), "priority": int(priority)},
                    "ipv4": {
                        "config": {
                            "source-address": src_ip,
                            "destination-address": dst_ip,
                            "protocol": f"IP_{protocol.upper()}",
                        }
                    },
                }
            ]
        }
    }


def ifa_session_payload(
    name: str,
    flowgroup: str,
    node_type: str,
    collector: str | None = None,
    sampler: str | None = None,
) -> dict[str, Any]:
    config = {"name": name, "flowgroup": flowgroup, "node-type": node_type.upper()}
    if collector:
        config["collector"] = collector
    if sampler:
        config["sample-rate"] = sampler
    return {"openconfig-tam:ifa-sessions": {"ifa-session": [{"name": name, "config": config}]}}


def ifa_feature_payload(status: str) -> dict[str, Any]:
    status = status.upper()
    return {
        "openconfig-tam:features": {
            "feature": [{"feature-ref": "IFA", "config": {"feature-ref": "IFA", "status": status}}]
        }
    }


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
