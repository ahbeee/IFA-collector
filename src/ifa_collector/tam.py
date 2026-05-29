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


def preview_tam_plan(spec: dict[str, Any]) -> dict[str, Any]:
    operations = _build_delete_operations(spec) + _build_set_operations(spec)
    warnings = _validate_operations(spec)
    return {"operations": operations, "warnings": warnings, "summary": {"operations": len(operations), "warnings": len(warnings)}}


def apply_tam_plan(devices: list[RestconfDevice], spec: dict[str, Any]) -> dict[str, Any]:
    plan = preview_tam_plan(spec)
    results = []
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
        for op in plan["operations"]:
            item = {"host": device.host, "method": op["method"], "path": op["path"], "description": op["description"]}
            try:
                if op["method"] == "PATCH":
                    client.patch_json(op["path"], op["payload"])
                elif op["method"] == "DELETE":
                    client.delete(op["path"])
                else:
                    raise ValueError(f"unsupported method {op['method']}")
                item["status"] = "ok"
            except Exception as exc:
                item["status"] = "error"
                item["error"] = str(exc)
            results.append(item)
            if item["status"] == "error" and not spec.get("continue_on_error", False):
                break
    errors = [item for item in results if item.get("status") == "error"]
    return {"plan": plan, "results": results, "summary": {"requests": len(results), "errors": len(errors)}}


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


def _build_delete_operations(spec: dict[str, Any]) -> list[dict[str, Any]]:
    deletes = spec.get("delete", {})
    ops = []
    for name in deletes.get("sessions", []):
        ops.append(_delete_op(f"openconfig-tam:tam/ifa-sessions/ifa-session={name}", f"delete IFA session {name}"))
    for name in deletes.get("collectors", []):
        ops.append(_delete_op(f"openconfig-tam:tam/collectors/collector={name}", f"delete collector {name}"))
    for name in deletes.get("samplers", []):
        ops.append(_delete_op(f"openconfig-tam:tam/samplers/sampler={name}", f"delete sampler {name}"))
    for name in deletes.get("flowgroups", []):
        ops.append(_delete_op(f"openconfig-tam:tam/flowgroups/flowgroup={name}", f"delete flowgroup {name}"))
    if deletes.get("switch_id"):
        ops.append(_delete_op("openconfig-tam:tam/switch/config/switch-id", "delete switch-id"))
    if deletes.get("enterprise_id"):
        ops.append(_delete_op("openconfig-tam:tam/switch/config/enterprise-id", "delete enterprise-id"))
    return ops


def _build_set_operations(spec: dict[str, Any]) -> list[dict[str, Any]]:
    ops = []
    switch = spec.get("switch", {})
    if "switch_id" in switch:
        ops.append(_patch_op("openconfig-tam:tam/switch/config/switch-id", {"openconfig-tam:switch-id": int(switch["switch_id"])}, "set switch-id"))
    if "enterprise_id" in switch:
        ops.append(_patch_op("openconfig-tam:tam/switch/config/enterprise-id", {"openconfig-tam:enterprise-id": int(switch["enterprise_id"])}, "set enterprise-id"))
    for collector in spec.get("collectors", []):
        ops.append(
            _patch_op(
                "openconfig-tam:tam/collectors",
                collector_payload(
                    collector["name"],
                    collector["ip"],
                    int(collector["port"]),
                    collector.get("protocol", "UDP"),
                    collector.get("vrf"),
                ),
                f"set collector {collector['name']}",
            )
        )
    for sampler in spec.get("samplers", []):
        ops.append(_patch_op("openconfig-tam:tam/samplers", sampler_payload(sampler["name"], int(sampler["sampling_rate"])), f"set sampler {sampler['name']}"))
    for flowgroup in spec.get("flowgroups", []):
        ops.append(_patch_op("openconfig-tam:tam/flowgroups", flowgroup_payload(**flowgroup), f"set flowgroup {flowgroup['name']}"))
    for session in spec.get("sessions", []):
        ops.append(
            _patch_op(
                "openconfig-tam:tam/ifa-sessions",
                ifa_session_payload(
                    session["name"],
                    session["flowgroup"],
                    session["node_type"],
                    collector=session.get("collector"),
                    sampler=session.get("sampler"),
                ),
                f"set IFA session {session['name']}",
            )
        )
    if "ifa_status" in spec:
        ops.append(_patch_op("openconfig-tam:tam/features", ifa_feature_payload(str(spec["ifa_status"])), f"set IFA {spec['ifa_status']}"))
    return ops


def _validate_operations(spec: dict[str, Any]) -> list[str]:
    warnings = []
    sessions = spec.get("sessions", [])
    flowgroups = [session.get("flowgroup") for session in sessions]
    if len(flowgroups) != len(set(flowgroups)):
        warnings.append("One flowgroup cannot be used by multiple IFA sessions on the tested SONiC build.")
    collectors = {session.get("collector") for session in sessions if session.get("collector")}
    if len(collectors) > 1:
        warnings.append("Only one collector can be used by active IFA sessions on the tested SONiC build.")
    for session in sessions:
        node_type = str(session.get("node_type", "")).upper()
        if node_type == "INGRESS" and not session.get("sampler"):
            warnings.append(f"Ingress session {session.get('name')} needs a sampler.")
        if node_type == "EGRESS" and not session.get("collector"):
            warnings.append(f"Egress session {session.get('name')} needs a collector.")
    return warnings


def _patch_op(path: str, payload: dict[str, Any], description: str) -> dict[str, Any]:
    return {"method": "PATCH", "path": path, "payload": payload, "description": description}


def _delete_op(path: str, description: str) -> dict[str, Any]:
    return {"method": "DELETE", "path": path, "payload": None, "description": description}


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
        ipv6 = _state(item.get("ipv6", {}))
        l2 = _state(item.get("l2", {}))
        transport = _state(item.get("transport", {}))
        stats = state.get("statistics", {})
        rows.append(
            {
                "name": state.get("name") or item.get("name"),
                "id": state.get("id"),
                "priority": state.get("priority"),
                "src_ip": ipv4.get("source-address"),
                "dst_ip": ipv4.get("destination-address"),
                "src_ipv6": ipv6.get("source-address"),
                "dst_ipv6": ipv6.get("destination-address"),
                "protocol": _short_enum(ipv4.get("protocol")),
                "src_mac": l2.get("source-mac"),
                "dst_mac": l2.get("destination-mac"),
                "vlan": l2.get("vlan"),
                "ethertype": _short_enum(l2.get("ethertype")),
                "l4_src_port": transport.get("source-port"),
                "l4_dst_port": transport.get("destination-port"),
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
    flowgroup_id: int | None = None,
    priority: int = 100,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    src_ipv6: str | None = None,
    dst_ipv6: str | None = None,
    src_mac: str | None = None,
    dst_mac: str | None = None,
    l4_src_port: int | None = None,
    l4_dst_port: int | None = None,
    vlan: int | None = None,
    ethertype: str | None = None,
    id: int | None = None,
) -> dict[str, Any]:
    resolved_id = flowgroup_id if flowgroup_id is not None else id
    if resolved_id is None:
        raise ValueError("flowgroup id is required")
    flowgroup: dict[str, Any] = {
        "name": name,
        "config": {"name": name, "id": int(resolved_id), "priority": int(priority)},
    }
    if src_ip or dst_ip or protocol:
        flowgroup["ipv4"] = {
            "config": _without_none(
                {
                    "source-address": src_ip,
                    "destination-address": dst_ip,
                    "protocol": f"IP_{protocol.upper()}" if protocol else None,
                }
            )
        }
    if src_ipv6 or dst_ipv6:
        flowgroup["ipv6"] = {
            "config": _without_none({"source-address": src_ipv6, "destination-address": dst_ipv6})
        }
    if src_mac or dst_mac or vlan is not None or ethertype:
        flowgroup["l2"] = {
            "config": _without_none(
                {
                    "source-mac": src_mac.upper() if src_mac else None,
                    "destination-mac": dst_mac.upper() if dst_mac else None,
                    "vlan": int(vlan) if vlan is not None else None,
                    "ethertype": _ethertype_value(ethertype) if ethertype else None,
                }
            )
        }
    if l4_src_port is not None or l4_dst_port is not None:
        flowgroup["transport"] = {
            "config": _without_none(
                {
                    "source-port": int(l4_src_port) if l4_src_port is not None else None,
                    "destination-port": int(l4_dst_port) if l4_dst_port is not None else None,
                }
            )
        }
    return {
        "openconfig-tam:flowgroups": {
            "flowgroup": [flowgroup]
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
    return str(value).split(":")[-1].replace("IP_", "").replace("ETHERTYPE_", "")


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _without_none(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _ethertype_value(value: str) -> str:
    normalized = value.strip().upper()
    aliases = {
        "ARP": "ETHERTYPE_ARP",
        "IP": "ETHERTYPE_IPV4",
        "IPV4": "ETHERTYPE_IPV4",
        "IPV6": "ETHERTYPE_IPV6",
        "LLDP": "ETHERTYPE_LLDP",
        "MPLS": "ETHERTYPE_MPLS",
        "ROCE": "ETHERTYPE_ROCE",
        "VLAN": "ETHERTYPE_VLAN",
    }
    return aliases.get(normalized, normalized)
