from __future__ import annotations

import ipaddress
import json
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .restconf import RestconfClient


DEFAULT_PATHS = {
    "lldp": "openconfig-lldp:lldp/interfaces",
    "ports": "sonic-port:sonic-port/PORT_TABLE",
    "lags": "sonic-portchannel:sonic-portchannel/LAG_TABLE",
    "system": "openconfig-system:system/state",
    "tam_switch": "openconfig-tam:tam/switch",
    "eeprom": "openconfig-platform:components/component=System%20Eeprom",
    "interface_naming": "sonic-device-metadata-state:sonic-device-metadata-state/DEVICE_METADATA_STATE/DEVICE_METADATA_STATE_LIST=localhost/intf_naming_mode",
}


@dataclass(frozen=True)
class RestconfAuth:
    username: str
    password: str
    port: int = 443
    path_prefix: str = "/restconf/data"
    verify_tls: bool = False
    timeout: float = 10


@dataclass(frozen=True)
class RestconfDevice:
    host: str
    auth: RestconfAuth


def parse_targets(text: str) -> list[str]:
    targets = []
    seen = set()
    for token in re.split(r"[,\s]+", text.strip()):
        if not token:
            continue
        if "/" in token:
            for ip in ipaddress.ip_network(token, strict=False).hosts():
                _append_unique(targets, seen, str(ip))
        elif "-" in token:
            start_raw, end_raw = token.split("-", 1)
            start = ipaddress.ip_address(start_raw.strip())
            end = ipaddress.ip_address(end_raw.strip())
            current = start
            while current <= end:
                _append_unique(targets, seen, str(current))
                current += 1
        else:
            _append_unique(targets, seen, str(ipaddress.ip_address(token)))
    return targets


def ping_host(ip: str, timeout_ms: int = 500) -> bool:
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), ip]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def scan_topology(
    targets_text: str,
    auth: RestconfAuth,
    output_path: Path,
    ping_first: bool = True,
    ping_timeout_ms: int = 500,
    paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    paths = paths or DEFAULT_PATHS
    targets = parse_targets(targets_text)
    scan_targets = _live_hosts(targets, ping_timeout_ms) if ping_first else targets
    devices = [RestconfDevice(host=host, auth=auth) for host in scan_targets]
    output = scan_topology_devices(devices, output_path, paths=paths)
    output["summary"]["targets"] = len(targets)
    output["summary"]["scanned"] = len(scan_targets)
    _write_topology(output_path, output)
    return output


def scan_topology_devices(
    devices: list[RestconfDevice],
    output_path: Path,
    paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    paths = paths or DEFAULT_PATHS
    graph = {"nodes": [], "links": []}
    interfaces: dict[str, list[dict[str, Any]]] = {}
    neighborships: dict[str, list[dict[str, str]]] = {}
    errors: list[dict[str, str]] = []

    for device in devices:
        host = device.host
        client = RestconfClient(
            host=host,
            username=device.auth.username,
            password=device.auth.password,
            port=device.auth.port,
            path_prefix=device.auth.path_prefix,
            verify_tls=device.auth.verify_tls,
            timeout=device.auth.timeout,
        )
        try:
            lldp = client.get_json(paths["lldp"])
            ports = client.get_json(paths["ports"])
            lags = client.get_json(paths["lags"])
            system = client.get_json(paths["system"])
            metadata = fetch_device_metadata(client, paths, system=system, ports=ports)
        except Exception as exc:
            errors.append({"host": host, "error": str(exc)})
            continue

        device_name = metadata.get("hostname") or host
        _add_node(graph, device_name, host, metadata)
        interfaces[device_name] = _interface_rows(ports, lags)
        neighborships[device_name] = []

        up_names = {row["name"].lower() for row in interfaces[device_name] if _is_up(row.get("oper_status"))}
        for item in _lldp_interfaces(lldp):
            local_name = _first(item.get("name"), item.get("id"), item.get("state", {}).get("name"))
            if not local_name:
                continue
            if up_names and local_name.lower() not in up_names:
                continue
            for neighbor in _neighbors(item):
                state = neighbor.get("state", {}) if isinstance(neighbor, dict) else {}
                neighbor_name = _first(
                    state.get("system-name"),
                    state.get("system-description"),
                    state.get("chassis-id"),
                    "unknown-neighbor",
                )
                neighbor_port = _first(state.get("port-description"), state.get("port-id"), "unknown-port")
                _add_node(graph, neighbor_name, None)
                _add_link(graph, device_name, neighbor_name, local_name, neighbor_port, _speed_for(interfaces[device_name], local_name))
                neighborships[device_name].append(
                    {"local_interface": local_name, "neighbor": neighbor_name, "neighbor_interface": neighbor_port}
                )

    output = {
        "graph": graph,
        "interfaces": interfaces,
        "neighborships": neighborships,
        "devices": {node["id"]: node.get("metadata", {}) for node in graph["nodes"] if node.get("metadata")},
        "errors": errors,
        "summary": {"targets": len(devices), "scanned": len(devices), "nodes": len(graph["nodes"]), "links": len(graph["links"])},
    }
    _write_topology(output_path, output)
    return output


def scan_topology_target_specs(
    target_specs: list[dict[str, Any]],
    output_path: Path,
    rest_port: int = 443,
    path_prefix: str = "/restconf/data",
    verify_tls: bool = False,
    timeout: float = 10,
    ping_first: bool = True,
    ping_timeout_ms: int = 500,
    paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    devices = []
    target_count = 0
    for item in target_specs:
        targets = parse_targets(str(item.get("targets") or item.get("host") or ""))
        target_count += len(targets)
        scan_targets = _live_hosts(targets, ping_timeout_ms) if ping_first else targets
        auth = RestconfAuth(
            username=str(item.get("username", "")),
            password=str(item.get("password", "")),
            port=int(item.get("rest_port", rest_port)),
            path_prefix=str(item.get("path_prefix", path_prefix)),
            verify_tls=bool(item.get("verify_tls", verify_tls)),
            timeout=float(item.get("timeout", timeout)),
        )
        devices.extend(RestconfDevice(host=host, auth=auth) for host in scan_targets)
    output = scan_topology_devices(devices, output_path, paths=paths)
    output["summary"]["targets"] = target_count
    output["summary"]["scanned"] = len(devices)
    _write_topology(output_path, output)
    return output


def _write_topology(output_path: Path, output: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")


def load_topology(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"graph": {"nodes": [], "links": []}, "interfaces": {}, "neighborships": {}, "devices": {}, "errors": [], "summary": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_device_metadata(
    client: RestconfClient,
    paths: dict[str, str] | None = None,
    system: dict[str, Any] | None = None,
    ports: dict[str, Any] | None = None,
) -> dict[str, Any]:
    paths = paths or DEFAULT_PATHS
    system = system if system is not None else _get_optional(client, paths["system"])
    ports = ports if ports is not None else _get_optional(client, paths["ports"])
    tam_switch = _get_optional(client, paths["tam_switch"])
    eeprom = _get_optional(client, paths["eeprom"])
    interface_naming = _get_optional(client, paths["interface_naming"])
    switch_state = _state(tam_switch.get("openconfig-tam:switch", {}))
    platform_state = _component_state(eeprom)
    return {
        "hostname": _hostname(system),
        "switch_id": switch_state.get("switch-id"),
        "enterprise_id": switch_state.get("enterprise-id"),
        "platform": platform_state.get("description"),
        "product_name": platform_state.get("id"),
        "serial_number": platform_state.get("serial-no"),
        "vendor": platform_state.get("vendor-name"),
        "base_mac": platform_state.get("openconfig-platform-ext:base-mac-address"),
        "software_version": platform_state.get("software-version"),
        "interface_naming_mode": _first(
            interface_naming.get("sonic-device-metadata-state:intf_naming_mode"),
            _system_state(system).get("openconfig-system-deviation:intf-naming-mode"),
        ),
        "interfaces": _interface_map(ports),
    }


def _append_unique(values: list[str], seen: set[str], value: str) -> None:
    if value not in seen:
        seen.add(value)
        values.append(value)


def _live_hosts(targets: list[str], timeout_ms: int) -> list[str]:
    with ThreadPoolExecutor(max_workers=min(128, max(4, len(targets) or 1))) as executor:
        futures = {executor.submit(ping_host, target, timeout_ms): target for target in targets}
        return [futures[future] for future in as_completed(futures) if future.result()]


def _first(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _is_up(value: Any) -> bool:
    return str(value).strip().lower() in {"up", "true", "1"}


def _hostname(system_payload: dict[str, Any]) -> str:
    return _first(_system_state(system_payload).get("hostname"))


def _system_state(system_payload: dict[str, Any]) -> dict[str, Any]:
    return system_payload.get("openconfig-system:state", {}) if isinstance(system_payload, dict) else {}


def _state(item: dict[str, Any]) -> dict[str, Any]:
    return item.get("state") or item.get("config") or {} if isinstance(item, dict) else {}


def _component_state(payload: dict[str, Any]) -> dict[str, Any]:
    components = payload.get("openconfig-platform:component", []) if isinstance(payload, dict) else []
    if not isinstance(components, list):
        return {}
    for component in components:
        if isinstance(component, dict) and component.get("name") == "System Eeprom":
            return _state(component)
    return _state(components[0]) if components else {}


def _get_optional(client: RestconfClient, path: str) -> dict[str, Any]:
    try:
        return client.get_json(path)
    except Exception:
        return {}


def _lldp_interfaces(payload: dict[str, Any]) -> list[dict[str, Any]]:
    root = payload.get("openconfig-lldp:interfaces", {})
    items = root.get("interface", []) if isinstance(root, dict) else []
    return items if isinstance(items, list) else []


def _neighbors(interface: dict[str, Any]) -> list[dict[str, Any]]:
    root = interface.get("neighbors", {})
    items = root.get("neighbor", []) if isinstance(root, dict) else []
    return items if isinstance(items, list) else []


def _list_by_suffix(root: Any, suffix: str) -> list[dict[str, Any]]:
    if not isinstance(root, dict):
        return []
    for key, value in root.items():
        if key.endswith(suffix) and isinstance(value, list):
            return value
    return []


def _interface_rows(port_payload: dict[str, Any], lag_payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in _list_by_suffix(port_payload.get("sonic-port:PORT_TABLE"), "PORT_TABLE_LIST"):
        name = _first(item.get("ifname"), item.get("name"))
        if not name or (not item.get("admin_status") and not item.get("oper_status")):
            continue
        rows.append(
            {
                "name": name,
                "alias": _first(item.get("alias")),
                "ifindex": _ifindex(item),
                "lanes": _first(item.get("lanes")),
                "speed": _first(item.get("speed"), item.get("speed_bps"), "0"),
                "mtu": item.get("mtu"),
                "admin_status": _first(item.get("admin_status"), "unknown"),
                "oper_status": _first(item.get("oper_status"), "unknown"),
                "reason": _first(item.get("reason")),
                "mac": _first(item.get("mac"), item.get("mac_address")),
            }
        )
    for item in _list_by_suffix(lag_payload.get("sonic-portchannel:LAG_TABLE"), "LAG_TABLE_LIST"):
        name = _first(item.get("lagname"), item.get("ifname"), item.get("name"))
        if name:
            rows.append({"name": name, "speed": _first(item.get("speed"), "0"), "admin_status": _first(item.get("admin_status"), "unknown"), "oper_status": _first(item.get("oper_status"), "unknown")})
    return rows


def _interface_map(port_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    interfaces = {}
    for row in _interface_rows(port_payload, {}):
        interfaces[row["name"]] = row
    return interfaces


def _ifindex(item: dict[str, Any]) -> int | None:
    try:
        return int(item["index"]) + 1
    except (KeyError, TypeError, ValueError):
        return None


def _speed_for(rows: list[dict[str, Any]], interface: str) -> str:
    for row in rows:
        if row["name"] == interface:
            try:
                speed = int(float(row.get("speed") or 0))
            except ValueError:
                return "1"
            return str(max(1, int(speed / 1000))) if speed >= 1000 else "1"
    return "1"


def _add_node(graph: dict[str, Any], node_id: str, ip: str | None, metadata: dict[str, Any] | None = None) -> None:
    for node in graph["nodes"]:
        if node["id"] == node_id:
            if ip and not node.get("ip"):
                node["ip"] = ip
                node["label"] = f"{node_id} ({ip})"
            if metadata:
                node["metadata"] = {**node.get("metadata", {}), **metadata}
            return
    label = f"{node_id} ({ip})" if ip else node_id
    node = {"id": node_id, "label": label, "ip": ip}
    if metadata:
        node["metadata"] = metadata
    graph["nodes"].append(node)


def _add_link(graph: dict[str, Any], source: str, target: str, source_interface: str, target_interface: str, speed: str) -> None:
    if source == target:
        return
    for link in graph["links"]:
        if {link["source"], link["target"]} == {source, target}:
            if link["source"] == source:
                _append_list(link, "source_interfaces", source_interface)
                _append_list(link, "target_interfaces", target_interface)
            else:
                _append_list(link, "source_interfaces", target_interface)
                _append_list(link, "target_interfaces", source_interface)
            return
    graph["links"].append(
        {
            "source": source,
            "target": target,
            "speed": speed,
            "source_interfaces": [source_interface],
            "target_interfaces": [target_interface],
        }
    )


def _append_list(item: dict[str, Any], key: str, value: str) -> None:
    if value and value not in item[key]:
        item[key].append(value)
