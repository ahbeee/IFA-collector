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
        except Exception as exc:
            errors.append({"host": host, "error": str(exc)})
            continue

        device_name = _hostname(system) or host
        _add_node(graph, device_name, host)
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
        return {"graph": {"nodes": [], "links": []}, "interfaces": {}, "neighborships": {}, "errors": [], "summary": {}}
    return json.loads(path.read_text(encoding="utf-8"))


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
    return _first(system_payload.get("openconfig-system:state", {}).get("hostname"))


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
                "speed": _first(item.get("speed"), item.get("speed_bps"), "0"),
                "admin_status": _first(item.get("admin_status"), "unknown"),
                "oper_status": _first(item.get("oper_status"), "unknown"),
                "mac": _first(item.get("mac"), item.get("mac_address")),
            }
        )
    for item in _list_by_suffix(lag_payload.get("sonic-portchannel:LAG_TABLE"), "LAG_TABLE_LIST"):
        name = _first(item.get("lagname"), item.get("ifname"), item.get("name"))
        if name:
            rows.append({"name": name, "speed": _first(item.get("speed"), "0"), "admin_status": _first(item.get("admin_status"), "unknown"), "oper_status": _first(item.get("oper_status"), "unknown")})
    return rows


def _speed_for(rows: list[dict[str, Any]], interface: str) -> str:
    for row in rows:
        if row["name"] == interface:
            try:
                speed = int(float(row.get("speed") or 0))
            except ValueError:
                return "1"
            return str(max(1, int(speed / 1000))) if speed >= 1000 else "1"
    return "1"


def _add_node(graph: dict[str, Any], node_id: str, ip: str | None) -> None:
    for node in graph["nodes"]:
        if node["id"] == node_id:
            if ip and not node.get("ip"):
                node["ip"] = ip
                node["label"] = f"{node_id} ({ip})"
            return
    label = f"{node_id} ({ip})" if ip else node_id
    graph["nodes"].append({"id": node_id, "label": label, "ip": ip})


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
