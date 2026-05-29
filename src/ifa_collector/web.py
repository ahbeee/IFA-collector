from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .query import QueryStore
from .topology import RestconfAuth, RestconfDevice, load_topology, scan_topology, scan_topology_devices


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IFA Collector</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #64748b;
      --line: #d7dde5;
      --accent: #0f766e;
      --accent-soft: #e7f5f2;
      --warn: #b45309;
      --bad: #b91c1c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
    }
    header {
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      background: #113b45;
      color: white;
    }
    header h1 { font-size: 18px; margin: 0; font-weight: 600; letter-spacing: 0; }
    main { padding: 20px 24px 32px; max-width: 1500px; margin: 0 auto; }
    .tabs { display: flex; gap: 8px; margin-bottom: 16px; }
    .tabs button {
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      padding: 8px 12px;
      cursor: pointer;
      border-radius: 6px;
    }
    .tabs button.active { background: var(--accent); color: white; border-color: var(--accent); }
    section { display: none; }
    section.active { display: block; }
    .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }
    .metric .label { color: var(--muted); font-size: 12px; }
    .metric .value { font-size: 24px; font-weight: 650; margin-top: 6px; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 16px;
    }
    .panel h2 {
      font-size: 15px;
      margin: 0;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfd;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: 600; background: #fbfcfd; font-size: 12px; }
    tr:last-child td { border-bottom: 0; }
    code { font-family: Consolas, monospace; font-size: 12px; }
    .path { line-height: 1.6; }
    .pill { display: inline-block; padding: 2px 7px; border-radius: 999px; background: #e7f5f2; color: #0f766e; }
    .bad { color: var(--bad); font-weight: 600; }
    .warn { color: var(--warn); font-weight: 600; }
    .clickable { cursor: pointer; }
    .clickable:hover { background: #f8fafc; }
    .detail { padding: 12px 14px; }
    .hopline { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 8px 0; }
    .hop {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #fbfcfd;
      min-width: 220px;
    }
    .arrow { color: var(--muted); }
    .toolbar {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) 140px 140px 92px 92px;
      gap: 8px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      align-items: end;
    }
    label { display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    input {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 9px;
      font: inherit;
      background: white;
    }
    textarea {
      width: 100%;
      min-height: 70px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 9px;
      font: 12px Consolas, monospace;
      resize: vertical;
    }
    .primary {
      border: 1px solid var(--accent);
      background: var(--accent);
      color: white;
      border-radius: 6px;
      padding: 8px 12px;
      cursor: pointer;
      height: 36px;
    }
    .secondary {
      border: 1px solid var(--line);
      background: white;
      color: var(--text);
      border-radius: 6px;
      padding: 8px 12px;
      cursor: pointer;
      height: 36px;
    }
    .topology {
      min-height: 480px;
      padding: 12px 14px 16px;
    }
    .topology svg {
      width: 100%;
      height: 460px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfd;
    }
    .topology-line { stroke: #94a3b8; stroke-width: 2; }
    .topology-node { fill: var(--accent-soft); stroke: var(--accent); stroke-width: 2; }
    .topology-label { font-size: 12px; fill: var(--text); text-anchor: middle; }
    .topology-edge-label { font-size: 11px; fill: var(--muted); text-anchor: middle; }
    .status { padding: 0 14px 12px; color: var(--muted); }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
      .toolbar { grid-template-columns: 1fr; }
      main { padding: 14px; }
      th, td { padding: 8px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>IFA Collector</h1>
    <div id="dbLabel"></div>
  </header>
  <main>
    <div class="tabs">
      <button data-tab="overview" class="active">Overview</button>
      <button data-tab="flows">Flows</button>
      <button data-tab="paths">Paths</button>
      <button data-tab="topology">Topology</button>
      <button data-tab="errors">Diagnostics</button>
    </div>

    <section id="overview" class="active">
      <div class="grid">
        <div class="metric"><div class="label">Exporters</div><div class="value" id="mExporters">-</div></div>
        <div class="metric"><div class="label">Flows</div><div class="value" id="mFlows">-</div></div>
        <div class="metric"><div class="label">Sequence Gaps</div><div class="value" id="mGaps">-</div></div>
      </div>
      <div class="panel"><h2>Exporters</h2><div id="exportersTable"></div></div>
    </section>

    <section id="flows">
      <div class="panel"><h2>Flows</h2><div id="flowsTable"></div></div>
      <div class="panel"><h2>Flow Detail</h2><div id="flowDetail" class="detail">Select a flow.</div></div>
    </section>

    <section id="paths">
      <div class="panel"><h2>Paths</h2><div id="pathsTable"></div></div>
    </section>

    <section id="topology">
      <div class="panel">
        <h2>Topology</h2>
        <div class="toolbar">
          <div><label for="topoTargets">Targets</label><input id="topoTargets" placeholder="192.168.100.11, 192.168.100.12 or /24"></div>
          <div><label for="topoUser">Username</label><input id="topoUser" autocomplete="username"></div>
          <div><label for="topoPass">Password</label><input id="topoPass" type="password" autocomplete="current-password"></div>
          <button id="topoScan" class="primary">Scan</button>
          <button id="topoReload" class="secondary">Reload</button>
        </div>
        <div style="padding: 0 14px 12px;">
          <label for="topoDevices">Per-device credentials</label>
          <textarea id="topoDevices" placeholder="10.101.110.1,admin,admin&#10;10.101.110.2,admin,admin&#10;10.101.125.2,admin,password"></textarea>
        </div>
        <div id="topologyStatus" class="status"></div>
        <div id="topologyGraph" class="topology"></div>
      </div>
      <div class="panel"><h2>LLDP Links</h2><div id="topologyLinks"></div></div>
    </section>

    <section id="errors">
      <div class="panel"><h2>Parse Errors</h2><div id="errorsTable"></div></div>
    </section>
  </main>
  <script>
    const state = { exporters: [], flows: [], paths: [], errors: [], topology: null };

    async function api(path, options) {
      const res = await fetch(path, options);
      if (!res.ok) throw new Error(await res.text());
      return await res.json();
    }
    function esc(v) {
      return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function table(headers, rows) {
      return `<table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
    }
    function statusClass(row) {
      if (row.gaps || row.duplicate_or_reordered) return 'bad';
      return '';
    }
    async function loadAll() {
      const [exporters, flows, paths, errors, topology] = await Promise.all([
        api('/api/exporters'), api('/api/flows?limit=100'), api('/api/paths?limit=100'), api('/api/errors'), api('/api/topology')
      ]);
      state.exporters = exporters.exporters;
      state.flows = flows.flows;
      state.paths = paths.paths;
      state.errors = errors.errors;
      state.topology = topology;
      render();
    }
    function render() {
      document.getElementById('mExporters').textContent = state.exporters.length;
      document.getElementById('mFlows').textContent = state.flows.length;
      document.getElementById('mGaps').textContent = state.exporters.reduce((a, e) => a + (e.gaps || 0), 0);
      renderExporters();
      renderFlows();
      renderPaths();
      renderTopology();
      renderErrors();
    }
    function renderExporters() {
      const rows = state.exporters.map(e => `<tr>
        <td><code>${esc(e.exporter_key)}</code></td>
        <td>${esc(e.records)}</td>
        <td class="${statusClass(e)}">${esc(e.gaps)}</td>
        <td class="${statusClass(e)}">${esc(e.duplicate_or_reordered)}</td>
        <td>${esc(e.first_sequence)} - ${esc(e.last_sequence)}</td>
      </tr>`);
      document.getElementById('exportersTable').innerHTML = table(['Exporter', 'Records', 'Gaps', 'Dup/Reorder', 'Sequence'], rows);
    }
    function renderFlows() {
      const rows = state.flows.map(f => `<tr class="clickable" onclick="loadFlow(${JSON.stringify(f.flow_key).replace(/"/g, '&quot;')})">
        <td><code>${esc(f.src_ip)}:${esc(f.src_port)} -> ${esc(f.dst_ip)}:${esc(f.dst_port)}</code></td>
        <td>${esc(f.protocol)}</td>
        <td>${esc(f.records)}</td>
        <td><code>${esc(f.flow_key)}</code></td>
      </tr>`);
      document.getElementById('flowsTable').innerHTML = table(['Flow', 'Proto', 'Records', 'Key'], rows);
    }
    function renderPaths() {
      const rows = state.paths.map(p => `<tr>
        <td class="path">${esc(p.resolved_traffic_path)}</td>
        <td><code>${esc(p.traffic_path)}</code></td>
        <td><code>${esc(p.metadata_path)}</code></td>
        <td>${esc(p.records)}</td>
      </tr>`);
      document.getElementById('pathsTable').innerHTML = table(['Resolved Traffic Path', 'Traffic Order', 'Metadata Order', 'Records'], rows);
    }
    function renderErrors() {
      const rows = state.errors.map(e => `<tr><td>${esc(e.error)}</td><td>${esc(e.occurrences)}</td></tr>`);
      document.getElementById('errorsTable').innerHTML = table(['Error', 'Occurrences'], rows);
    }
    function renderTopology() {
      const topo = state.topology || { graph: { nodes: [], links: [] }, summary: {}, errors: [] };
      const nodes = topo.graph?.nodes || [];
      const links = topo.graph?.links || [];
      const status = topo.summary?.nodes === undefined
        ? 'No topology file loaded.'
        : `${topo.summary.nodes || nodes.length} nodes, ${topo.summary.links || links.length} links, ${topo.errors?.length || 0} errors`;
      document.getElementById('topologyStatus').textContent = status;
      if (!nodes.length) {
        document.getElementById('topologyGraph').innerHTML = '<p>No topology data. Run a scan or load a topology file.</p>';
        document.getElementById('topologyLinks').innerHTML = table(['Link', 'Interfaces', 'Speed'], []);
        return;
      }
      const width = 1000, height = 460, cx = width / 2, cy = height / 2;
      const radius = Math.max(120, Math.min(360, 120 + nodes.length * 18));
      const pos = {};
      nodes.forEach((n, i) => {
        const a = (-Math.PI / 2) + (Math.PI * 2 * i / nodes.length);
        pos[n.id] = { x: cx + Math.cos(a) * radius, y: cy + Math.sin(a) * Math.min(radius, 170) };
      });
      const edgeSvg = links.map(l => {
        const s = pos[l.source], t = pos[l.target];
        if (!s || !t) return '';
        const label = `${(l.source_interfaces || []).join(',')} - ${(l.target_interfaces || []).join(',')}`;
        return `<line class="topology-line" x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"><title>${esc(label)}</title></line>
          <text class="topology-edge-label" x="${(s.x + t.x) / 2}" y="${(s.y + t.y) / 2 - 6}">${esc(label)}</text>`;
      }).join('');
      const nodeSvg = nodes.map(n => {
        const p = pos[n.id];
        return `<g><circle class="topology-node" cx="${p.x}" cy="${p.y}" r="34"><title>${esc(n.label || n.id)}</title></circle>
          <text class="topology-label" x="${p.x}" y="${p.y + 4}">${esc(shortLabel(n.id))}</text></g>`;
      }).join('');
      document.getElementById('topologyGraph').innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img">${edgeSvg}${nodeSvg}</svg>`;
      const rows = links.map(l => `<tr><td>${esc(l.source)} -> ${esc(l.target)}</td><td>${esc((l.source_interfaces || []).join(','))} / ${esc((l.target_interfaces || []).join(','))}</td><td>${esc(l.speed)}</td></tr>`);
      document.getElementById('topologyLinks').innerHTML = table(['Link', 'Interfaces', 'Speed'], rows);
    }
    function shortLabel(text) {
      text = String(text || '');
      return text.length > 16 ? text.slice(0, 15) + '...' : text;
    }
    async function scanTopology() {
      const status = document.getElementById('topologyStatus');
      status.textContent = 'Scanning topology...';
      const body = {
        targets: document.getElementById('topoTargets').value,
        username: document.getElementById('topoUser').value,
        password: document.getElementById('topoPass').value,
        devices: parseDeviceSpecs(document.getElementById('topoDevices').value)
      };
      state.topology = await api('/api/topology/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });
      renderTopology();
    }
    function parseDeviceSpecs(text) {
      return String(text || '').split(/\\r?\\n/).map(line => line.trim()).filter(Boolean).map(line => {
        const parts = line.split(',');
        return {host: parts[0]?.trim(), username: parts[1]?.trim(), password: parts.slice(2).join(',').trim()};
      }).filter(item => item.host && item.username && item.password);
    }
    async function loadFlow(flowKey) {
      const data = await api('/api/flow-detail?flow_key=' + encodeURIComponent(flowKey) + '&limit=3');
      const flow = data.flow;
      const records = data.sample_records.map(r => `<div>
        <p><span class="pill">seq ${esc(r.sequence_number)}</span> <code>${esc(r.resolved_traffic_path)}</code></p>
        <div class="hopline">${r.hops.map((h, i) => `<div class="hop">
          <strong>${esc(h.device_name || h.device_id)}</strong><br>
          ingress ${esc(h.ingress_interface || h.ingress_logical_port)} -> egress ${esc(h.egress_interface || h.egress_logical_port)}<br>
          ttl ${esc(h.ttl)}
        </div>${i < r.hops.length - 1 ? '<span class="arrow">-></span>' : ''}`).join('')}</div>
      </div>`).join('');
      document.getElementById('flowDetail').innerHTML = `<p><code>${esc(flow.flow_key)}</code></p>${records}`;
      document.querySelector('[data-tab="flows"]').click();
    }
    document.querySelectorAll('.tabs button').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
      });
    });
    document.getElementById('topoReload').addEventListener('click', async () => {
      state.topology = await api('/api/topology');
      renderTopology();
    });
    document.getElementById('topoScan').addEventListener('click', () => scanTopology().catch(err => {
      document.getElementById('topologyStatus').textContent = err.message || String(err);
    }));
    loadAll().catch(err => { document.body.innerHTML = '<pre>' + esc(err.stack || err) + '</pre>'; });
  </script>
</body>
</html>
"""


def serve(db_path: Path, host: str, port: int, topology_path: Path | None = None) -> None:
    topology_path = topology_path or Path("topology/topology.json")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/":
                    self._send_html(INDEX_HTML)
                elif parsed.path == "/api/exporters":
                    self._send_json({"exporters": _query(db_path).exporters()})
                elif parsed.path == "/api/flows":
                    limit = _limit(parsed.query)
                    self._send_json({"flows": _query(db_path).flows(limit)})
                elif parsed.path == "/api/paths":
                    limit = _limit(parsed.query)
                    self._send_json({"paths": _query(db_path).paths(limit)})
                elif parsed.path == "/api/errors":
                    limit = _limit(parsed.query)
                    self._send_json({"errors": _query(db_path).errors(limit)})
                elif parsed.path == "/api/topology":
                    self._send_json(load_topology(topology_path))
                elif parsed.path == "/api/flow-detail":
                    params = parse_qs(parsed.query)
                    flow_key = unquote(params.get("flow_key", [""])[0])
                    limit = int(params.get("limit", ["10"])[0])
                    self._send_json(_query(db_path).flow_detail(flow_key, limit))
                else:
                    self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            except Exception as exc:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/api/topology/scan":
                    body = self._read_json()
                    if body.get("devices"):
                        self._send_json(scan_topology_devices(_web_device_specs(body), topology_path))
                    else:
                        auth = RestconfAuth(
                            username=str(body.get("username", "")),
                            password=str(body.get("password", "")),
                            port=int(body.get("rest_port", body.get("port", 443))),
                            path_prefix=str(body.get("path_prefix", "/restconf/data")),
                            verify_tls=bool(body.get("verify_tls", False)),
                            timeout=float(body.get("timeout", 10)),
                        )
                        targets = str(body.get("targets", "")).strip()
                        if not targets:
                            self.send_error(HTTPStatus.BAD_REQUEST, "targets is required")
                            return
                        self._send_json(
                            scan_topology(
                                targets,
                                auth,
                                topology_path,
                                ping_first=bool(body.get("ping_first", True)),
                                ping_timeout_ms=int(body.get("ping_timeout_ms", 500)),
                            )
                        )
                else:
                    self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            except Exception as exc:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send_html(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, body: object) -> None:
            data = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Serving IFA UI on http://{host}:{port}/ using {db_path}")
    httpd.serve_forever()


def _query(db_path: Path) -> QueryStore:
    return QueryStore(db_path)


def _limit(query: str) -> int:
    params = parse_qs(query)
    return int(params.get("limit", ["100"])[0])


def _web_device_specs(body: dict[str, object]) -> list[RestconfDevice]:
    devices = []
    for item in body.get("devices", []):
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).strip()
        username = str(item.get("username", "")).strip()
        password = str(item.get("password", ""))
        if not host or not username or not password:
            continue
        devices.append(
            RestconfDevice(
                host=host,
                auth=RestconfAuth(
                    username=username,
                    password=password,
                    port=int(body.get("rest_port", body.get("port", 443))),
                    path_prefix=str(body.get("path_prefix", "/restconf/data")),
                    verify_tls=bool(body.get("verify_tls", False)),
                    timeout=float(body.get("timeout", 10)),
                ),
            )
        )
    if not devices:
        raise ValueError("devices must contain host, username, and password")
    return devices
