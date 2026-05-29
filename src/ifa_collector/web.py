from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .query import QueryStore


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
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
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

    <section id="errors">
      <div class="panel"><h2>Parse Errors</h2><div id="errorsTable"></div></div>
    </section>
  </main>
  <script>
    const state = { exporters: [], flows: [], paths: [], errors: [] };

    async function api(path) {
      const res = await fetch(path);
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
      const [exporters, flows, paths, errors] = await Promise.all([
        api('/api/exporters'), api('/api/flows?limit=100'), api('/api/paths?limit=100'), api('/api/errors')
      ]);
      state.exporters = exporters.exporters;
      state.flows = flows.flows;
      state.paths = paths.paths;
      state.errors = errors.errors;
      render();
    }
    function render() {
      document.getElementById('mExporters').textContent = state.exporters.length;
      document.getElementById('mFlows').textContent = state.flows.length;
      document.getElementById('mGaps').textContent = state.exporters.reduce((a, e) => a + (e.gaps || 0), 0);
      renderExporters();
      renderFlows();
      renderPaths();
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
    loadAll().catch(err => { document.body.innerHTML = '<pre>' + esc(err.stack || err) + '</pre>'; });
  </script>
</body>
</html>
"""


def serve(db_path: Path, host: str, port: int) -> None:
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
                elif parsed.path == "/api/flow-detail":
                    params = parse_qs(parsed.query)
                    flow_key = unquote(params.get("flow_key", [""])[0])
                    limit = int(params.get("limit", ["10"])[0])
                    self._send_json(_query(db_path).flow_detail(flow_key, limit))
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

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Serving IFA UI on http://{host}:{port}/ using {db_path}")
    httpd.serve_forever()


def _query(db_path: Path) -> QueryStore:
    return QueryStore(db_path)


def _limit(query: str) -> int:
    params = parse_qs(query)
    return int(params.get("limit", ["100"])[0])
