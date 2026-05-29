from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .query import QueryStore
from .tam import apply_tam_plan, preview_tam_plan, read_tam_devices
from .topology import RestconfAuth, RestconfDevice, load_topology, scan_topology, scan_topology_devices, scan_topology_target_specs


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
      grid-template-columns: minmax(220px, 1fr) 140px 140px 92px;
      gap: 8px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      align-items: end;
    }
    label { display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    input, select {
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
    .topology-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      padding: 12px 14px 0;
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
    .device-list {
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      overflow: hidden;
    }
    .device-list table input {
      padding: 6px 7px;
      font-size: 13px;
    }
    .device-list input[type="checkbox"] { width: auto; }
    .device-list input[type="radio"] { width: auto; }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 8px;
      align-items: end;
      margin-bottom: 12px;
    }
    .form-grid .wide { grid-column: span 2; }
    .form-section {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 12px;
      background: #fbfcfd;
    }
    .form-section h3 {
      margin: 0 0 10px;
      font-size: 13px;
    }
    .table-actions {
      display: flex;
      justify-content: flex-end;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfd;
    }
    .mini {
      border: 1px solid var(--line);
      background: white;
      color: var(--text);
      border-radius: 6px;
      padding: 6px 9px;
      cursor: pointer;
    }
    pre {
      margin: 0;
      padding: 12px 14px;
      white-space: pre-wrap;
      word-break: break-word;
      background: #0f172a;
      color: #e2e8f0;
      font: 12px Consolas, monospace;
      max-height: 420px;
      overflow: auto;
    }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
      .toolbar { grid-template-columns: 1fr; }
      .form-grid { grid-template-columns: 1fr; }
      .form-grid .wide { grid-column: span 1; }
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
      <button data-tab="tam">TAM</button>
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
          <div><label for="topoTargets">Targets</label><input id="topoTargets" placeholder="192.168.100.11, 192.168.100.12"></div>
          <div><label for="topoUser">Username</label><input id="topoUser" autocomplete="username"></div>
          <div><label for="topoPass">Password</label><input id="topoPass" type="password" autocomplete="current-password"></div>
          <button id="topoAdd" class="primary">Add</button>
        </div>
        <div style="padding: 0 14px 12px;">
          <div id="topoDeviceRows" class="device-list"></div>
        </div>
        <div id="topologyStatus" class="status"></div>
        <div class="topology-actions">
          <button id="topoScan" class="primary">Scan</button>
          <button id="topoReload" class="secondary">Reload</button>
          <button id="topoClear" class="secondary">Clear</button>
        </div>
        <div id="topologyGraph" class="topology"></div>
      </div>
      <div class="panel"><h2>LLDP Links</h2><div id="topologyLinks"></div></div>
    </section>

    <section id="tam">
      <div class="panel">
        <h2>TAM / IFA State</h2>
        <div style="padding: 12px 14px;">
          <div class="status" style="padding: 0 0 8px;">Uses the shared device list from Topology. Select one device to read or configure.</div>
          <div id="tamSharedDeviceRows" class="device-list"></div>
          <button id="tamRead" class="primary" style="margin-top: 8px;">Read TAM</button>
        </div>
        <div id="tamStatus" class="status"></div>
      </div>
      <div class="panel"><h2>Switches</h2><div id="tamSwitches"></div></div>
      <div class="panel"><h2>Collectors</h2><div id="tamCollectors"></div></div>
      <div class="panel"><h2>Samplers</h2><div id="tamSamplers"></div></div>
      <div class="panel"><h2>Flow Groups</h2><div id="tamFlowgroups"></div></div>
      <div class="panel"><h2>IFA Sessions</h2><div id="tamSessions"></div></div>
      <div class="panel">
        <h2>Configuration Preview / Apply</h2>
        <div style="padding: 12px 14px;">
          <div class="form-section">
            <h3>Switch</h3>
            <div class="form-grid">
              <div><label for="tamSwitchId">Switch ID</label><input id="tamSwitchId" type="number" placeholder="1001"></div>
              <div><label for="tamEnterpriseId">Enterprise ID</label><input id="tamEnterpriseId" type="number" placeholder="4434"></div>
              <div><label for="tamIfaStatus">IFA Status</label><select id="tamIfaStatus"><option value="">No change</option><option value="ACTIVE">ACTIVE</option><option value="INACTIVE">INACTIVE</option></select></div>
              <button id="tamQueueSwitch" class="secondary">Queue Set</button>
            </div>
            <button id="tamDeleteSwitchId" class="mini">Queue Delete Switch ID</button>
            <button id="tamDeleteEnterpriseId" class="mini">Queue Delete Enterprise ID</button>
          </div>
          <div class="form-section">
            <h3>Add Collector</h3>
            <div class="form-grid">
              <div><label for="tamCollectorName">Name</label><input id="tamCollectorName" placeholder="ifa_collector"></div>
              <div><label for="tamCollectorIp">IP</label><input id="tamCollectorIp" placeholder="192.168.100.100"></div>
              <div><label for="tamCollectorPort">Port</label><input id="tamCollectorPort" type="number" value="9090"></div>
              <div><label for="tamCollectorProtocol">Protocol</label><select id="tamCollectorProtocol"><option>UDP</option><option>TCP</option></select></div>
              <div><label for="tamCollectorVrf">VRF</label><select id="tamCollectorVrf"></select></div>
              <button id="tamAddCollector" class="secondary">Queue Add</button>
            </div>
          </div>
          <div class="form-section">
            <h3>Add Sampler</h3>
            <div class="form-grid">
              <div><label for="tamSamplerName">Name</label><input id="tamSamplerName" placeholder="ifa_samp"></div>
              <div><label for="tamSamplerRate">Sampling Rate</label><input id="tamSamplerRate" type="number" value="1"></div>
              <button id="tamAddSampler" class="secondary">Queue Add</button>
            </div>
          </div>
          <div class="form-section">
            <h3>Add Flow Group</h3>
            <div class="form-grid">
              <div><label for="tamFgName">Name</label><input id="tamFgName" placeholder="s01_to_s02_udp"></div>
              <div><label for="tamFgId">ID</label><input id="tamFgId" type="number" placeholder="30"></div>
              <div><label for="tamFgPriority">Priority</label><input id="tamFgPriority" type="number" value="100"></div>
              <div><label for="tamFgProtocol">Protocol</label><select id="tamFgProtocol"><option value="">Any</option><option>UDP</option><option>TCP</option></select></div>
              <div><label for="tamFgSrcIp">SRC IP</label><input id="tamFgSrcIp" placeholder="1.1.1.1/32"></div>
              <div><label for="tamFgDstIp">DST IP</label><input id="tamFgDstIp" placeholder="4.4.4.4/32"></div>
              <div><label for="tamFgSrcPort">SRC L4 Port</label><input id="tamFgSrcPort" type="number"></div>
              <div><label for="tamFgDstPort">DST L4 Port</label><input id="tamFgDstPort" type="number"></div>
              <button id="tamAddFlowgroup" class="secondary">Queue Add</button>
            </div>
          </div>
          <div class="form-section">
            <h3>Add IFA Session</h3>
            <div class="form-grid">
              <div><label for="tamSessionName">Name</label><input id="tamSessionName" placeholder="ifa_s01_to_s02_UDP"></div>
              <div><label for="tamSessionFlowgroup">Flow Group</label><select id="tamSessionFlowgroup"></select></div>
              <div><label for="tamSessionNodeType">Node Type</label><select id="tamSessionNodeType"><option>INGRESS</option><option>EGRESS</option></select></div>
              <div><label for="tamSessionCollector">Collector</label><select id="tamSessionCollector"></select></div>
              <div><label for="tamSessionSampler">Sampler</label><select id="tamSessionSampler"></select></div>
              <button id="tamAddSession" class="secondary">Queue Add</button>
            </div>
          </div>
          <div class="status" style="padding: 6px 0 0;">Changes are queued locally. Preview builds RESTCONF requests only. Apply sends them to the selected device.</div>
          <button id="tamPreview" class="secondary" style="margin-top: 8px;">Preview</button>
          <button id="tamApply" class="primary" style="margin-top: 8px;">Apply</button>
          <button id="tamClearPending" class="secondary" style="margin-top: 8px;">Clear Pending</button>
        </div>
        <pre id="tamPending">{}</pre>
        <pre id="tamPlan">{}</pre>
      </div>
    </section>

    <section id="errors">
      <div class="panel"><h2>Parse Errors</h2><div id="errorsTable"></div></div>
    </section>
  </main>
  <script>
    const state = { exporters: [], flows: [], paths: [], errors: [], topology: null, tam: null, devices: [], tamDeviceIndex: -1, tamSpec: emptyTamSpec() };

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
      renderTam();
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
        credential_targets: state.devices.map(d => ({targets: d.host, username: d.username, password: d.password}))
      };
      if (!body.credential_targets.length) {
        status.textContent = 'Add at least one device before scanning.';
        return;
      }
      state.topology = await api('/api/topology/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });
      updateDeviceHostnames();
      renderSharedDeviceRows();
      renderTopology();
    }
    function splitTargets(text) {
      return String(text || '').split(/[\\s,]+/).map(item => item.trim()).filter(Boolean);
    }
    function addTopologyTarget() {
      const target = document.getElementById('topoTargets').value.trim();
      const username = document.getElementById('topoUser').value.trim();
      const password = document.getElementById('topoPass').value;
      if (!target || !username || !password) {
        document.getElementById('topologyStatus').textContent = 'Enter targets, username, and password before Add.';
        return;
      }
      const targets = splitTargets(target);
      if (targets.some(item => item.includes('/') || item.includes('-'))) {
        document.getElementById('topologyStatus').textContent = 'Add supports IPs only. Enter multiple IPs separated by comma or space.';
        return;
      }
      targets.forEach(item => {
        if (!state.devices.some(device => device.host === item)) {
          state.devices.push({host: item, username, password, hostname: ''});
        }
      });
      ensureTamDeviceSelection();
      renderSharedDeviceRows();
      document.getElementById('topoTargets').value = '';
      document.getElementById('topoUser').value = '';
      document.getElementById('topoPass').value = '';
      document.getElementById('topologyStatus').textContent = `${state.devices.length} devices ready.`;
    }
    function renderSharedDeviceRows() {
      ensureTamDeviceSelection();
      renderTopologyDeviceRows();
      renderTamDeviceRows();
    }
    function renderTopologyDeviceRows() {
      const container = document.getElementById('topoDeviceRows');
      if (!container) return;
      if (!state.devices.length) {
        container.innerHTML = '';
        return;
      }
      container.innerHTML = table(['IP', 'Hostname', 'Username', 'Password', ''], state.devices.map((row, i) => `<tr>
        <td><input data-shared-row="${i}" data-shared-field="host" value="${esc(row.host)}"></td>
        <td>${esc(row.hostname || '-')}</td>
        <td><input data-shared-row="${i}" data-shared-field="username" value="${esc(row.username)}"></td>
        <td><input data-shared-row="${i}" data-shared-field="password" type="password" value="${esc(row.password)}"></td>
        <td><button class="mini" data-shared-delete="${i}">Delete</button></td>
      </tr>`));
      container.querySelectorAll('input[data-shared-row]').forEach(input => {
        input.addEventListener('input', () => {
          const row = state.devices[Number(input.dataset.sharedRow)];
          row[input.dataset.sharedField] = input.value;
          if (input.dataset.sharedField === 'host') row.hostname = '';
          renderTamDeviceRows();
        });
      });
      container.querySelectorAll('button[data-shared-delete]').forEach(button => {
        button.addEventListener('click', () => {
          const index = Number(button.dataset.sharedDelete);
          state.devices.splice(index, 1);
          if (state.tamDeviceIndex === index) state.tamDeviceIndex = state.devices.length ? Math.min(index, state.devices.length - 1) : -1;
          else if (state.tamDeviceIndex > index) state.tamDeviceIndex -= 1;
          renderSharedDeviceRows();
          document.getElementById('topologyStatus').textContent = `${state.devices.length} devices ready.`;
        });
      });
    }
    function renderTamDeviceRows() {
      const container = document.getElementById('tamSharedDeviceRows');
      if (!container) return;
      ensureTamDeviceSelection();
      if (!state.devices.length) {
        container.innerHTML = '';
        return;
      }
      container.innerHTML = table(['Select', 'IP', 'Hostname', 'Username'], state.devices.map((row, i) => `<tr>
        <td><input name="tamDevice" data-tam-device="${i}" type="radio" ${state.tamDeviceIndex === i ? 'checked' : ''}></td>
        <td>${esc(row.host)}</td>
        <td>${esc(row.hostname || '-')}</td>
        <td>${esc(row.username)}</td>
      </tr>`));
      container.querySelectorAll('input[data-tam-device]').forEach(input => {
        input.addEventListener('change', () => {
          state.tamDeviceIndex = Number(input.dataset.tamDevice);
          renderTamDeviceRows();
        });
      });
    }
    function ensureTamDeviceSelection() {
      if (!state.devices.length) {
        state.tamDeviceIndex = -1;
        return;
      }
      if (state.tamDeviceIndex < 0 || state.tamDeviceIndex >= state.devices.length) state.tamDeviceIndex = 0;
    }
    function selectedDeviceSpecs() {
      ensureTamDeviceSelection();
      const d = state.devices[state.tamDeviceIndex];
      if (!d || !d.host || !d.username || !d.password) return [];
      return [{host: d.host, username: d.username, password: d.password}];
    }
    function updateDeviceHostnames() {
      const nodes = state.topology?.graph?.nodes || [];
      const byIp = {};
      nodes.forEach(node => { if (node.ip) byIp[node.ip] = node.id; });
      state.devices.forEach(device => { device.hostname = byIp[device.host] || device.hostname || ''; });
    }
    function flowgroupMatch(f) {
      const parts = [];
      if (f.src_ip || f.dst_ip) parts.push(`${f.src_ip || '*'} -> ${f.dst_ip || '*'}`);
      if (f.src_ipv6 || f.dst_ipv6) parts.push(`${f.src_ipv6 || '*'} -> ${f.dst_ipv6 || '*'}`);
      if (f.protocol) parts.push(`proto=${f.protocol}`);
      if (f.src_mac || f.dst_mac) parts.push(`mac=${f.src_mac || '*'} -> ${f.dst_mac || '*'}`);
      if (f.l4_src_port || f.l4_dst_port) parts.push(`l4=${f.l4_src_port || '*'} -> ${f.l4_dst_port || '*'}`);
      if (f.vlan) parts.push(`vlan=${f.vlan}`);
      if (f.ethertype) parts.push(`ethertype=${f.ethertype}`);
      return parts.join(', ');
    }
    function tableWithActions(kind, headers, rows) {
      const controls = rows.length
        ? `<div class="table-actions"><button class="mini" data-delete-kind="${kind}">Queue Selected Deletes</button></div>`
        : '';
      return controls + table(['Delete', ...headers], rows);
    }
    function renderTam() {
      const tam = state.tam || { devices: [], errors: [] };
      document.getElementById('tamStatus').textContent = tam.summary
        ? `${tam.summary.devices} devices, ${tam.summary.errors} errors`
        : 'No TAM state loaded.';
      const switches = tam.devices.flatMap(d => [{
        host: d.host,
        switch_id: d.switch_id,
        enterprise_id: d.enterprise_id,
        ifa_status: d.ifa_status,
        features: (d.features || []).map(f => `${f.feature}:${f.status}`).join(', ')
      }]);
      document.getElementById('tamSwitches').innerHTML = table(['Host', 'Switch ID', 'Enterprise ID', 'IFA', 'VRFs', 'Features'],
        switches.map(d => {
          const source = tam.devices.find(item => item.host === d.host) || {};
          return `<tr><td>${esc(d.host)}</td><td>${esc(d.switch_id)}</td><td>${esc(d.enterprise_id)}</td><td>${esc(d.ifa_status)}</td><td>${esc((source.vrfs || []).join(', '))}</td><td>${esc(d.features)}</td></tr>`;
        }));
      document.getElementById('tamCollectors').innerHTML = tableWithActions('collectors', ['Host', 'Name', 'IP', 'Port', 'Protocol', 'VRF'],
        tam.devices.flatMap(d => (d.collectors || []).map(c => `<tr><td><input type="checkbox" data-tam-delete="collectors" value="${esc(c.name)}"></td><td>${esc(d.host)}</td><td>${esc(c.name)}</td><td>${esc(c.ip)}</td><td>${esc(c.port)}</td><td>${esc(c.protocol)}</td><td>${esc(c.vrf || '-')}</td></tr>`)));
      document.getElementById('tamSamplers').innerHTML = tableWithActions('samplers', ['Host', 'Name', 'Sampling Rate'],
        tam.devices.flatMap(d => (d.samplers || []).map(s => `<tr><td><input type="checkbox" data-tam-delete="samplers" value="${esc(s.name)}"></td><td>${esc(d.host)}</td><td>${esc(s.name)}</td><td>${esc(s.sampling_rate)}</td></tr>`)));
      document.getElementById('tamFlowgroups').innerHTML = tableWithActions('flowgroups', ['Host', 'Name', 'ID', 'Match', 'Packets', 'Bytes'],
        tam.devices.flatMap(d => (d.flowgroups || []).map(f => `<tr><td><input type="checkbox" data-tam-delete="flowgroups" value="${esc(f.name)}"></td><td>${esc(d.host)}</td><td>${esc(f.name)}</td><td>${esc(f.id)}</td><td><code>${esc(flowgroupMatch(f))}</code></td><td>${esc(f.packets)}</td><td>${esc(f.bytes)}</td></tr>`)));
      document.getElementById('tamSessions').innerHTML = tableWithActions('sessions', ['Host', 'Name', 'Flow Group', 'Node Type', 'Collector', 'Sampler'],
        tam.devices.flatMap(d => (d.ifa_sessions || []).map(s => `<tr><td><input type="checkbox" data-tam-delete="sessions" value="${esc(s.name)}"></td><td>${esc(d.host)}</td><td>${esc(s.name)}</td><td>${esc(s.flowgroup)}</td><td>${esc(s.node_type)}</td><td>${esc(s.collector || '-')}</td><td>${esc(s.sampler || '-')}</td></tr>`)));
      document.querySelectorAll('button[data-delete-kind]').forEach(button => {
        button.addEventListener('click', () => queueSelectedDeletes(button.dataset.deleteKind));
      });
      renderTamForms();
      renderPendingTamSpec();
    }
    async function readTam() {
      const status = document.getElementById('tamStatus');
      status.textContent = 'Reading TAM state...';
      const devices = selectedDeviceSpecs();
      if (!devices.length) {
        status.textContent = 'Select at least one device with IP, username, and password.';
        return;
      }
      state.tam = await api('/api/tam/read', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({devices})
      });
      renderTam();
    }
    function emptyTamSpec() {
      return {delete: {sessions: [], collectors: [], samplers: [], flowgroups: []}, switch: {}, collectors: [], samplers: [], flowgroups: [], sessions: []};
    }
    function configSpec() {
      const spec = JSON.parse(JSON.stringify(state.tamSpec));
      ['sessions', 'collectors', 'samplers', 'flowgroups'].forEach(kind => {
        spec.delete[kind] = [...new Set(spec.delete[kind] || [])];
      });
      if (!Object.keys(spec.switch || {}).length) delete spec.switch;
      if (!spec.collectors.length) delete spec.collectors;
      if (!spec.samplers.length) delete spec.samplers;
      if (!spec.flowgroups.length) delete spec.flowgroups;
      if (!spec.sessions.length) delete spec.sessions;
      if (!Object.values(spec.delete || {}).some(value => Array.isArray(value) ? value.length : Boolean(value))) delete spec.delete;
      return spec;
    }
    function selectedTamDevice() {
      const devices = state.tam?.devices || [];
      const selected = state.devices[state.tamDeviceIndex];
      return devices.find(d => d.host === selected?.host) || devices[0] || {};
    }
    function namesFor(kind) {
      const device = selectedTamDevice();
      const existing = (device[kind] || []).map(item => item.name).filter(Boolean);
      const pending = (state.tamSpec[kind] || []).map(item => item.name).filter(Boolean);
      return [...new Set([...existing, ...pending])];
    }
    function setOptions(id, values, emptyLabel = '') {
      const select = document.getElementById(id);
      if (!select) return;
      const current = select.value;
      select.innerHTML = `${emptyLabel ? `<option value="">${esc(emptyLabel)}</option>` : ''}${values.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('')}`;
      if (values.includes(current) || (!current && emptyLabel)) select.value = current;
    }
    function renderTamForms() {
      const device = selectedTamDevice();
      setOptions('tamCollectorVrf', device.vrfs || [], 'None');
      setOptions('tamSessionFlowgroup', namesFor('flowgroups'), 'Select flow group');
      setOptions('tamSessionCollector', namesFor('collectors'), 'None');
      setOptions('tamSessionSampler', namesFor('samplers'), 'None');
    }
    function renderPendingTamSpec() {
      const spec = configSpec();
      document.getElementById('tamPending').textContent = JSON.stringify(spec, null, 2);
    }
    function queueMessage(message) {
      document.getElementById('tamPlan').textContent = message;
      renderTamForms();
      renderPendingTamSpec();
    }
    function addOrReplace(list, item) {
      const index = list.findIndex(row => row.name === item.name);
      if (index >= 0) list[index] = item;
      else list.push(item);
    }
    function addDelete(kind, name) {
      if (!name) return;
      if (!state.tamSpec.delete[kind].includes(name)) state.tamSpec.delete[kind].push(name);
    }
    function queueSelectedDeletes(kind) {
      const selected = [...document.querySelectorAll(`input[data-tam-delete="${kind}"]:checked`)].map(input => input.value);
      selected.forEach(name => addDelete(kind, name));
      queueMessage(selected.length ? `Queued ${selected.length} ${kind} delete operation(s).` : `Select ${kind} rows before queueing delete.`);
    }
    function queueSwitchConfig() {
      const switchId = document.getElementById('tamSwitchId').value.trim();
      const enterpriseId = document.getElementById('tamEnterpriseId').value.trim();
      const ifaStatus = document.getElementById('tamIfaStatus').value;
      if (switchId) state.tamSpec.switch.switch_id = Number(switchId);
      if (enterpriseId) state.tamSpec.switch.enterprise_id = Number(enterpriseId);
      if (ifaStatus) state.tamSpec.ifa_status = ifaStatus;
      queueMessage('Queued switch settings.');
    }
    function queueCollector() {
      const item = {
        name: document.getElementById('tamCollectorName').value.trim(),
        ip: document.getElementById('tamCollectorIp').value.trim(),
        port: Number(document.getElementById('tamCollectorPort').value || 0),
        protocol: document.getElementById('tamCollectorProtocol').value,
        vrf: document.getElementById('tamCollectorVrf').value || undefined
      };
      if (!item.name || !item.ip || !item.port) return queueMessage('Collector needs name, IP, and port.');
      addOrReplace(state.tamSpec.collectors, item);
      queueMessage(`Queued collector ${item.name}.`);
    }
    function queueSampler() {
      const item = {
        name: document.getElementById('tamSamplerName').value.trim(),
        sampling_rate: Number(document.getElementById('tamSamplerRate').value || 0)
      };
      if (!item.name || !item.sampling_rate) return queueMessage('Sampler needs name and sampling rate.');
      addOrReplace(state.tamSpec.samplers, item);
      queueMessage(`Queued sampler ${item.name}.`);
    }
    function queueFlowgroup() {
      const item = {
        name: document.getElementById('tamFgName').value.trim(),
        id: Number(document.getElementById('tamFgId').value || 0),
        priority: Number(document.getElementById('tamFgPriority').value || 100),
        src_ip: document.getElementById('tamFgSrcIp').value.trim() || undefined,
        dst_ip: document.getElementById('tamFgDstIp').value.trim() || undefined,
        protocol: document.getElementById('tamFgProtocol').value || undefined,
        l4_src_port: document.getElementById('tamFgSrcPort').value ? Number(document.getElementById('tamFgSrcPort').value) : undefined,
        l4_dst_port: document.getElementById('tamFgDstPort').value ? Number(document.getElementById('tamFgDstPort').value) : undefined
      };
      if (!item.name || !item.id) return queueMessage('Flow group needs name and ID.');
      addOrReplace(state.tamSpec.flowgroups, item);
      queueMessage(`Queued flow group ${item.name}.`);
    }
    function queueSession() {
      const nodeType = document.getElementById('tamSessionNodeType').value;
      const item = {
        name: document.getElementById('tamSessionName').value.trim(),
        flowgroup: document.getElementById('tamSessionFlowgroup').value,
        node_type: nodeType,
        collector: nodeType === 'EGRESS' ? document.getElementById('tamSessionCollector').value || undefined : undefined,
        sampler: nodeType === 'INGRESS' ? document.getElementById('tamSessionSampler').value || undefined : undefined
      };
      if (!item.name || !item.flowgroup) return queueMessage('IFA session needs name and flow group.');
      if (item.node_type === 'INGRESS' && !item.sampler) return queueMessage('Ingress session needs a sampler.');
      if (item.node_type === 'EGRESS' && !item.collector) return queueMessage('Egress session needs a collector.');
      addOrReplace(state.tamSpec.sessions, item);
      queueMessage(`Queued IFA session ${item.name}.`);
    }
    async function previewTam() {
      const plan = await api('/api/tam/preview', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({spec: configSpec()})
      });
      document.getElementById('tamPlan').textContent = JSON.stringify(plan, null, 2);
    }
    async function applyTam() {
      const devices = selectedDeviceSpecs();
      if (!devices.length) {
        document.getElementById('tamPlan').textContent = 'Select at least one device with IP, username, and password.';
        return;
      }
      const result = await api('/api/tam/apply', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({devices, spec: configSpec()})
      });
      document.getElementById('tamPlan').textContent = JSON.stringify(result, null, 2);
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
    document.getElementById('topoAdd').addEventListener('click', addTopologyTarget);
    document.getElementById('topoClear').addEventListener('click', () => {
      document.getElementById('topoTargets').value = '';
      document.getElementById('topoUser').value = '';
      document.getElementById('topoPass').value = '';
      state.topology = { graph: { nodes: [], links: [] }, summary: {}, errors: [] };
      renderTopology();
    });
    document.getElementById('topoScan').addEventListener('click', () => scanTopology().catch(err => {
      document.getElementById('topologyStatus').textContent = err.message || String(err);
    }));
    document.getElementById('tamRead').addEventListener('click', () => readTam().catch(err => {
      document.getElementById('tamStatus').textContent = err.message || String(err);
    }));
    renderSharedDeviceRows();
    renderPendingTamSpec();
    document.getElementById('tamQueueSwitch').addEventListener('click', queueSwitchConfig);
    document.getElementById('tamDeleteSwitchId').addEventListener('click', () => {
      state.tamSpec.delete.switch_id = true;
      queueMessage('Queued switch-id delete.');
    });
    document.getElementById('tamDeleteEnterpriseId').addEventListener('click', () => {
      state.tamSpec.delete.enterprise_id = true;
      queueMessage('Queued enterprise-id delete.');
    });
    document.getElementById('tamAddCollector').addEventListener('click', queueCollector);
    document.getElementById('tamAddSampler').addEventListener('click', queueSampler);
    document.getElementById('tamAddFlowgroup').addEventListener('click', queueFlowgroup);
    document.getElementById('tamAddSession').addEventListener('click', queueSession);
    document.getElementById('tamSessionNodeType').addEventListener('change', renderTamForms);
    document.getElementById('tamClearPending').addEventListener('click', () => {
      state.tamSpec = emptyTamSpec();
      document.getElementById('tamPlan').textContent = '{}';
      renderPendingTamSpec();
    });
    document.getElementById('tamPreview').addEventListener('click', () => previewTam().catch(err => {
      document.getElementById('tamPlan').textContent = err.message || String(err);
    }));
    document.getElementById('tamApply').addEventListener('click', () => applyTam().catch(err => {
      document.getElementById('tamPlan').textContent = err.message || String(err);
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
            except ValueError as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            except Exception as exc:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/api/topology/scan":
                    body = self._read_json()
                    if body.get("credential_targets"):
                        self._send_json(
                            scan_topology_target_specs(
                                body["credential_targets"],
                                topology_path,
                                rest_port=int(body.get("rest_port", body.get("port", 443))),
                                path_prefix=str(body.get("path_prefix", "/restconf/data")),
                                verify_tls=bool(body.get("verify_tls", False)),
                                timeout=float(body.get("timeout", 10)),
                                ping_first=bool(body.get("ping_first", True)),
                                ping_timeout_ms=int(body.get("ping_timeout_ms", 500)),
                            )
                        )
                    elif body.get("devices"):
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
                elif parsed.path == "/api/tam/read":
                    body = self._read_json()
                    self._send_json(read_tam_devices(_web_device_specs(body)))
                elif parsed.path == "/api/tam/preview":
                    body = self._read_json()
                    self._send_json(preview_tam_plan(_spec(body)))
                elif parsed.path == "/api/tam/apply":
                    body = self._read_json()
                    self._send_json(apply_tam_plan(_web_device_specs(body), _spec(body)))
                else:
                    self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            except ValueError as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
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


def _spec(body: dict[str, object]) -> dict[str, object]:
    spec = body.get("spec", {})
    if not isinstance(spec, dict):
        raise ValueError("spec must be an object")
    return spec
