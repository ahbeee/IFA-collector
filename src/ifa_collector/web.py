from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .ingest import UdpIngestCollector, ingest_pcap
from .inventory import Inventory
from .query import QueryStore
from .schema import SchemaRegistry
from .storage import SqliteStore
from .tam import apply_tam_plan, clear_flowgroup_counters, preview_tam_plan, read_tam_devices
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
    .selected-row { background: #ecfeff; }
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
    .topology-line.active-path { stroke: var(--accent); stroke-width: 4; }
    .topology-node { fill: var(--accent-soft); stroke: var(--accent); stroke-width: 2; }
    .topology-node.active-node { fill: #ccfbf1; stroke-width: 3; }
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
    .inline-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: end; padding: 12px 14px; }
    .inline-actions > div { min-width: 180px; flex: 1; }
    .kv { display: grid; grid-template-columns: 160px 1fr; gap: 6px 12px; padding: 12px 14px; }
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
        <div class="metric"><div class="label">Unresolved Hops</div><div class="value" id="mUnresolved">-</div></div>
      </div>
      <div class="panel">
        <h2>PCAP Import</h2>
        <div class="inline-actions">
          <div><label for="pcapPath">Local PCAP Path</label><input id="pcapPath" placeholder="C:\\captures\\ifa_udp.pcap"></div>
          <button id="pcapImport" class="primary">Import</button>
          <button id="refreshData" class="secondary">Refresh Data</button>
          <button id="reResolveData" class="secondary">Re-resolve DB</button>
          <button id="clearData" class="secondary">Clear DB Data</button>
        </div>
        <div id="pcapStatus" class="status">Import writes parsed IFA records into the active SQLite database. Re-resolve DB refreshes device and interface names from current topology/TAM inventory.</div>
      </div>
      <div class="panel">
        <h2>Live Collector</h2>
        <div class="inline-actions">
          <div><label for="collectorHost">Listen IP</label><input id="collectorHost" value="0.0.0.0"></div>
          <div><label for="collectorPort">UDP Port</label><input id="collectorPort" type="number" value="9090"></div>
          <button id="collectorStart" class="primary">Start</button>
          <button id="collectorStop" class="secondary">Stop</button>
        </div>
        <div id="collectorStatus" class="status">Collector status not loaded.</div>
      </div>
      <div class="panel"><h2>Recent IFA Records</h2><div id="recentRecordsTable"></div></div>
      <div class="panel"><h2>PCAP Import History</h2><div id="importsTable"></div></div>
      <div class="panel"><h2>Exporters</h2><div id="exportersTable"></div></div>
    </section>

    <section id="flows">
      <div class="panel"><h2>Flows</h2><div id="flowsTable"></div></div>
      <div class="panel"><h2>Flow Detail</h2><div id="flowDetail" class="detail">Select a flow.</div></div>
    </section>

    <section id="paths">
      <div class="panel"><h2>Paths</h2><div id="pathsTable"></div></div>
      <div class="panel"><h2>Path Detail</h2><div id="pathDetail" class="detail">Select a path.</div></div>
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
        <div id="topologyPathDetail" class="status">Select a path to highlight it on the topology.</div>
        <div id="topologyGraph" class="topology"></div>
      </div>
      <div class="panel"><h2>Selected Node</h2><div id="topologyNodeDetail" class="detail">Select a topology node.</div></div>
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
              <div><label for="tamFgSrcIpv6">SRC IPv6</label><input id="tamFgSrcIpv6" placeholder="2100::1/64"></div>
              <div><label for="tamFgDstIpv6">DST IPv6</label><input id="tamFgDstIpv6" placeholder="2100::2/64"></div>
              <div><label for="tamFgSrcMac">SRC MAC</label><input id="tamFgSrcMac" placeholder="AA:BB:CC:11:22:33"></div>
              <div><label for="tamFgDstMac">DST MAC</label><input id="tamFgDstMac" placeholder="AA:BB:CC:11:22:44"></div>
              <div><label for="tamFgVlan">VLAN</label><input id="tamFgVlan" type="number"></div>
              <div><label for="tamFgEthertype">Ethertype</label><select id="tamFgEthertype"><option value="">Any</option><option>ARP</option><option>IP</option><option>IPV6</option><option>LLDP</option><option>MPLS</option><option>ROCE</option><option>VLAN</option></select></div>
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
          <button id="tamClearSuccess" class="secondary" style="margin-top: 8px;">Clear Successful</button>
          <button id="tamClearPending" class="secondary" style="margin-top: 8px;">Clear Pending</button>
        </div>
        <pre id="tamPending">No pending changes.</pre>
        <pre id="tamPlan">{}</pre>
      </div>
    </section>

    <section id="errors">
      <div class="panel"><h2>Unresolved Hops</h2><div id="unresolvedTable"></div></div>
      <div class="panel"><h2>Parse Errors</h2><div id="errorsTable"></div></div>
    </section>
  </main>
  <script>
    const state = {
      exporters: [], flows: [], paths: [], recentRecords: [], imports: [], errors: [], unresolved: [], topology: null, tam: null,
      resolution: null,
      devices: [], tamDeviceIndex: -1, tamSpec: emptyTamSpec(), tamTasks: [],
      collector: null, selectedTopologyNode: null, selectedPath: null, selectedPathDetail: null, selectedImportId: null
    };

    async function api(path, options) {
      const res = await fetch(path, options);
      if (!res.ok) throw new Error(await res.text());
      return await res.json();
    }
    function esc(v) {
      return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function jsArg(v) {
      return JSON.stringify(String(v ?? '')).replace(/"/g, '&quot;');
    }
    function table(headers, rows) {
      return `<table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
    }
    function statusClass(row) {
      if (row.gaps || row.duplicate_or_reordered) return 'bad';
      return '';
    }
    function protocolLabel(value) {
      const map = {6: 'TCP', 17: 'UDP'};
      return map[value] || value || '-';
    }
    function hopRange(row) {
      if (row.min_hops == null && row.max_hops == null) return '-';
      return row.min_hops === row.max_hops ? String(row.min_hops) : `${row.min_hops}-${row.max_hops}`;
    }
    function deviceInfo(host) {
      const configured = state.devices.find(d => d.host === host) || {};
      const tamDevice = (state.tam?.devices || []).find(d => d.host === host) || {};
      const topoDevice = topologyDeviceInfo(host);
      return {...configured, ...topoDevice, ...tamDevice, host};
    }
    function topologyDeviceInfo(host) {
      const nodes = state.topology?.graph?.nodes || [];
      const node = nodes.find(n => n.ip === host || n.metadata?.hostname === host || String(n.metadata?.switch_id) === String(host));
      return node?.metadata || {};
    }
    function deviceDisplay(host) {
      const info = deviceInfo(host);
      return info.hostname ? `${info.hostname} (${host})` : host;
    }
    function hopDeviceDisplay(hop) {
      if (hop.device_name) return hop.device_name;
      const tamDevice = (state.tam?.devices || []).find(d => String(d.switch_id) === String(hop.device_id));
      if (tamDevice) return `${deviceDisplay(tamDevice.host)} / switch-id ${hop.device_id}`;
      const topoNode = (state.topology?.graph?.nodes || []).find(n => String(n.metadata?.switch_id) === String(hop.device_id));
      if (topoNode) return `${topoNode.id} / switch-id ${hop.device_id}`;
      return hop.device_id || '-';
    }
    function parsePathNodes(pathText) {
      return String(pathText || '').split(' -> ').map(part => {
        const index = part.indexOf('(');
        return (index >= 0 ? part.slice(0, index) : part).trim();
      }).filter(Boolean);
    }
    function topologyNodeForHop(hop) {
      const nodes = state.topology?.graph?.nodes || [];
      const candidates = [
        hop.device_name,
        hop.device_id != null ? String(hop.device_id) : ''
      ].filter(Boolean).map(String);
      const node = nodes.find(n => {
        const metadata = n.metadata || {};
        return candidates.includes(String(n.id))
          || candidates.includes(String(n.label))
          || candidates.includes(String(metadata.hostname))
          || candidates.includes(String(metadata.switch_id));
      });
      return node?.id || hop.device_name || (hop.device_id != null ? String(hop.device_id) : '');
    }
    function selectedPathHops() {
      return state.selectedPathDetail?.sample_record?.hops || [];
    }
    function selectedTopologyPathNodes() {
      const hops = selectedPathHops();
      if (hops.length) return hops.map(topologyNodeForHop).filter(Boolean);
      return parsePathNodes(state.selectedPath);
    }
    function formatTime(epochSeconds) {
      return epochSeconds ? new Date(epochSeconds * 1000).toLocaleString() : '-';
    }
    async function loadAll() {
      const importQuery = state.selectedImportId ? `&import_id=${encodeURIComponent(state.selectedImportId)}` : '';
      const [exporters, flows, paths, recentRecords, imports, errors, unresolved, topology, collector, resolution] = await Promise.all([
        api(`/api/exporters?${importQuery.slice(1)}`), api(`/api/flows?limit=100${importQuery}`), api(`/api/paths?limit=100${importQuery}`), api(`/api/recent-records?limit=10${importQuery}`), api('/api/imports?limit=10'), api(`/api/errors?limit=100${importQuery}`), api(`/api/unresolved-hops?limit=100${importQuery}`), api('/api/topology'), api('/api/collector/status'), api(`/api/resolution?${importQuery.slice(1)}`)
      ]);
      state.exporters = exporters.exporters;
      state.flows = flows.flows;
      state.paths = paths.paths;
      state.recentRecords = recentRecords.records;
      state.imports = imports.imports;
      state.errors = errors.errors;
      state.unresolved = unresolved.unresolved_hops;
      state.topology = topology;
      state.collector = collector;
      state.resolution = resolution;
      render();
    }
    function render() {
      document.getElementById('mExporters').textContent = state.exporters.length;
      document.getElementById('mFlows').textContent = state.flows.length;
      document.getElementById('mGaps').textContent = state.exporters.reduce((a, e) => a + (e.gaps || 0), 0);
      document.getElementById('mUnresolved').textContent = unresolvedTotal(state.resolution);
      renderExporters();
      renderFlows();
      renderPaths();
      renderTopology();
      renderTam();
      renderErrors();
      renderRecentRecords();
      renderImports();
      renderCollector();
    }
    function renderExporters() {
      const rows = state.exporters.map(e => `<tr>
        <td><code>${esc(e.exporter_key)}</code></td>
        <td>${esc(e.records)}</td>
        <td class="${statusClass(e)}">${esc(e.gaps)}</td>
        <td class="${statusClass(e)}">${esc(e.duplicate_or_reordered)}</td>
        <td>${esc(e.first_sequence)} - ${esc(e.last_sequence)}</td>
        <td>${esc(formatNsTime(e.first_seen_ns))}</td>
        <td>${esc(formatNsTime(e.last_seen_ns))}</td>
        <td>${esc(formatNsAge(e.last_seen_ns))}</td>
      </tr>`);
      document.getElementById('exportersTable').innerHTML = table(['Exporter', 'Records', 'Gaps', 'Dup/Reorder', 'Sequence', 'First Seen', 'Last Seen', 'Idle'], rows);
    }
    function renderFlows() {
      const rows = state.flows.map(f => `<tr class="clickable" onclick="loadFlow(${jsArg(f.flow_key)})">
        <td><code>${esc(f.src_ip)}:${esc(f.src_port)} -> ${esc(f.dst_ip)}:${esc(f.dst_port)}</code></td>
        <td>${esc(protocolLabel(f.protocol))}</td>
        <td>${esc(f.records)}</td>
        <td>${esc(f.paths)}</td>
        <td>${esc(hopRange(f))}</td>
        <td>${esc(f.last_seen_ns)}</td>
        <td><code>${esc(f.flow_key)}</code></td>
      </tr>`);
      document.getElementById('flowsTable').innerHTML = table(['Flow', 'Proto', 'Records', 'Paths', 'Hops', 'Last Seen ns', 'Key'], rows);
    }
    function renderPaths() {
      const rows = state.paths.map(p => `<tr class="clickable" onclick="selectPath(${jsArg(p.resolved_traffic_path)})">
        <td class="path">${esc(p.resolved_traffic_path)}</td>
        <td><code>${esc(p.traffic_path)}</code></td>
        <td><code>${esc(p.metadata_path)}</code></td>
        <td class="${unresolvedTotal(p) ? 'warn' : ''}">${esc(unresolvedTotal(p))}</td>
        <td>${esc(p.flows)}</td>
        <td>${esc(hopRange(p))}</td>
        <td>${esc(p.records)}</td>
      </tr>`);
      document.getElementById('pathsTable').innerHTML = table(['Resolved Traffic Path', 'Traffic Order', 'Metadata Order', 'Unresolved', 'Flows', 'Hops', 'Records'], rows);
    }
    function unresolvedTotal(row) {
      return (row?.unresolved_devices || 0) + (row?.unresolved_ingress_ports || 0) + (row?.unresolved_egress_ports || 0);
    }
    async function selectPath(pathText) {
      try {
        const row = state.paths.find(p => p.resolved_traffic_path === pathText) || {};
        state.selectedPath = pathText;
        const importQuery = state.selectedImportId ? `&import_id=${encodeURIComponent(state.selectedImportId)}` : '';
        state.selectedPathDetail = await api(`/api/path-detail?path=${encodeURIComponent(pathText)}&limit=5${importQuery}`);
        const nodes = selectedTopologyPathNodes();
        const hops = selectedPathHops();
        const hopRows = hops.map(h => `<tr>
          <td>${esc(h.traffic_index)}</td>
          <td>${esc(hopDeviceDisplay(h))}</td>
          <td>${esc(h.ingress_interface || h.ingress_logical_port || '-')} -> ${esc(h.egress_interface || h.egress_logical_port || '-')}</td>
          <td>${esc(h.ttl || '-')}</td>
        </tr>`);
        const pathRecords = Number(row.records || state.selectedPathDetail.path?.records || 0);
        const flowRows = (state.selectedPathDetail.flows || []).map(f => {
          const share = pathRecords ? `${((Number(f.records || 0) / pathRecords) * 100).toFixed(1)}%` : '-';
          const sequenceRange = f.first_sequence == null ? '-' : `${f.first_sequence} - ${f.last_sequence}`;
          return `<tr class="clickable" onclick="loadFlow(${jsArg(f.flow_key)})">
            <td><code>${esc(f.flow_key || '-')}</code></td>
            <td>${esc(f.records || 0)}</td>
            <td>${esc(share)}</td>
            <td>${esc(formatNsTime(f.first_seen_ns))}</td>
            <td>${esc(formatNsTime(f.last_seen_ns))}</td>
            <td>${esc(sequenceRange)}</td>
          </tr>`;
        });
        const sampleRows = (state.selectedPathDetail.sample_records || []).map(r => `<tr class="clickable" onclick="loadFlow(${jsArg(r.flow_key)})">
          <td>${esc(r.id)}</td>
          <td>${esc(r.sequence_number ?? '-')}</td>
          <td>${esc(formatNsTime(r.timestamp_ns))}</td>
          <td><code>${esc(r.flow_key || '-')}</code></td>
          <td>${esc((r.hops || []).length)}</td>
        </tr>`);
        document.getElementById('pathDetail').innerHTML = `<div class="kv">
          <strong>Resolved</strong><code>${esc(pathText)}</code>
          <strong>Traffic IDs</strong><code>${esc(row.traffic_path || state.selectedPathDetail.path?.traffic_path || '-')}</code>
          <strong>Metadata IDs</strong><code>${esc(row.metadata_path || state.selectedPathDetail.path?.metadata_path || '-')}</code>
          <strong>Topology Nodes</strong><span>${esc(nodes.join(' -> ') || '-')}</span>
          <strong>Records</strong><span>${esc(pathRecords)}</span>
          <strong>Flows</strong><span>${esc((state.selectedPathDetail.flows || []).length)}</span>
          <strong>Unresolved Devices</strong><span class="${row.unresolved_devices ? 'warn' : ''}">${esc(row.unresolved_devices || 0)}</span>
          <strong>Unresolved Ingress Ports</strong><span class="${row.unresolved_ingress_ports ? 'warn' : ''}">${esc(row.unresolved_ingress_ports || 0)}</span>
          <strong>Unresolved Egress Ports</strong><span class="${row.unresolved_egress_ports ? 'warn' : ''}">${esc(row.unresolved_egress_ports || 0)}</span>
        </div>
        ${table(['Flow', 'Records', 'Share', 'First Seen', 'Last Seen', 'Sequence Range'], flowRows)}
        ${table(['Record', 'Seq', 'Timestamp', 'Flow', 'Hops'], sampleRows)}
        ${table(['Hop', 'Device', 'Ingress -> Egress', 'TTL'], hopRows)}`;
        renderTopology();
        document.querySelector('[data-tab="paths"]').click();
      } catch (err) {
        document.getElementById('pathDetail').textContent = err.message || String(err);
      }
    }
    function renderCollector() {
      const c = state.collector || {};
      document.getElementById('collectorStatus').innerHTML = `<div class="kv">
        <strong>Status</strong><span class="${c.running ? '' : 'warn'}">${c.running ? 'Running' : 'Stopped'}</span>
        <strong>Listen</strong><code>${esc(c.host || '-')} : ${esc(c.port || '-')}</code>
        <strong>Uptime</strong><span>${esc(formatDuration(c.uptime_seconds || 0))}</span>
        <strong>Packets</strong><span>${esc(c.packets || 0)}</span>
        <strong>Parsed IFA Records</strong><span>${esc(c.parsed_ifa_records || 0)}</span>
        <strong>Packets/s</strong><span>${esc(formatRate(c.packets_per_second || 0))}</span>
        <strong>Records/s</strong><span>${esc(formatRate(c.records_per_second || 0))}</span>
        <strong>Parse Errors</strong><span class="${c.parse_errors ? 'bad' : ''}">${esc(c.parse_errors || 0)}</span>
        <strong>Last Packet</strong><span>${esc(formatTime(c.last_packet_time))}</span>
        <strong>Last Peer</strong><span>${esc(c.last_peer || '-')}</span>
        <strong>Last Error</strong><span>${esc(c.last_error || '-')}</span>
        <strong>Inventory Switches</strong><span class="${c.inventory?.devices ? '' : 'warn'}">${esc(c.inventory?.devices || 0)}</span>
        <strong>Inventory Ports</strong><span class="${c.inventory?.logical_ports ? '' : 'warn'}">${esc(c.inventory?.logical_ports || 0)}</span>
      </div>`;
    }
    function renderRecentRecords() {
      const rows = state.recentRecords.map(r => {
        const hops = (r.hops || []).map(h => `${hopDeviceDisplay(h)}(${h.ingress_interface || h.ingress_logical_port || '-'}->${h.egress_interface || h.egress_logical_port || '-'})`).join(' -> ');
        return `<tr class="clickable" onclick="selectPath(${jsArg(r.resolved_traffic_path)})">
          <td>${esc(r.id)}</td>
          <td>${esc(r.sequence_number ?? '-')}</td>
          <td><code>${esc(r.flow_key || '-')}</code></td>
          <td class="path">${esc(r.resolved_traffic_path || '-')}</td>
          <td class="path">${esc(hops || '-')}</td>
        </tr>`;
      });
      document.getElementById('recentRecordsTable').innerHTML = table(['Record', 'Seq', 'Flow', 'Path', 'Hops'], rows);
    }
    function renderImports() {
      const rows = state.imports.map(item => `<tr class="clickable ${state.selectedImportId === item.id ? 'selected-row' : ''}" onclick="selectImport(${esc(item.id)})">
        <td>${esc(item.id)}</td>
        <td>${esc(formatNsTime(item.imported_at_ns))}</td>
        <td><code>${esc(item.source || '-')}</code></td>
        <td>${esc(item.parsed_ifa_records || 0)}</td>
        <td class="${item.parse_errors ? 'bad' : ''}">${esc(item.parse_errors || 0)}</td>
        <td><button class="secondary" onclick="deleteImport(event, ${esc(item.id)})">Delete</button></td>
      </tr>`);
      const label = state.selectedImportId ? `Filtering by import #${state.selectedImportId}` : 'Showing all records';
      document.getElementById('importsTable').innerHTML = `<div class="status">${esc(label)} ${state.selectedImportId ? '<button class="secondary" onclick="clearImportFilter()">Clear Import Filter</button>' : ''}</div>` + table(['Import', 'Imported At', 'Source', 'Records', 'Errors', 'Action'], rows);
    }
    async function selectImport(importId) {
      state.selectedImportId = Number(importId);
      state.selectedPath = null;
      state.selectedPathDetail = null;
      await loadAll();
    }
    async function clearImportFilter() {
      state.selectedImportId = null;
      await loadAll();
    }
    async function deleteImport(event, importId) {
      event.stopPropagation();
      const stats = await api(`/api/imports/stats?import_id=${encodeURIComponent(importId)}`);
      if (!stats.imports) {
        document.getElementById('pcapStatus').textContent = `Import #${importId} was not found.`;
        await loadAll();
        return;
      }
      const source = stats.source ? `\nSource: ${stats.source}` : '';
      const summary = `${stats.records || 0} record(s), ${stats.hops || 0} hop(s), ${stats.errors || 0} parse error(s)`;
      if (!confirm(`Delete import #${importId}?${source}\n\nThis will delete ${summary}.`)) return;
      const result = await api('/api/imports/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({import_id: Number(importId)})
      });
      if (state.selectedImportId === Number(importId)) {
        state.selectedImportId = null;
        state.selectedPath = null;
        state.selectedPathDetail = null;
      }
      document.getElementById('pcapStatus').textContent = `Deleted import #${importId}: ${result.records || 0} record(s), ${result.hops || 0} hop(s), ${result.errors || 0} error(s).`;
      await loadAll();
    }
    function formatRate(value) {
      return Number(value || 0).toFixed(2);
    }
    function formatNsTime(ns) {
      if (!ns) return '-';
      return new Date(Number(ns) / 1e6).toLocaleString();
    }
    function formatNsAge(ns) {
      if (!ns) return '-';
      return formatDuration((Date.now() * 1e6 - Number(ns)) / 1e9);
    }
    function formatDuration(seconds) {
      const value = Math.max(0, Math.floor(Number(seconds || 0)));
      const h = Math.floor(value / 3600);
      const m = Math.floor((value % 3600) / 60);
      const s = value % 60;
      if (h) return `${h}h ${m}m ${s}s`;
      if (m) return `${m}m ${s}s`;
      return `${s}s`;
    }
    function renderErrors() {
      const unresolvedRows = state.unresolved.map(h => `<tr>
        <td>${esc(h.record_id)}</td>
        <td>${esc(h.traffic_index)}</td>
        <td>${esc(h.device_id || '-')}</td>
        <td>${esc(h.ingress_logical_port || '-')} -> ${esc(h.egress_logical_port || '-')}</td>
        <td>${esc(h.ingress_interface || '-')} -> ${esc(h.egress_interface || '-')}</td>
        <td><code>${esc(h.flow_key || '-')}</code></td>
        <td class="path">${esc(h.resolved_traffic_path || '-')}</td>
      </tr>`);
      document.getElementById('unresolvedTable').innerHTML = table(['Record', 'Hop', 'Device ID', 'Logical Ports', 'Resolved Interfaces', 'Flow', 'Path'], unresolvedRows);
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
      const selectedPathNodes = selectedTopologyPathNodes();
      const selectedEdges = new Set();
      selectedPathNodes.forEach((node, index) => {
        if (index < selectedPathNodes.length - 1) {
          selectedEdges.add([node, selectedPathNodes[index + 1]].sort().join('||'));
        }
      });
      nodes.forEach((n, i) => {
        const a = (-Math.PI / 2) + (Math.PI * 2 * i / nodes.length);
        pos[n.id] = { x: cx + Math.cos(a) * radius, y: cy + Math.sin(a) * Math.min(radius, 170) };
      });
      const edgeSvg = links.map(l => {
        const s = pos[l.source], t = pos[l.target];
        if (!s || !t) return '';
        const active = selectedEdges.has([l.source, l.target].sort().join('||'));
        const label = `${(l.source_interfaces || []).join(',')} - ${(l.target_interfaces || []).join(',')}`;
        return `<line class="topology-line ${active ? 'active-path' : ''}" x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"><title>${esc(label)}</title></line>
          <text class="topology-edge-label" x="${(s.x + t.x) / 2}" y="${(s.y + t.y) / 2 - 6}">${esc(label)}</text>`;
      }).join('');
      const nodeSvg = nodes.map(n => {
        const p = pos[n.id];
        const active = n.id === state.selectedTopologyNode || selectedPathNodes.includes(n.id);
        return `<g class="clickable" onclick="selectTopologyNode(${JSON.stringify(n.id).replace(/"/g, '&quot;')})"><circle class="topology-node ${active ? 'active-node' : ''}" cx="${p.x}" cy="${p.y}" r="34"><title>${esc(n.label || n.id)}</title></circle>
          <text class="topology-label" x="${p.x}" y="${p.y + 4}">${esc(shortLabel(n.id))}</text></g>`;
      }).join('');
      document.getElementById('topologyGraph').innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img">${edgeSvg}${nodeSvg}</svg>`;
      const rows = links.map(l => {
        const active = selectedEdges.has([l.source, l.target].sort().join('||'));
        return `<tr class="${active ? 'selected-row' : ''}"><td>${esc(l.source)} -> ${esc(l.target)}</td><td>${esc((l.source_interfaces || []).join(','))} / ${esc((l.target_interfaces || []).join(','))}</td><td>${esc(l.speed)}</td></tr>`;
      });
      document.getElementById('topologyLinks').innerHTML = table(['Link', 'Interfaces', 'Speed'], rows);
      renderTopologyPathDetail();
      renderTopologyNodeDetail();
    }
    function renderTopologyPathDetail() {
      const el = document.getElementById('topologyPathDetail');
      if (!state.selectedPath) {
        el.textContent = 'Select a path to highlight it on the topology.';
        return;
      }
      const nodes = selectedTopologyPathNodes();
      const row = state.paths.find(p => p.resolved_traffic_path === state.selectedPath) || {};
      const unresolved = unresolvedTotal(row);
      el.innerHTML = `<div class="kv">
        <strong>Selected Path</strong><code>${esc(state.selectedPath)}</code>
        <strong>Topology Nodes</strong><span>${esc(nodes.join(' -> ') || '-')}</span>
        <strong>Unresolved</strong><span class="${unresolved ? 'warn' : ''}">${esc(unresolved)}</span>
      </div>`;
    }
    function selectTopologyNode(nodeId) {
      state.selectedTopologyNode = nodeId;
      renderTopology();
    }
    function renderTopologyNodeDetail() {
      const nodes = state.topology?.graph?.nodes || [];
      const interfaces = state.topology?.interfaces || {};
      const neighbors = state.topology?.neighborships || {};
      const node = nodes.find(n => n.id === state.selectedTopologyNode);
      if (!node) {
        document.getElementById('topologyNodeDetail').textContent = 'Select a topology node.';
        return;
      }
      const topoMetadata = node.metadata || (state.topology?.devices || {})[node.id] || {};
      const tamDevice = (state.tam?.devices || []).find(d => d.host === node.ip || d.hostname === node.id || String(d.switch_id) === String(topoMetadata.switch_id));
      const mergedDevice = {...topoMetadata, ...(tamDevice || {})};
      const ports = interfaces[node.id] || [];
      const portRows = ports.map(p => `<tr><td>${esc(p.name)}</td><td>${esc(p.alias || '-')}</td><td>${esc(p.ifindex || '-')}</td><td>${esc(p.oper_status)}</td><td>${esc(p.speed)}</td><td>${esc(p.mac || '-')}</td></tr>`);
      document.getElementById('topologyNodeDetail').innerHTML = `<div class="kv">
        <strong>Node</strong><span>${esc(node.id)}</span>
        <strong>IP</strong><code>${esc(node.ip || '-')}</code>
        <strong>Switch ID</strong><span>${esc(mergedDevice.switch_id || '-')}</span>
        <strong>Enterprise ID</strong><span>${esc(mergedDevice.enterprise_id || '-')}</span>
        <strong>Platform</strong><span>${esc(mergedDevice.platform || '-')}</span>
        <strong>Product</strong><span>${esc(mergedDevice.product_name || '-')}</span>
        <strong>Interface Naming</strong><span>${esc(mergedDevice.interface_naming_mode || '-')}</span>
        <strong>IFA</strong><span>${esc(mergedDevice.ifa_status || '-')}</span>
        <strong>Neighbors</strong><span>${esc((neighbors[node.id] || []).map(n => `${n.local_interface}->${n.neighbor}`).join(', ') || '-')}</span>
      </div>${table(['Interface', 'Alias', 'IfIndex', 'Oper', 'Speed', 'MAC'], portRows)}`;
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
    async function importPcap() {
      const path = document.getElementById('pcapPath').value.trim();
      const status = document.getElementById('pcapStatus');
      if (!path) {
        status.textContent = 'Enter a local PCAP path before importing.';
        return;
      }
      status.textContent = 'Importing PCAP...';
      const result = await api('/api/pcap/ingest', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path})
      });
      const importId = result.import_id ? ` as import #${result.import_id}` : '';
      status.textContent = `Imported ${result.parsed_ifa_records || 0} IFA record(s), ${result.parse_errors || 0} parse error(s)${importId}.`;
      await loadAll();
    }
    async function startCollector() {
      state.collector = await api('/api/collector/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          host: document.getElementById('collectorHost').value.trim() || '0.0.0.0',
          port: Number(document.getElementById('collectorPort').value || 0)
        })
      });
      renderCollector();
    }
    async function stopCollector() {
      state.collector = await api('/api/collector/stop', {method: 'POST'});
      renderCollector();
      await loadAll();
    }
    async function refreshCollectorStatus() {
      state.collector = await api('/api/collector/status');
      renderCollector();
    }
    async function clearDbData() {
      const status = document.getElementById('pcapStatus');
      const stats = await api('/api/db/stats');
      const summary = `${stats.records || 0} record(s), ${stats.hops || 0} hop(s), ${stats.imports || 0} import(s), ${stats.errors || 0} parse error(s)`;
      if (!confirm(`Clear all IFA collector records from the active database?\n\nThis will delete ${summary}.\n\nTopology and device credentials in this page stay unchanged.`)) return;
      status.textContent = 'Clearing DB data...';
      const result = await api('/api/db/clear', {method: 'POST'});
      status.textContent = `Cleared ${result.records || 0} record(s), ${result.hops || 0} hop(s), ${result.imports || 0} import(s), ${result.errors || 0} parse error(s).`;
      await loadAll();
    }
    async function reResolveDbData() {
      const status = document.getElementById('pcapStatus');
      status.textContent = 'Re-resolving DB with current topology/TAM inventory...';
      const result = await api('/api/db/reresolve', {method: 'POST'});
      status.textContent = `Re-resolved ${result.records || 0} record(s), ${result.hops || 0} hop(s).`;
      await loadAll();
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
      container.innerHTML = table(['Select', 'IP', 'Hostname', 'Switch ID', 'Enterprise ID', 'IFA', 'Username'], state.devices.map((row, i) => {
        const info = deviceInfo(row.host);
        return `<tr>
        <td><input name="tamDevice" data-tam-device="${i}" type="radio" ${state.tamDeviceIndex === i ? 'checked' : ''}></td>
        <td>${esc(row.host)}</td>
        <td>${esc(info.hostname || row.hostname || '-')}</td>
        <td>${esc(info.switch_id || '-')}</td>
        <td>${esc(info.enterprise_id || '-')}</td>
        <td>${esc(info.ifa_status || '-')}</td>
        <td>${esc(row.username)}</td>
      </tr>`;
      }));
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
      nodes.forEach(node => { if (node.ip) byIp[node.ip] = node.metadata?.hostname || node.id; });
      state.devices.forEach(device => {
        const tamDevice = (state.tam?.devices || []).find(d => d.host === device.host);
        device.hostname = tamDevice?.hostname || byIp[device.host] || device.hostname || '';
      });
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
    function tableWithActions(kind, headers, rows, extraControls = '') {
      const controls = rows.length
        ? `<div class="table-actions"><button class="mini" data-delete-kind="${kind}">Queue Selected Deletes</button>${extraControls}</div>`
        : '';
      return controls + table(['Delete', 'Edit', ...headers], rows);
    }
    function renderTam() {
      const tam = state.tam || { devices: [], errors: [] };
      document.getElementById('tamStatus').textContent = tam.summary
        ? `${tam.summary.devices} devices, ${tam.summary.errors} errors`
        : 'No TAM state loaded.';
      const switches = tam.devices.flatMap(d => [{
        host: d.host,
        hostname: d.hostname,
        switch_id: d.switch_id,
        enterprise_id: d.enterprise_id,
        platform: d.platform,
        product_name: d.product_name,
        ifa_status: d.ifa_status,
        features: (d.features || []).map(f => `${f.feature}:${f.status}`).join(', ')
      }]);
      document.getElementById('tamSwitches').innerHTML = table(['Host', 'Switch ID', 'Enterprise ID', 'Platform', 'Product', 'IFA', 'VRFs', 'Features'],
        switches.map(d => {
          const source = tam.devices.find(item => item.host === d.host) || {};
          return `<tr><td>${esc(deviceDisplay(d.host))}</td><td>${esc(d.switch_id)}</td><td>${esc(d.enterprise_id)}</td><td>${esc(d.platform || '-')}</td><td>${esc(d.product_name || '-')}</td><td>${esc(d.ifa_status)}</td><td>${esc((source.vrfs || []).join(', '))}</td><td>${esc(d.features)}</td></tr>`;
        }));
      document.getElementById('tamCollectors').innerHTML = tableWithActions('collectors', ['Host', 'Name', 'IP', 'Port', 'Protocol', 'VRF'],
        tam.devices.flatMap(d => (d.collectors || []).map(c => `<tr><td><input type="checkbox" data-tam-delete="collectors" value="${esc(c.name)}"></td><td><button class="mini" data-tam-edit="collectors" data-tam-name="${esc(c.name)}">Edit</button></td><td>${esc(d.host)}</td><td>${esc(c.name)}</td><td>${esc(c.ip)}</td><td>${esc(c.port)}</td><td>${esc(c.protocol)}</td><td>${esc(c.vrf || '-')}</td></tr>`)));
      document.getElementById('tamSamplers').innerHTML = tableWithActions('samplers', ['Host', 'Name', 'Sampling Rate'],
        tam.devices.flatMap(d => (d.samplers || []).map(s => `<tr><td><input type="checkbox" data-tam-delete="samplers" value="${esc(s.name)}"></td><td><button class="mini" data-tam-edit="samplers" data-tam-name="${esc(s.name)}">Edit</button></td><td>${esc(d.host)}</td><td>${esc(s.name)}</td><td>${esc(s.sampling_rate)}</td></tr>`)));
      document.getElementById('tamFlowgroups').innerHTML = tableWithActions(
        'flowgroups',
        ['Host', 'Name', 'ID', 'Match', 'Packets', 'Bytes'],
        tam.devices.flatMap(d => (d.flowgroups || []).map(f => `<tr><td><input type="checkbox" data-tam-delete="flowgroups" value="${esc(f.name)}"></td><td><button class="mini" data-tam-edit="flowgroups" data-tam-name="${esc(f.name)}">Edit</button></td><td>${esc(d.host)}</td><td>${esc(f.name)}</td><td>${esc(f.id)}</td><td><code>${esc(flowgroupMatch(f))}</code></td><td>${esc(f.packets)}</td><td>${esc(f.bytes)}</td></tr>`)),
        '<button class="mini" data-clear-fg-counters="selected">Clear Selected Counters</button><button class="mini" data-clear-fg-counters="all">Clear All Counters</button>'
      );
      document.getElementById('tamSessions').innerHTML = tableWithActions('sessions', ['Host', 'Name', 'Flow Group', 'Node Type', 'Collector', 'Sampler'],
        tam.devices.flatMap(d => (d.ifa_sessions || []).map(s => `<tr><td><input type="checkbox" data-tam-delete="sessions" value="${esc(s.name)}"></td><td><button class="mini" data-tam-edit="sessions" data-tam-name="${esc(s.name)}">Edit</button></td><td>${esc(d.host)}</td><td>${esc(s.name)}</td><td>${esc(s.flowgroup)}</td><td>${esc(s.node_type)}</td><td>${esc(s.collector || '-')}</td><td>${esc(s.sampler || '-')}</td></tr>`)));
      document.querySelectorAll('button[data-delete-kind]').forEach(button => {
        button.addEventListener('click', () => queueSelectedDeletes(button.dataset.deleteKind));
      });
      document.querySelectorAll('button[data-tam-edit]').forEach(button => {
        button.addEventListener('click', () => populateTamEdit(button.dataset.tamEdit, button.dataset.tamName));
      });
      document.querySelectorAll('button[data-clear-fg-counters]').forEach(button => {
        button.addEventListener('click', () => clearFlowgroupCounters(button.dataset.clearFgCounters).catch(err => {
          document.getElementById('tamPlan').textContent = err.message || String(err);
        }));
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
    function populateTamEdit(kind, name) {
      const device = selectedTamDevice();
      if (kind === 'collectors') {
        const item = (device.collectors || []).find(row => row.name === name);
        if (!item) return;
        document.getElementById('tamCollectorName').value = item.name || '';
        document.getElementById('tamCollectorIp').value = item.ip || '';
        document.getElementById('tamCollectorPort').value = item.port || '';
        document.getElementById('tamCollectorProtocol').value = item.protocol || 'UDP';
        document.getElementById('tamCollectorVrf').value = item.vrf || '';
        queueMessage(`Loaded collector ${name} into the form. Adjust values, then Queue Add.`);
      } else if (kind === 'samplers') {
        const item = (device.samplers || []).find(row => row.name === name);
        if (!item) return;
        document.getElementById('tamSamplerName').value = item.name || '';
        document.getElementById('tamSamplerRate').value = item.sampling_rate || '';
        queueMessage(`Loaded sampler ${name} into the form. Adjust values, then Queue Add.`);
      } else if (kind === 'flowgroups') {
        const item = (device.flowgroups || []).find(row => row.name === name);
        if (!item) return;
        document.getElementById('tamFgName').value = item.name || '';
        document.getElementById('tamFgId').value = item.id || '';
        document.getElementById('tamFgPriority').value = item.priority || 100;
        document.getElementById('tamFgProtocol').value = item.protocol || '';
        document.getElementById('tamFgSrcIp').value = item.src_ip || '';
        document.getElementById('tamFgDstIp').value = item.dst_ip || '';
        document.getElementById('tamFgSrcIpv6').value = item.src_ipv6 || '';
        document.getElementById('tamFgDstIpv6').value = item.dst_ipv6 || '';
        document.getElementById('tamFgSrcMac').value = item.src_mac || '';
        document.getElementById('tamFgDstMac').value = item.dst_mac || '';
        document.getElementById('tamFgVlan').value = item.vlan || '';
        document.getElementById('tamFgEthertype').value = item.ethertype || '';
        document.getElementById('tamFgSrcPort').value = item.l4_src_port || '';
        document.getElementById('tamFgDstPort').value = item.l4_dst_port || '';
        queueMessage(`Loaded flow group ${name} into the form. Adjust values, then Queue Add.`);
      } else if (kind === 'sessions') {
        const item = (device.ifa_sessions || []).find(row => row.name === name);
        if (!item) return;
        document.getElementById('tamSessionName').value = item.name || '';
        document.getElementById('tamSessionFlowgroup').value = item.flowgroup || '';
        document.getElementById('tamSessionNodeType').value = item.node_type || 'INGRESS';
        document.getElementById('tamSessionCollector').value = item.collector || '';
        document.getElementById('tamSessionSampler').value = item.sampler || '';
        queueMessage(`Loaded IFA session ${name} into the form. Adjust values, then Queue Add.`);
      }
    }
    function renderPendingTamSpec() {
      const text = state.tamTasks.length
        ? state.tamTasks.map(task => task.message + (task.status ? ' [' + task.status + ']' : '') + (task.error ? ' ' + task.error : '')).join('\\n')
        : 'No pending changes.';
      document.getElementById('tamPending').textContent = text;
    }
    function queueMessage(message) {
      document.getElementById('tamPlan').textContent = message;
      renderTamForms();
      renderPendingTamSpec();
    }
    function queueTask(message, description) {
      state.tamTasks.push({message, description, status: '', error: ''});
      queueMessage(message);
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
      selected.forEach(name => {
        addDelete(kind, name);
        const singular = kind === 'sessions' ? 'IFA session' : kind.slice(0, -1);
        queueTask(`Queued ${singular} ${name} delete operation.`, `delete ${singular} ${name}`);
      });
      queueMessage(selected.length ? `Queued ${selected.length} ${kind} delete operation(s).` : `Select ${kind} rows before queueing delete.`);
    }
    function queueSwitchConfig() {
      const switchId = document.getElementById('tamSwitchId').value.trim();
      const enterpriseId = document.getElementById('tamEnterpriseId').value.trim();
      const ifaStatus = document.getElementById('tamIfaStatus').value;
      if (switchId) {
        state.tamSpec.switch.switch_id = Number(switchId);
        queueTask('Queued switch-id setting.', 'set switch-id');
      }
      if (enterpriseId) {
        state.tamSpec.switch.enterprise_id = Number(enterpriseId);
        queueTask('Queued enterprise-id setting.', 'set enterprise-id');
      }
      if (ifaStatus) {
        state.tamSpec.ifa_status = ifaStatus;
        queueTask(`Queued IFA ${ifaStatus} setting.`, `set IFA ${ifaStatus}`);
      }
      if (!switchId && !enterpriseId && !ifaStatus) queueMessage('Enter switch settings before queueing.');
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
      queueTask(`Queued collector ${item.name}.`, `set collector ${item.name}`);
    }
    function queueSampler() {
      const item = {
        name: document.getElementById('tamSamplerName').value.trim(),
        sampling_rate: Number(document.getElementById('tamSamplerRate').value || 0)
      };
      if (!item.name || !item.sampling_rate) return queueMessage('Sampler needs name and sampling rate.');
      addOrReplace(state.tamSpec.samplers, item);
      queueTask(`Queued sampler ${item.name}.`, `set sampler ${item.name}`);
    }
    function queueFlowgroup() {
      const item = {
        name: document.getElementById('tamFgName').value.trim(),
        id: Number(document.getElementById('tamFgId').value || 0),
        priority: Number(document.getElementById('tamFgPriority').value || 100),
        src_ip: document.getElementById('tamFgSrcIp').value.trim() || undefined,
        dst_ip: document.getElementById('tamFgDstIp').value.trim() || undefined,
        src_ipv6: document.getElementById('tamFgSrcIpv6').value.trim() || undefined,
        dst_ipv6: document.getElementById('tamFgDstIpv6').value.trim() || undefined,
        src_mac: document.getElementById('tamFgSrcMac').value.trim() || undefined,
        dst_mac: document.getElementById('tamFgDstMac').value.trim() || undefined,
        vlan: document.getElementById('tamFgVlan').value ? Number(document.getElementById('tamFgVlan').value) : undefined,
        ethertype: document.getElementById('tamFgEthertype').value || undefined,
        protocol: document.getElementById('tamFgProtocol').value || undefined,
        l4_src_port: document.getElementById('tamFgSrcPort').value ? Number(document.getElementById('tamFgSrcPort').value) : undefined,
        l4_dst_port: document.getElementById('tamFgDstPort').value ? Number(document.getElementById('tamFgDstPort').value) : undefined
      };
      if (!item.name || !item.id) return queueMessage('Flow group needs name and ID.');
      addOrReplace(state.tamSpec.flowgroups, item);
      queueTask(`Queued flow group ${item.name}.`, `set flowgroup ${item.name}`);
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
      queueTask(`Queued IFA session ${item.name}.`, `set IFA session ${item.name}`);
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
      const byDescription = {};
      (result.results || []).forEach(item => { byDescription[item.description] = item; });
      state.tamTasks.forEach(task => {
        const item = byDescription[task.description];
        if (!item) return;
        task.status = item.status === 'ok' ? 'ok' : 'error';
        task.error = item.error || '';
      });
      renderPendingTamSpec();
      document.getElementById('tamPlan').textContent = `Apply finished: ${result.summary?.requests || 0} request(s), ${result.summary?.errors || 0} error(s).`;
      if ((result.summary?.errors || 0) === 0) {
        await readTam();
        document.getElementById('tamPlan').textContent = `Apply finished: ${result.summary?.requests || 0} request(s), ${result.summary?.errors || 0} error(s). TAM state refreshed.`;
      }
    }
    async function clearFlowgroupCounters(mode) {
      const devices = selectedDeviceSpecs();
      if (!devices.length) {
        document.getElementById('tamPlan').textContent = 'Select one TAM device before clearing counters.';
        return;
      }
      const names = mode === 'all'
        ? ['all']
        : [...document.querySelectorAll('input[data-tam-delete="flowgroups"]:checked')].map(input => input.value);
      if (!names.length) {
        document.getElementById('tamPlan').textContent = 'Select flow group rows before clearing counters.';
        return;
      }
      const result = await api('/api/tam/flowgroup-counters/clear', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({devices, names})
      });
      document.getElementById('tamPlan').textContent = `Clear counters finished: ${result.summary?.requests || 0} request(s), ${result.summary?.errors || 0} error(s).`;
      if ((result.summary?.errors || 0) === 0) {
        await readTam();
        document.getElementById('tamPlan').textContent = `Clear counters finished: ${result.summary?.requests || 0} request(s), ${result.summary?.errors || 0} error(s). TAM state refreshed.`;
      } else {
        document.getElementById('tamPlan').textContent = JSON.stringify(result, null, 2);
      }
    }
    function clearSuccessfulTamTasks() {
      state.tamTasks.filter(task => task.status === 'ok').forEach(task => removeTaskFromSpec(task.description));
      state.tamTasks = state.tamTasks.filter(task => task.status !== 'ok');
      if (!state.tamTasks.length) {
        state.tamSpec = emptyTamSpec();
      }
      renderPendingTamSpec();
      document.getElementById('tamPlan').textContent = state.tamTasks.length ? 'Successful tasks cleared; failed or pending tasks remain.' : '{}';
    }
    function removeTaskFromSpec(description) {
      const removeNamed = (list, name) => {
        const index = list.findIndex(item => item.name === name);
        if (index >= 0) list.splice(index, 1);
      };
      const deleteMatch = description.match(/^delete (IFA session|collector|sampler|flowgroup) (.+)$/);
      if (deleteMatch) {
        const map = {'IFA session': 'sessions', collector: 'collectors', sampler: 'samplers', flowgroup: 'flowgroups'};
        const key = map[deleteMatch[1]];
        state.tamSpec.delete[key] = (state.tamSpec.delete[key] || []).filter(name => name !== deleteMatch[2]);
        return;
      }
      const setMatch = description.match(/^set (collector|sampler|flowgroup|IFA session) (.+)$/);
      if (setMatch) {
        const map = {collector: 'collectors', sampler: 'samplers', flowgroup: 'flowgroups', 'IFA session': 'sessions'};
        removeNamed(state.tamSpec[map[setMatch[1]]] || [], setMatch[2]);
        return;
      }
      if (description === 'set switch-id') delete state.tamSpec.switch.switch_id;
      if (description === 'set enterprise-id') delete state.tamSpec.switch.enterprise_id;
      if (description.startsWith('set IFA ')) delete state.tamSpec.ifa_status;
      if (description === 'delete switch-id') delete state.tamSpec.delete.switch_id;
      if (description === 'delete enterprise-id') delete state.tamSpec.delete.enterprise_id;
    }
    async function loadFlow(flowKey) {
      const importQuery = state.selectedImportId ? `&import_id=${encodeURIComponent(state.selectedImportId)}` : '';
      const data = await api('/api/flow-detail?flow_key=' + encodeURIComponent(flowKey) + '&limit=3' + importQuery);
      const flow = data.flow;
      const totalRecords = Number(flow.records || 0);
      const pathRows = (data.paths || []).map(p => {
        const share = totalRecords ? `${((Number(p.records || 0) / totalRecords) * 100).toFixed(1)}%` : '-';
        return `<tr class="clickable" onclick="selectPath(${jsArg(p.resolved_traffic_path)})">
          <td class="path"><code>${esc(p.resolved_traffic_path || '-')}</code></td>
          <td><code>${esc(p.traffic_path || '-')}</code></td>
          <td>${esc(p.records || 0)}</td>
          <td>${esc(share)}</td>
          <td>${esc(formatNsTime(p.first_seen_ns))}</td>
          <td>${esc(formatNsTime(p.last_seen_ns))}</td>
          <td>${esc(hopRange(p))}</td>
        </tr>`;
      });
      const records = data.sample_records.map(r => `<div>
        <p><span class="pill">seq ${esc(r.sequence_number)}</span> <code>${esc(r.resolved_traffic_path)}</code></p>
        <div class="hopline">${r.hops.map((h, i) => `<div class="hop">
          <strong>${esc(hopDeviceDisplay(h))}</strong><br>
          ${h.model ? `${esc(h.model)}<br>` : ''}
          ingress ${esc(h.ingress_interface || h.ingress_logical_port)} -> egress ${esc(h.egress_interface || h.egress_logical_port)}<br>
          ttl ${esc(h.ttl)}
        </div>${i < r.hops.length - 1 ? '<span class="arrow">-></span>' : ''}`).join('')}</div>
      </div>`).join('');
      document.getElementById('flowDetail').innerHTML = `<div class="kv">
        <strong>Flow</strong><code>${esc(flow.flow_key)}</code>
        <strong>Records</strong><span>${esc(totalRecords)}</span>
        <strong>Paths</strong><span>${esc((data.paths || []).length)}</span>
        <strong>First Seen</strong><span>${esc(formatNsTime(flow.first_seen_ns))}</span>
        <strong>Last Seen</strong><span>${esc(formatNsTime(flow.last_seen_ns))}</span>
      </div>
      ${table(['Resolved Path', 'Traffic IDs', 'Records', 'Share', 'First Seen', 'Last Seen', 'Hops'], pathRows)}
      <div class="detail">${records || 'No sample records.'}</div>`;
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
    document.getElementById('refreshData').addEventListener('click', () => loadAll().catch(err => {
      document.getElementById('pcapStatus').textContent = err.message || String(err);
    }));
    document.getElementById('pcapImport').addEventListener('click', () => importPcap().catch(err => {
      document.getElementById('pcapStatus').textContent = err.message || String(err);
    }));
    document.getElementById('clearData').addEventListener('click', () => clearDbData().catch(err => {
      document.getElementById('pcapStatus').textContent = err.message || String(err);
    }));
    document.getElementById('reResolveData').addEventListener('click', () => reResolveDbData().catch(err => {
      document.getElementById('pcapStatus').textContent = err.message || String(err);
    }));
    document.getElementById('collectorStart').addEventListener('click', () => startCollector().catch(err => {
      document.getElementById('collectorStatus').textContent = err.message || String(err);
    }));
    document.getElementById('collectorStop').addEventListener('click', () => stopCollector().catch(err => {
      document.getElementById('collectorStatus').textContent = err.message || String(err);
    }));
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
      queueTask('Queued switch-id delete.', 'delete switch-id');
    });
    document.getElementById('tamDeleteEnterpriseId').addEventListener('click', () => {
      state.tamSpec.delete.enterprise_id = true;
      queueTask('Queued enterprise-id delete.', 'delete enterprise-id');
    });
    document.getElementById('tamAddCollector').addEventListener('click', queueCollector);
    document.getElementById('tamAddSampler').addEventListener('click', queueSampler);
    document.getElementById('tamAddFlowgroup').addEventListener('click', queueFlowgroup);
    document.getElementById('tamAddSession').addEventListener('click', queueSession);
    document.getElementById('tamSessionNodeType').addEventListener('change', renderTamForms);
    document.getElementById('tamClearPending').addEventListener('click', () => {
      state.tamSpec = emptyTamSpec();
      state.tamTasks = [];
      document.getElementById('tamPlan').textContent = '{}';
      renderPendingTamSpec();
    });
    document.getElementById('tamClearSuccess').addEventListener('click', clearSuccessfulTamTasks);
    document.getElementById('tamPreview').addEventListener('click', () => previewTam().catch(err => {
      document.getElementById('tamPlan').textContent = err.message || String(err);
    }));
    document.getElementById('tamApply').addEventListener('click', () => applyTam().catch(err => {
      document.getElementById('tamPlan').textContent = err.message || String(err);
    }));
    setInterval(() => refreshCollectorStatus().catch(() => {}), 5000);
    loadAll().catch(err => { document.body.innerHTML = '<pre>' + esc(err.stack || err) + '</pre>'; });
  </script>
</body>
</html>
"""


def serve(db_path: Path, host: str, port: int, topology_path: Path | None = None) -> None:
    topology_path = topology_path or Path("topology/topology.json")
    registry = SchemaRegistry.load_default()
    inventory = Inventory()
    inventory.update_from_topology(load_topology(topology_path))
    collector = UdpIngestCollector(db_path, registry, inventory)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/":
                    self._send_html(INDEX_HTML)
                elif parsed.path == "/api/exporters":
                    self._send_json({"exporters": _query(db_path).exporters(_import_id(parsed.query))})
                elif parsed.path == "/api/flows":
                    limit = _limit(parsed.query)
                    self._send_json({"flows": _query(db_path).flows(limit, _import_id(parsed.query))})
                elif parsed.path == "/api/paths":
                    limit = _limit(parsed.query)
                    self._send_json({"paths": _query(db_path).paths(limit, _import_id(parsed.query))})
                elif parsed.path == "/api/recent-records":
                    limit = _limit(parsed.query)
                    self._send_json({"records": _query(db_path).recent_records(limit, _import_id(parsed.query))})
                elif parsed.path == "/api/imports":
                    limit = _limit(parsed.query)
                    self._send_json({"imports": _query(db_path).import_runs(limit)})
                elif parsed.path == "/api/imports/stats":
                    import_id = _required_import_id(parsed.query)
                    store = SqliteStore(db_path)
                    try:
                        self._send_json(store.import_counts(import_id))
                    finally:
                        store.close()
                elif parsed.path == "/api/resolution":
                    self._send_json(_query(db_path).resolution_summary(_import_id(parsed.query)))
                elif parsed.path == "/api/unresolved-hops":
                    limit = _limit(parsed.query)
                    self._send_json({"unresolved_hops": _query(db_path).unresolved_hops(limit, _import_id(parsed.query))})
                elif parsed.path == "/api/errors":
                    limit = _limit(parsed.query)
                    self._send_json({"errors": _query(db_path).errors(limit, _import_id(parsed.query))})
                elif parsed.path == "/api/topology":
                    topology = load_topology(topology_path)
                    inventory.update_from_topology(topology)
                    self._send_json(topology)
                elif parsed.path == "/api/collector/status":
                    self._send_json(collector.status())
                elif parsed.path == "/api/db/stats":
                    store = SqliteStore(db_path)
                    try:
                        self._send_json(store.runtime_counts())
                    finally:
                        store.close()
                elif parsed.path == "/api/flow-detail":
                    params = parse_qs(parsed.query)
                    flow_key = unquote(params.get("flow_key", [""])[0])
                    limit = int(params.get("limit", ["10"])[0])
                    self._send_json(_query(db_path).flow_detail(flow_key, limit, _import_id(parsed.query)))
                elif parsed.path == "/api/path-detail":
                    params = parse_qs(parsed.query)
                    path = unquote(params.get("path", [""])[0])
                    limit = int(params.get("limit", ["5"])[0])
                    self._send_json(_query(db_path).path_detail(path, _import_id(parsed.query), limit))
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
                        result = scan_topology_target_specs(
                            body["credential_targets"],
                            topology_path,
                            rest_port=int(body.get("rest_port", body.get("port", 443))),
                            path_prefix=str(body.get("path_prefix", "/restconf/data")),
                            verify_tls=bool(body.get("verify_tls", False)),
                            timeout=float(body.get("timeout", 10)),
                            ping_first=bool(body.get("ping_first", True)),
                            ping_timeout_ms=int(body.get("ping_timeout_ms", 500)),
                        )
                        inventory.update_from_topology(result)
                        self._send_json(result)
                    elif body.get("devices"):
                        result = scan_topology_devices(_web_device_specs(body), topology_path)
                        inventory.update_from_topology(result)
                        self._send_json(result)
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
                        result = scan_topology(
                            targets,
                            auth,
                            topology_path,
                            ping_first=bool(body.get("ping_first", True)),
                            ping_timeout_ms=int(body.get("ping_timeout_ms", 500)),
                        )
                        inventory.update_from_topology(result)
                        self._send_json(result)
                elif parsed.path == "/api/tam/read":
                    body = self._read_json()
                    result = read_tam_devices(_web_device_specs(body))
                    inventory.update_from_tam_devices(result.get("devices", []))
                    self._send_json(result)
                elif parsed.path == "/api/tam/preview":
                    body = self._read_json()
                    self._send_json(preview_tam_plan(_spec(body)))
                elif parsed.path == "/api/tam/apply":
                    body = self._read_json()
                    self._send_json(apply_tam_plan(_web_device_specs(body), _spec(body)))
                elif parsed.path == "/api/tam/flowgroup-counters/clear":
                    body = self._read_json()
                    names = body.get("names", [])
                    if not isinstance(names, list):
                        self.send_error(HTTPStatus.BAD_REQUEST, "names must be a list")
                        return
                    self._send_json(clear_flowgroup_counters(_web_device_specs(body), [str(name) for name in names]))
                elif parsed.path == "/api/pcap/ingest":
                    body = self._read_json()
                    path = Path(str(body.get("path", ""))).expanduser()
                    if not path.exists():
                        self.send_error(HTTPStatus.BAD_REQUEST, f"pcap not found: {path}")
                        return
                    self._send_json(ingest_pcap(path, db_path, registry, inventory).as_dict())
                elif parsed.path == "/api/collector/start":
                    body = self._read_json()
                    listen_host = str(body.get("host", "0.0.0.0") or "0.0.0.0")
                    listen_port = int(body.get("port", 0))
                    if listen_port <= 0:
                        self.send_error(HTTPStatus.BAD_REQUEST, "port is required")
                        return
                    self._send_json(collector.start(listen_host, listen_port))
                elif parsed.path == "/api/collector/stop":
                    self._send_json(collector.stop())
                elif parsed.path == "/api/db/clear":
                    store = SqliteStore(db_path)
                    try:
                        self._send_json(store.clear_runtime_data())
                    finally:
                        store.close()
                elif parsed.path == "/api/db/reresolve":
                    store = SqliteStore(db_path)
                    try:
                        self._send_json(store.re_resolve_inventory(inventory))
                    finally:
                        store.close()
                elif parsed.path == "/api/imports/delete":
                    body = self._read_json()
                    import_id = int(body.get("import_id", 0))
                    if import_id <= 0:
                        self.send_error(HTTPStatus.BAD_REQUEST, "import_id is required")
                        return
                    store = SqliteStore(db_path)
                    try:
                        self._send_json(store.delete_import_run(import_id))
                    finally:
                        store.close()
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


def _import_id(query: str) -> int | None:
    value = parse_qs(query).get("import_id", [""])[0]
    return int(value) if value else None


def _required_import_id(query: str) -> int:
    value = _import_id(query)
    if value is None or value <= 0:
        raise ValueError("import_id is required")
    return value


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
