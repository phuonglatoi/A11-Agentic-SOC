const state = {
  token: localStorage.getItem("a11_soc_admin_token") || "",
  alerts: [],
  incidents: [],
  actions: [],
  audit: [],
  stats: {},
  runtime: {},
  stream: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
}[char]));

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? esc(value) : new Intl.DateTimeFormat("vi-VN", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "2-digit",
  }).format(date);
}

function ago(value) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return formatTime(value);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body && typeof options.body !== "string") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    lockConsole("Token không hợp lệ hoặc đã thay đổi.");
    throw new Error("Unauthorized");
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || "Request failed");
  }
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("application/json") ? response.json() : response.text();
}

function toast(message, type = "") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.textContent = message;
  $("#toastStack").append(item);
  setTimeout(() => item.remove(), 4200);
}

function lockConsole(message = "") {
  if (state.stream) state.stream.close();
  state.stream = null;
  state.token = "";
  localStorage.removeItem("a11_soc_admin_token");
  $("#authError").textContent = message;
  if (!$("#authDialog").open) $("#authDialog").showModal();
}

async function authenticate(token) {
  state.token = token;
  try {
    await api("/api/v1/runtime");
    localStorage.setItem("a11_soc_admin_token", token);
    $("#authDialog").close();
    $("#authError").textContent = "";
    await refreshAll();
    connectStream();
  } catch (error) {
    state.token = "";
    $("#authError").textContent = "Không thể xác thực. Kiểm tra token và dịch vụ.";
  }
}

async function refreshAll(silent = false) {
  if (!state.token) return lockConsole();
  try {
    const [alerts, incidents, actions, audit, stats, runtime] = await Promise.all([
      api("/api/v1/alerts?limit=200"),
      api("/api/v1/incidents?limit=100"),
      api("/api/v1/actions?limit=100"),
      api("/api/v1/audit?limit=100"),
      api("/api/v1/stats"),
      api("/api/v1/runtime"),
    ]);
    Object.assign(state, { alerts, incidents, actions, audit, stats, runtime });
    render();
    if (!silent) toast("Console synchronized", "success");
  } catch (error) {
    if (error.message !== "Unauthorized") toast(error.message, "error");
  }
}

async function connectStream() {
  if (state.stream) state.stream.close();
  let streamTicket;
  try {
    streamTicket = await api("/api/v1/stream-ticket", { method: "POST" });
  } catch (error) {
    toast("Could not authorize the live stream", "error");
    return;
  }
  const url = `/api/v1/stream?ticket=${encodeURIComponent(streamTicket.ticket)}`;
  state.stream = new EventSource(url);
  state.stream.onopen = () => {
    $("#streamPulse").className = "pulse online";
    $("#streamLabel").textContent = "Live stream";
  };
  state.stream.onerror = () => {
    $("#streamPulse").className = "pulse offline";
    $("#streamLabel").textContent = "Reconnecting";
  };
  state.stream.onmessage = async (message) => {
    const event = JSON.parse(message.data);
    if (event.type === "heartbeat") return;
    if (event.type === "alert") {
      const index = state.alerts.findIndex((item) => item.id === event.data.id);
      if (index >= 0) state.alerts[index] = event.data;
      else state.alerts.unshift(event.data);
      toast(`${event.data.severity.toUpperCase()} · ${event.data.title}`);
      renderAlerts();
    }
    await refreshAll(true);
  };
}

function render() {
  renderRuntime();
  renderStats();
  renderAlerts();
  renderIncidents();
  renderActions();
  renderAudit();
}

function renderRuntime() {
  const llm = state.runtime.ollama_enabled;
  const ml = state.runtime.ml_detector?.enabled;
  $("#engineMode").textContent = llm
    ? `${state.runtime.ollama_model.toUpperCase()} + ${ml ? "ML + " : ""}RAG`
    : `RULES + ${ml ? "ML + " : ""}RAG`;
  $("#responseMode").textContent = String(state.runtime.response_mode || "dry_run").toUpperCase();
  $("#syslogStatus").textContent = state.runtime.syslog?.enabled ? `${state.runtime.syslog.port}/UDP` : "OFF";
  const warnings = state.runtime.warnings || [];
  $("#warningBanner").classList.toggle("hidden", !warnings.length);
  $("#warningBanner").textContent = warnings.join(" ");
}

function renderStats() {
  const counts = state.stats.alerts_by_severity || {};
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  $("#metricCritical").textContent = counts.critical || 0;
  $("#metricHigh").textContent = counts.high || 0;
  $("#metricIncidents").textContent = state.stats.open_incidents || 0;
  $("#metricActions").textContent = state.stats.pending_actions || 0;
  $("#metricTotal").textContent = total;
  $("#metricEvents").textContent = state.stats.correlated_events || 0;
  $("#navAlertCount").textContent = total;
  $("#navActionCount").textContent = state.stats.pending_actions || 0;
  const config = [
    ["critical", "#ff3e60"], ["high", "#ff8548"], ["medium", "#f4bd5e"], ["low", "#4fe1ff"],
  ];
  let cursor = 0;
  const segments = config.map(([name, color]) => {
    const start = cursor;
    cursor += total ? ((counts[name] || 0) / total) * 100 : 0;
    return `${color} ${start}% ${cursor}%`;
  });
  $("#severityDonut").style.background = total
    ? `conic-gradient(${segments.join(",")})`
    : "conic-gradient(rgba(151,177,196,.12) 0 100%)";
  $("#severityLegend").innerHTML = config.map(([name, color]) => `
    <div class="legend-row" style="--legend:${color}"><i></i><span>${name}</span><b>${counts[name] || 0}</b></div>
  `).join("");
}

function severityBadge(severity) {
  return `<span class="severity ${esc(severity)}">${esc(severity)}</span>`;
}

function mitreText(alert) {
  return (alert.mitre || []).slice(0, 2).map((item) => `<span class="mitre-chip">${esc(item.id)}</span>`).join(" ") || "—";
}

function overviewRow(alert) {
  return `<tr data-id="${esc(alert.id)}">
    <td>${severityBadge(alert.severity)}</td>
    <td><span class="cell-title">${esc(alert.title)}</span><span class="cell-sub">${esc(alert.source)} · ${esc(alert.id)}</span></td>
    <td><span class="cell-title">${esc(alert.src_ip || "unknown")}</span><span class="cell-sub">→ ${esc(alert.asset || alert.dst_ip || "unmapped")}</span></td>
    <td>${mitreText(alert)}</td><td>×${alert.event_count}</td><td>${ago(alert.last_seen)}</td>
  </tr>`;
}

function fullAlertRow(alert) {
  return `<tr data-id="${esc(alert.id)}">
    <td>${severityBadge(alert.severity)}</td>
    <td><span class="cell-title">${esc(alert.title)}</span><span class="cell-sub">${esc(alert.id)} · ${esc(alert.event_type)}</span></td>
    <td>${esc(alert.src_ip || "—")}</td><td>${esc(alert.asset || alert.dst_ip || "—")}</td>
    <td>${Math.round(alert.confidence * 100)}%</td><td><span class="status-chip">${esc(alert.status)}</span></td><td>${ago(alert.last_seen)}</td>
  </tr>`;
}

function renderAlerts() {
  const overview = state.alerts.slice(0, 7);
  $("#overviewAlertRows").innerHTML = overview.map(overviewRow).join("");
  $("#overviewEmpty").classList.toggle("hidden", overview.length > 0);
  const severity = $("#severityFilter").value;
  const status = $("#statusFilter").value;
  const filtered = state.alerts.filter((alert) => (!severity || alert.severity === severity) && (!status || alert.status === status));
  $("#alertRows").innerHTML = filtered.map(fullAlertRow).join("");
  $("#alertEmpty").classList.toggle("hidden", filtered.length > 0);
  $$("#overviewAlertRows tr, #alertRows tr").forEach((row) => row.onclick = () => openAlert(row.dataset.id));
}

function openAlert(id) {
  const alert = state.alerts.find((item) => item.id === id);
  if (!alert) return;
  const reasons = (alert.triage?.reasons || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const recommendations = (alert.recommendations || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const knowledge = (alert.triage?.knowledge || []).map((item) => `<li><b>${esc(item.name)}</b> · score ${esc(item.score)}<br>${esc(item.excerpt)}</li>`).join("");
  const ml = alert.triage?.ml_prediction || alert.normalized_event?.ml_prediction || {};
  const mlSection = ml.enabled ? `
    <div class="detail-section"><h3>ML Detection Agent</h3>
      <p><b>${esc(ml.attack_type || "unknown")}</b> · confidence ${Math.round((ml.confidence || 0) * 100)}% · model ${esc(ml.model_version || "unknown")}</p>
      <pre class="evidence-box">${esc(JSON.stringify(ml.top_labels || [], null, 2))}</pre>
    </div>
  ` : "";
  $("#detailContent").innerHTML = `<div class="detail-body">
    <div class="detail-title-row"><p class="eyebrow">ALERT INVESTIGATION / ${esc(alert.id)}</p><h2>${esc(alert.title)}</h2>${severityBadge(alert.severity)}</div>
    <div class="detail-grid">
      <div><span>Status</span><strong>${esc(alert.status)}</strong></div><div><span>Confidence</span><strong>${Math.round(alert.confidence * 100)}%</strong></div>
      <div><span>Events</span><strong>${alert.event_count}</strong></div><div><span>Last seen</span><strong>${formatTime(alert.last_seen)}</strong></div>
      <div><span>Source IP</span><strong>${esc(alert.src_ip || "—")}</strong></div><div><span>Destination</span><strong>${esc(alert.dst_ip || "—")}</strong></div>
      <div><span>Asset</span><strong>${esc(alert.asset || "unmapped")}</strong></div><div><span>Engine</span><strong>${esc(alert.ai_analysis?.engine || "deterministic")}</strong></div>
    </div>
    <div class="detail-section"><h3>Assessment</h3><p>${esc(alert.description)}</p><ul>${reasons}</ul></div>
    ${mlSection}
    <div class="detail-section"><h3>MITRE ATT&CK</h3><p>${(alert.mitre || []).map((item) => `${esc(item.id)} · ${esc(item.name)}`).join("<br>") || "Not mapped"}</p></div>
    <div class="detail-section"><h3>Local knowledge retrieval</h3><ul>${knowledge || "<li>No matching playbook excerpt.</li>"}</ul></div>
    <div class="detail-section"><h3>Recommendations</h3><ul>${recommendations}</ul></div>
    <div class="detail-section"><h3>Latest normalized evidence</h3><pre class="evidence-box">${esc(JSON.stringify({ normalized: alert.normalized_event, raw: alert.raw_event, enrichment: alert.enrichment }, null, 2))}</pre></div>
  </div>`;
  $("#detailDialog").showModal();
}

function renderIncidents() {
  $("#incidentCards").innerHTML = state.incidents.map((incident) => `
    <article class="panel incident-card">
      <div class="card-top"><span class="mono-id">${esc(incident.id)}</span>${severityBadge(incident.priority)}</div>
      <h3>${esc(incident.title)}</h3><p>${esc(incident.summary)}</p>
      <div class="incident-meta"><div><span>Status</span><b>${esc(incident.status)}</b></div><div><span>Opened</span><b>${formatTime(incident.created_at)}</b></div></div>
      <a class="report-link" href="/api/v1/incidents/${encodeURIComponent(incident.id)}/report" data-report="${esc(incident.id)}">View generated report →</a>
    </article>
  `).join("");
  $("#incidentEmpty").classList.toggle("hidden", state.incidents.length > 0);
  $$("[data-report]").forEach((link) => link.onclick = async (event) => {
    event.preventDefault();
    try {
      const report = await api(`/api/v1/incidents/${link.dataset.report}/report`);
      $("#detailContent").innerHTML = `<div class="detail-body"><p class="eyebrow">AUTOMATED INCIDENT REPORT</p><pre class="evidence-box" style="max-height:none">${esc(report)}</pre></div>`;
      $("#detailDialog").showModal();
    } catch (error) { toast(error.message, "error"); }
  });
}

function actionLabel(type) {
  return ({ block_ip: "Add IP to firewall blocklist", isolate_host: "Isolate endpoint", notify_soc: "Notify SOC" })[type] || type;
}

function renderActions() {
  const pending = state.actions.filter((action) => action.status === "pending");
  $("#actionCards").innerHTML = pending.map((action) => `
    <article class="panel action-card"><div class="action-main"><div>
      <p class="eyebrow">${esc(action.id)} / ${esc(action.alert_id)}</p><h3>${esc(actionLabel(action.action_type))}</h3>
      <div class="action-target">TARGET · ${esc(action.target || "—")}</div>
      <div class="action-context"><span class="risk-chip">RISK ${esc(action.risk)}</span><span class="status-chip">${esc(action.status)}</span></div>
    </div><div class="action-buttons">
      <button class="button secondary" data-decision="reject" data-action="${esc(action.id)}">Reject</button>
      <button class="button danger" data-decision="approve" data-action="${esc(action.id)}">Approve</button>
    </div></div></article>
  `).join("");
  $("#actionEmpty").classList.toggle("hidden", pending.length > 0);
  $$("#actionCards [data-decision]").forEach((button) => button.onclick = () => openDecision(button.dataset.action, button.dataset.decision));
}

function openDecision(actionId, decision) {
  const action = state.actions.find((item) => item.id === actionId);
  $("#decisionActionId").value = actionId;
  $("#decisionValue").value = decision;
  $("#decisionTitle").textContent = decision === "approve" ? "Approve response action" : "Reject response action";
  $("#decisionWarning").textContent = decision === "approve"
    ? `${actionLabel(action.action_type)} will run through ${String(state.runtime.response_mode).toUpperCase()} mode against ${action.target}.`
    : "The action will be closed without execution.";
  $("#decisionSubmit").className = decision === "approve" ? "button danger" : "button primary";
  $("#decisionSubmit").textContent = decision === "approve" ? "Approve & execute" : "Confirm rejection";
  $("#decisionDialog").showModal();
}

async function submitDecision() {
  const actionId = $("#decisionActionId").value;
  const decision = $("#decisionValue").value;
  try {
    await api(`/api/v1/actions/${encodeURIComponent(actionId)}/decision`, {
      method: "POST",
      body: { decision, analyst: $("#analystInput").value, reason: $("#decisionReason").value },
    });
    $("#decisionDialog").close();
    $("#decisionReason").value = "";
    toast(`Action ${decision === "approve" ? "executed" : "rejected"} and audited`, "success");
    await refreshAll(true);
  } catch (error) { toast(error.message, "error"); }
}

function renderAudit() {
  $("#auditRows").innerHTML = state.audit.map((item) => `<tr>
    <td>${formatTime(item.created_at)}</td><td>${esc(item.actor)}</td><td><span class="cell-title">${esc(item.action)}</span></td>
    <td><span class="cell-sub">${esc(item.object_type)} / ${esc(item.object_id)}</span></td><td><span class="outcome">${esc(item.outcome)}</span></td>
  </tr>`).join("");
}

function switchView(view) {
  const labels = {
    overview: ["OVERVIEW", "Live defense posture"], alerts: ["ALERT QUEUE", "Detection workbench"],
    incidents: ["INCIDENTS", "Cases and reports"], response: ["RESPONSE", "Human approval gates"], audit: ["AUDIT TRAIL", "Operational accountability"],
  };
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `view-${view}`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $("#currentViewLabel").textContent = labels[view][0];
  $("#pageTitle").textContent = labels[view][1];
}

async function generateDemo() {
  const button = $("#demoButton");
  button.disabled = true; button.textContent = "Generating…";
  try {
    const result = await api("/api/v1/demo/generate", { method: "POST" });
    toast(`${result.generated} synthetic lab events ingested`, "success");
    await refreshAll(true);
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.textContent = "Run lab scenario"; }
}

$("#authForm").addEventListener("submit", (event) => { event.preventDefault(); authenticate($("#tokenInput").value); });
$("#logoutButton").onclick = () => lockConsole();
$("#refreshButton").onclick = () => refreshAll();
$("#demoButton").onclick = generateDemo;
$("#detailClose").onclick = () => $("#detailDialog").close();
$("#severityFilter").onchange = renderAlerts;
$("#statusFilter").onchange = renderAlerts;
$("#decisionCancel").onclick = () => $("#decisionDialog").close();
$("#decisionForm").addEventListener("submit", (event) => { event.preventDefault(); submitDecision(); });
$$(".nav-item").forEach((button) => button.onclick = () => switchView(button.dataset.view));
$$("[data-jump]").forEach((button) => button.onclick = () => switchView(button.dataset.jump));

setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString("vi-VN"); }, 1000);
if (state.token) authenticate(state.token); else lockConsole();
