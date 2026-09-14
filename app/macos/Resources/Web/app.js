(() => {
  "use strict";
  const state = { report: null, quarantine: [], capabilities: { baseline: false, nativeEvents: false, installed: true, appPath: "", version: "0.8.1" }, phase: "starting", autoTimer: null };
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const esc = value => String(value ?? "—").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
  const title = value => String(value || "Unknown").replace(/[_-]+/g, " ").replace(/\b\w/g, char => char.toUpperCase());
  const native = (action, details = {}) => window.webkit?.messageHandlers?.rattler?.postMessage({ action, ...details });
  const decode = base64 => new TextDecoder().decode(Uint8Array.from(atob(base64), char => char.charCodeAt(0)));
  const statusLabel = status => ({healthy:"Protected", degraded:"Needs attention", unhealthy:"Action required", unknown:"Coverage incomplete"}[status] || "Coverage incomplete");
  const severityRank = severity => ({critical:4, high:3, medium:2, low:1, info:0}[severity] ?? 0);
  const formatValue = value => typeof value === "string" ? value : JSON.stringify(value);
  const icon = name => `<svg aria-hidden="true"><use href="#i-${esc(name)}"></use></svg>`;
  const evidence = object => {
    const entries = Object.entries(object || {}).sort(([a],[b]) => a.localeCompare(b));
    if (!entries.length) return "";
    return `<dl class="evidence">${entries.map(([key,value]) => `<dt>${esc(title(key))}</dt><dd>${esc(formatValue(value))}</dd>`).join("")}</dl>`;
  };
  const empty = (icon, heading, message) => `<div class="panel empty"><div><div class="empty-icon">${esc(icon)}</div><h3>${esc(heading)}</h3><p>${esc(message)}</p></div></div>`;
  const badge = severity => `<span class="badge ${esc(severity)}">${esc(String(severity).toUpperCase())}</span>`;
  const checkRow = check => {
    const status = check.status || "unknown";
    return `<div class="check-row ${esc(status)}"><span class="check-dot">${status === "healthy" ? "✓" : status === "unhealthy" ? "×" : "!"}</span><div><strong>${esc(title(check.name))}</strong><small>${esc(check.message)}</small></div><em>${esc(statusLabel(status))}</em></div>`;
  };
  const findingRow = finding => `<div class="finding-row ${esc(finding.severity)}"><div class="finding-main"><strong>${esc(finding.title)}</strong><p>${esc(finding.message)}</p><span class="meta">${esc(finding.rule_id)} &nbsp;•&nbsp; ${esc(title(finding.category))}</span></div>${badge(finding.severity)}</div>`;

  function renderDashboard() {
    if (!state.report) return;
    const report = state.report, behavior = report.behavior || {}, protection = report.protection || {};
    const findings = [...(behavior.findings || [])].sort((a,b) => severityRank(b.severity) - severityRank(a.severity));
    const checks = [...(protection.checks || []), ...(behavior.sensors || [])];
    const healthy = checks.filter(item => item.status === "healthy").length;
    const high = findings.filter(item => ["critical","high"].includes(item.severity)).length;
    const heroCopy = {
      healthy:["No urgent indicators detected","Built-in protection and RATtler’s behavioral sensors completed without a high-risk finding."],
      degraded:["Some coverage needs attention","The endpoint is observable, but one or more findings or sensors need review."],
      unhealthy:["RATtler found activity to review","Open Findings for the evidence behind the highest-priority indicators. RATtler does not remove files automatically."],
      unknown:["The scan could not verify everything","One or more sensors were unavailable. Review Sensor Health to restore visibility."]
    }[report.status] || ["Scan completed","Review the available endpoint evidence."];
    const observed = report.observed_at ? new Date(report.observed_at).toLocaleString([], {dateStyle:"medium",timeStyle:"short"}) : "Just now";
    const priority = findings.slice(0,4).map(findingRow).join("") || `<div class="empty"><div><div class="empty-icon">✓</div><h3>No behavioral findings</h3><p>No current indicator crossed RATtler’s alert threshold.</p></div></div>`;
    const coverage = checks.slice(0,6).map(checkRow).join("");
    const nativeNotice = state.capabilities.nativeEvents ? "" : `<div class="notice warning"><span>◇</span><div><strong>Native telemetry pending</strong><p>Apple’s restricted entitlement is not active. Snapshot and integrity sensors remain available.</p></div></div>`;
    const installNotice = state.capabilities.installed ? "" : `<div class="notice install-notice"><span>→</span><div><strong>Finish installing RATtler</strong><p>Close RATtler, drag it into Applications, then open it from Applications. This prevents download-location alerts.</p></div><button id="show-app-button" class="quiet-button">Show RATtler</button></div>`;
    $("#dashboard-content").className = "";
    $("#dashboard-content").innerHTML = `
      <article class="panel hero ${esc(report.status)}"><div class="shield-orbit"></div><div class="hero-copy"><div class="status-kicker">${esc(statusLabel(report.status).toUpperCase())}</div><h2>${esc(heroCopy[0])}</h2><p>${esc(heroCopy[1])}</p><div class="hostline">▣ ${esc(protection.hostname || "This Mac")} &nbsp;•&nbsp; ${esc(observed)}</div></div><button class="scan-button dashboard-scan"><span>↻</span>Scan now</button></article>${installNotice}
      <div class="metrics">
        ${metric(findings.length,"Findings",findings.length ? "Review recommended" : "No active indicators","alert",findings.length ? "warning" : "")}
        ${metric(high,"High priority","Critical and high","shield",high ? "danger" : "")}
        ${metric(`${healthy}/${checks.length}`,"Coverage","Healthy sensors","coverage","info")}
        ${metric((behavior.events || []).length,"Activity","Recent correlated events","clock","info")}
      </div>
      <div class="dashboard-grid"><article class="panel card-block"><div class="card-title"><div><h3>Priority findings</h3><p>Indicators that deserve attention first</p></div><span>${findings.length} total</span></div>${priority}</article><article class="panel card-block"><div class="card-title"><div><h3>Sensor coverage</h3><p>Latest health by layer</p></div></div>${coverage}${nativeNotice}</article></div>`;
    $(".dashboard-scan")?.addEventListener("click", () => native("scan"));
    $("#show-app-button")?.addEventListener("click", () => native("revealApp"));
  }

  const metric = (value,label,detail,iconName,kind) => `<article class="panel metric ${kind}"><span class="metric-icon">${icon(iconName)}</span><div><strong>${esc(value)}</strong><label>${esc(label)}</label><small>${esc(detail)}</small></div></article>`;

  function filteredFindings() {
    const source = state.report?.behavior?.findings || [];
    const severity = $("#severity-filter").value, query = $("#finding-search").value.trim().toLowerCase();
    return [...source].filter(item => (severity === "all" || item.severity === severity) && (!query || [item.title,item.rule_id,item.category].some(value => String(value || "").toLowerCase().includes(query)))).sort((a,b) => severityRank(b.severity)-severityRank(a.severity));
  }
  function renderFindings() {
    const findings = filteredFindings();
    $("#finding-count").textContent = `${findings.length} shown`;
    if (!state.report) { $("#findings-list").innerHTML = empty("⌕","No scan data","Run a scan to populate the investigation queue."); return; }
    if (!findings.length) { $("#findings-list").innerHTML = empty("✓","Nothing matches this view",(state.report.behavior?.findings || []).length ? "Adjust the filter or search query." : "No current finding crossed RATtler’s alert threshold."); return; }
    $("#findings-list").innerHTML = findings.map((finding,index) => {
      const candidate = responseCandidate(finding);
      const response = candidate ? `<div class="response-action"><span>Manual response only</span><button class="quarantine-button" data-path="${esc(candidate)}" data-rule="${esc(finding.rule_id)}">Review quarantine</button></div>` : "";
      return `<article class="panel finding-card" data-index="${index}">${findingRow(finding)}${response}${evidence(finding.evidence)}</article>`;
    }).join("");
    $$(".finding-card", $("#findings-list")).forEach(card => card.addEventListener("click", event => { if (!event.target.closest("button")) card.classList.toggle("expanded"); }));
    $$(".quarantine-button", $("#findings-list")).forEach(button => button.addEventListener("click", () => native("quarantine", { path: button.dataset.path, ruleId: button.dataset.rule })));
  }
  const responseCandidate = finding => {
    const values = finding?.evidence || {};
    for (const key of ["image", "executable", "actor_path", "path", "plist"]) {
      const value = values[key];
      if (typeof value === "string" && value.startsWith("/") && !value.endsWith(" (deleted)")) return value;
    }
    return null;
  };
  function renderSensors() {
    if (!state.report) { $("#sensors-content").innerHTML = empty("⌁","No sensor report yet","Run a scan to verify each available coverage layer."); return; }
    const protection = state.report.protection || {}, behavior = state.report.behavior || {};
    const checks = [...(protection.checks || []), ...(behavior.sensors || [])], healthy = checks.filter(item=>item.status==="healthy").length, unknown = checks.filter(item=>item.status==="unknown").length;
    $("#sensors-content").innerHTML = `<div class="sensor-summary">${metric(healthy,"Operational","Healthy checks","check","")}${metric(unknown,"Unavailable","Unknown coverage","alert","warning")}${metric(title(protection.provider),"Provider","Native protection","shield","info")}</div>${sensorGroup("Endpoint protection", protection.checks || [])}${sensorGroup("Behavioral sensors", behavior.sensors || [])}${nativeCard()}`;
  }
  const sensorGroup = (heading,checks) => `<div class="sensor-group"><h3>${esc(heading)}</h3><div class="sensor-grid">${checks.map(check => `<article class="panel sensor-card">${checkRow(check)}<p>${esc(check.message)}</p>${evidence(check.details)}</article>`).join("")}</div></div>`;
  const nativeCard = () => {
    const connected = state.capabilities.nativeEvents;
    return `<article class="panel native-card ${connected ? "connected" : ""}"><span class="native-symbol">${connected ? "◇" : "▣"}</span><div><h3>Endpoint Security telemetry <span class="native-state">${connected ? "CONNECTED" : "ENTITLEMENT PENDING"}</span></h3><p>${connected ? "RATtler is ingesting native memory, task-port, remote-thread, tracing, and signature events." : "The collector is built, but Apple must approve its restricted entitlement before public live telemetry can connect."}</p></div><a href="https://developer.apple.com/documentation/endpointsecurity">Apple documentation ↗</a></article>`;
  };
  function renderActivity() {
    const events = state.report?.behavior?.events || [];
    if (!events.length) { $("#activity-list").innerHTML = empty("◷",state.report ? "No new activity" : "No scan data",state.report ? "The current scan did not emit a new process, connection, persistence, or code-loading event." : "Run a scan to initialize RATtler’s local timeline."); return; }
    $("#activity-list").innerHTML = `<article class="panel event-list">${events.map(event => `<div class="event-row ${esc(event.severity)}"><div class="event-head"><span class="event-dot"></span><div><strong>${esc(title(event.event_type))}</strong><small>${esc(event.observed_at ? new Date(event.observed_at).toLocaleString() : "Time unavailable")}</small></div>${badge(event.severity)}</div>${evidence(event.evidence)}</div>`).join("")}</article>`;
    $$(".event-row").forEach(row => row.addEventListener("click", () => row.classList.toggle("expanded")));
  }
  function renderSettings() {
    $("#app-version").textContent = state.capabilities.version;
    $("#baseline-description").textContent = state.capabilities.baseline ? "A reviewed baseline is active and checked during every scan." : "Create this only after reviewing a clean endpoint scan.";
    $("#baseline-button").textContent = state.capabilities.baseline ? "Replace baseline" : "Create baseline";
    $("#installation-description").textContent = state.capabilities.installed ? "RATtler is running from Applications." : "Close RATtler, drag it into Applications, then reopen it there.";
    $("#installation-state").textContent = state.capabilities.installed ? "INSTALLED" : "MOVE APP";
    $("#installation-state").classList.toggle("warning", !state.capabilities.installed);
    $("#native-settings").innerHTML = nativeCard();
    const active = state.quarantine.filter(entry => entry.status === "quarantined");
    $("#quarantine-list").innerHTML = active.length ? active.map(entry => `<div class="quarantine-entry"><div><strong title="${esc(entry.original_path)}">${esc(entry.original_path)}</strong><small>${esc(String(entry.sha256 || "").slice(0,16))}… · ${esc(entry.id)}</small></div><button class="quiet-button restore-button" data-id="${esc(entry.id)}">Review restore</button></div>`).join("") : `<span>No quarantined files are awaiting restore.</span>`;
    $$(".restore-button", $("#quarantine-list")).forEach(button => button.addEventListener("click", () => native("restore", { id: button.dataset.id })));
  }
  function renderChrome() {
    const status = state.report?.status || "unknown";
    $("#sidebar-dot").className = `status-dot ${status}`;
    $("#sidebar-label").textContent = state.report ? statusLabel(status) : "Awaiting scan";
    $("#export-button").disabled = !state.report;
  }
  function renderAll() { renderDashboard(); renderFindings(); renderSensors(); renderActivity(); renderSettings(); renderChrome(); }
  function showToast(message, success = false) { const toast=$("#toast"); $("strong",toast).textContent=success ? "Response completed" : "RATtler needs attention"; $("p",toast).textContent=message; toast.classList.toggle("success",success); toast.classList.add("visible"); clearTimeout(showToast.timer); showToast.timer=setTimeout(()=>toast.classList.remove("visible"),7000); }

  window.RATtler = {
    receiveReport(base64) { try { state.report=JSON.parse(decode(base64)); renderAll(); } catch(error) { showToast(`The report could not be displayed: ${error.message}`); } },
    receiveCapabilities(base64) { try { state.capabilities={...state.capabilities,...JSON.parse(decode(base64))}; renderAll(); } catch(_) {} },
    receiveState(base64) { try { const next=JSON.parse(decode(base64)); state.phase=next.phase; $("#activity-message").textContent=next.message; const scanning=next.phase==="scanning"; $("#scan-button").classList.toggle("scanning",scanning); $("#scan-button").disabled=scanning; if(next.phase==="error") showToast(next.message); } catch(_) {} },
    receiveResponse(base64) { try { const result=JSON.parse(decode(base64)); if(Array.isArray(result.entries)) { state.quarantine=result.entries; renderSettings(); } if(result.message) showToast(result.message, Boolean(result.success)); } catch(_) {} }
  };

  $$(".nav-item").forEach(button => button.addEventListener("click", () => { $$(".nav-item").forEach(item=>item.classList.remove("active")); button.classList.add("active"); $$(".view").forEach(view=>view.classList.remove("active")); $(`#${button.dataset.view}`).classList.add("active"); if(button.dataset.view==="settings") native("listQuarantine"); }));
  $("#scan-button").addEventListener("click",()=>native("scan")); $("#export-button").addEventListener("click",()=>native("export")); $("#reveal-button").addEventListener("click",()=>native("reveal")); $("#quarantine-folder-button").addEventListener("click",()=>native("revealQuarantine")); $("#quarantine-refresh-button").addEventListener("click",()=>native("listQuarantine"));
  $("#baseline-button").addEventListener("click",()=>{ if(confirm(`${state.capabilities.baseline ? "Replace" : "Create"} the integrity baseline?\n\nOnly continue after reviewing the current scan and trusting this Mac’s present state.`)) native("baseline"); });
  $("#severity-filter").addEventListener("change",renderFindings); $("#finding-search").addEventListener("input",renderFindings); $("#toast button").addEventListener("click",()=>$("#toast").classList.remove("visible"));
  const auto=$("#auto-scan"); auto.checked=localStorage.getItem("rattler-auto-scan")==="true"; const configureAuto=()=>{ clearInterval(state.autoTimer); state.autoTimer=null; if(auto.checked) state.autoTimer=setInterval(()=>native("scan"),60000); localStorage.setItem("rattler-auto-scan",auto.checked); }; auto.addEventListener("change",configureAuto); configureAuto();
  native("capabilities");
})();
