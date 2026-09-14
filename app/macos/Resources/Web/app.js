(() => {
  "use strict";
  const state = { report: null, quarantine: [], capabilities: { baseline: false, nativeEvents: false, installed: true, appPath: "", version: "0.9.0" }, phase: "starting", autoTimer: null };
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
  const pulseCheck = behavior => (behavior?.sensors || []).find(item => item.name === "bluepulse");
  const ransomwareCheck = behavior => (behavior?.sensors || []).find(item => item.name === "ransomware");
  const scanFreshness = report => {
    if (document.documentElement.classList.contains("snapshot")) return { fresh:true, age:0 };
    const observed = Date.parse(report?.observed_at || "");
    const age = Date.now() - observed;
    return { fresh: Number.isFinite(age) && age >= 0 && age <= 150000, age };
  };
  const ageLabel = age => !Number.isFinite(age) ? "Unknown" : age < 60000 ? "Just now" : `${Math.floor(age / 60000)} min ago`;

  function renderDashboard() {
    if (!state.report) return;
    const report = state.report, behavior = report.behavior || {}, protection = report.protection || {};
    const findings = [...(behavior.findings || [])].sort((a,b) => severityRank(b.severity) - severityRank(a.severity));
    const checks = [...(protection.checks || []), ...(behavior.sensors || []).filter(item => item.name !== "bluepulse")];
    const pulse = pulseCheck(behavior), pulseConfidence = pulse?.details?.confidence || "unknown";
    const pulseKind = pulseConfidence === "high" ? "" : pulseConfidence === "reduced" ? "warning" : "danger";
    const high = findings.filter(item => ["critical","high"].includes(item.severity)).length;
    const heroCopy = {
      healthy:["No urgent indicators detected","Built-in protection and RATtler’s behavioral sensors completed without a high-risk finding."],
      degraded:["Some coverage needs attention","The endpoint is observable, but one or more findings or sensors need review."],
      unhealthy:["RATtler found activity to review","Open Findings for the evidence behind the highest-priority indicators. RATtler does not remove files automatically."],
      unknown:["The scan could not verify everything","One or more sensors were unavailable. Open BluePulse to restore visibility."]
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
        ${metric(title(pulseConfidence),"BluePulse","Detection confidence","pulse",pulseKind)}
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
  function renderRansomware() {
    if (!state.report) { $("#ransomware-content").innerHTML = empty("▣","No file-defense report yet","Run a scan to initialize protected-folder monitoring."); return; }
    const behavior = state.report.behavior || {};
    const sensor = ransomwareCheck(behavior) || {status:"unknown",message:"Ransomware sensor unavailable",details:{}};
    const details = sensor.details || {};
    const findings = (behavior.findings || []).filter(item => item.category === "ransomware").sort((a,b) => severityRank(b.severity)-severityRank(a.severity));
    const severe = findings.some(item => ["critical","high"].includes(item.severity));
    const warning = findings.length > 0 || sensor.status !== "healthy";
    const heroStatus = severe ? "unhealthy" : warning ? "degraded" : "healthy";
    const initialized = details.initialized === true;
    const headline = severe ? "Encryption-like activity needs review" : warning ? "File defense needs attention" : initialized ? "No encryption pattern detected" : "Protected-folder baseline is ready";
    const copy = severe ? "RATtler found multiple changes associated with ransomware. Review the evidence before taking manual action." : warning ? "Some monitoring coverage or file activity needs review." : "RATtler compared protected folders with the previous scan and found no ransomware pattern.";
    const changed = Number(details.modified_files || 0) + Number(details.created_files || 0) + Number(details.deleted_files || 0);
    const folders = Array.isArray(details.protected_folders) ? details.protected_folders : [];
    const canary = details.canary || "unknown";
    const signals = [
      {name:"canary_integrity",status:canary==="healthy"?"healthy":"unhealthy",message:canary==="healthy"?"The local ransomware decoy is intact.":`The local canary is ${canary}.`},
      {name:"rewrite_velocity",status:Number(details.modified_files||0)>=40?"degraded":"healthy",message:`${Number(details.modified_files||0)} protected files were rewritten since the previous scan.`},
      {name:"extension_churn",status:Number(details.extension_replacements||0)||Number(details.encrypted_names||0)>=5?"unhealthy":"healthy",message:`${Number(details.extension_replacements||0)} encryption-style replacements and ${Number(details.encrypted_names||0)} suspicious names.`},
      {name:"ransom_notes",status:Number(details.ransom_notes||0)?"unhealthy":"healthy",message:Number(details.ransom_notes||0)?`${Number(details.ransom_notes)} possible ransom note detected.`:"No new ransom-note filename was detected."}
    ];
    const indicatorList = findings.length ? findings.map(finding => `<div class="ransom-finding">${findingRow(finding)}${evidence(finding.evidence)}</div>`).join("") : `<div class="ransom-clear"><span>✓</span><div><strong>No active ransomware indicators</strong><p>Normal file changes can still occur; RATtler alerts only when a defined behavior threshold is crossed.</p></div></div>`;
    $("#ransomware-content").innerHTML = `
      <article class="panel ransom-hero ${esc(heroStatus)}"><div class="ransom-emblem">${icon("lock")}<i></i></div><div class="ransom-copy"><div class="status-kicker">${severe?"ACTION REQUIRED":warning?"REVIEW COVERAGE":"MONITORING"}</div><h2>${esc(headline)}</h2><p>${esc(copy)}</p><small>Detection observes changes while RATtler is open. Automatic write blocking is not enabled.</small></div><div class="ransom-sweep"><i></i></div></article>
      <div class="metrics ransom-metrics">
        ${metric(Number(details.monitored_files||0).toLocaleString(),"Files watched",folders.length?folders.join(", "):"Folder access needed","folder",sensor.status==="unknown"?"warning":"")}
        ${metric(changed,"Recent changes","Created, modified, or deleted","refresh",changed?"info":"")}
        ${metric(canary==="healthy"?"Intact":title(canary),"Canary","Tamper tripwire","shield",canary==="healthy"?"":"danger")}
        ${metric(findings.length,"Indicators",findings.length?"Review evidence":"No active pattern","alert",findings.length?"danger":"")}
      </div>
      <div class="ransom-layout">
        <article class="panel card-block"><div class="card-title"><div><h3>Ransomware signals</h3><p>Independent evidence checked on each scan</p></div><span>${esc(details.detection_mode||"snapshot monitoring")}</span></div>${signals.map(checkRow).join("")}</article>
        <article class="panel card-block"><div class="card-title"><div><h3>Protected folders</h3><p>Metadata only—RATtler does not upload file contents</p></div></div><div class="folder-pills">${folders.length?folders.map(folder=>`<span>${icon("folder")}${esc(folder)}</span>`).join(""):`<p>Desktop, Documents, and Pictures could not be read. Review macOS folder permissions.</p>`}</div><div class="ransom-limit"><strong>${details.limited?"PARTIAL COVERAGE":"BOUNDED COVERAGE"}</strong><span>Up to ${Number(details.max_files||0).toLocaleString()} files per scan</span></div></article>
      </div>
      <article class="panel card-block ransom-indicators"><div class="card-title"><div><h3>Current ransomware indicators</h3><p>Evidence is also available in Findings and the local Activity timeline</p></div><span>${findings.length} active</span></div>${indicatorList}</article>`;
    $$(".ransom-finding", $("#ransomware-content")).forEach(row => row.addEventListener("click", () => row.classList.toggle("expanded")));
  }
  function renderBluePulse() {
    if (!state.report) { $("#bluepulse-content").innerHTML = empty("⌁","No confidence report yet","Run a scan so BluePulse can verify each available layer."); return; }
    const protection = state.report.protection || {}, behavior = state.report.behavior || {};
    const pulse = pulseCheck(behavior) || { status:"unknown", message:"BluePulse data unavailable", details:{} };
    const details = pulse.details || {}, freshness = scanFreshness(state.report);
    const installed = state.capabilities.installed !== false;
    const decisiveStatus = ["unhealthy","unknown"].includes(pulse.status);
    const effectiveStatus = decisiveStatus ? pulse.status : !freshness.fresh || !installed ? "degraded" : pulse.status;
    const confidence = decisiveStatus ? details.confidence || "low" : !freshness.fresh || !installed ? "reduced" : details.confidence || "low";
    const headline = {healthy:"Sensors are reporting normally",degraded:"Detection confidence needs attention",unknown:"Detection confidence is incomplete",unhealthy:"A defensive layer is unhealthy"}[effectiveStatus] || "Detection confidence is incomplete";
    const explanation = effectiveStatus === "healthy" ? "BluePulse verified the available layers, event continuity, and local monitoring state behind this scan." : "Review the signals below before relying on a clean endpoint result.";
    const eventState = details.event_continuity || "not configured";
    const nativeState = details.native_telemetry || "not configured";
    const dropped = Number(details.native_dropped_events || 0);
    const artifactIssues = Array.isArray(details.artifact_issues) ? details.artifact_issues : [];
    const signals = [
      {name:"scan_freshness",status:freshness.fresh?"healthy":"degraded",message:freshness.fresh?"The current report is recent.":"The current report is older than 2½ minutes."},
      {name:"app_placement",status:installed?"healthy":"degraded",message:installed?"RATtler is running from Applications.":"Move RATtler into Applications and reopen it."},
      {name:"event_continuity",status:["healthy","not configured"].includes(eventState)?"healthy":eventState,message:eventState==="not configured"?"One-time snapshot mode; continuous event state is not enabled.":`Continuous event state is ${eventState}.`},
      {name:"local_state_protection",status:artifactIssues.length?"degraded":"healthy",message:artifactIssues.length?`${artifactIssues.length} local monitoring artifact needs review.`:`${Number(details.artifacts_checked || 0)} local monitoring artifacts passed permission checks.`},
      {name:"native_event_loss",status:nativeState==="not configured"?"healthy":dropped?"degraded":nativeState,message:nativeState==="not configured"?"Native telemetry is optional and not provisioned.":dropped?`${dropped} native events were dropped.`:"No native event loss was reported."}
    ];
    const behavioral = (behavior.sensors || []).filter(item => item.name !== "bluepulse");
    $("#bluepulse-content").innerHTML = `
      <article class="panel bluepulse-hero ${esc(effectiveStatus)}"><div class="pulse-orb"><span></span><i></i></div><div class="bluepulse-copy"><div class="status-kicker">${esc(confidence.toUpperCase())} CONFIDENCE</div><h2>${esc(headline)}</h2><p>${esc(explanation)}</p><small>Confidence describes visibility—not whether findings are safe or malicious.</small></div><div class="pulse-trace"><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div></article>
      <div class="sensor-summary">${metric(ageLabel(freshness.age),"Last scan",freshness.fresh?"Current":"Refresh recommended","clock",freshness.fresh?"":"warning")}${metric(`${Number(details.operational || 0)}/${Number(details.monitored || 0)}`,"Operational","Available layers","check",pulse.status==="healthy"?"":"warning")}${metric(title(details.monitoring_mode || "snapshot"),"Mode","Local monitoring","coverage","info")}</div>
      ${sensorGroup("Assurance signals", signals)}
      ${sensorGroup("Endpoint protection", protection.checks || [])}
      ${sensorGroup("Behavioral sensors", behavioral)}
      ${nativeCard()}`;
  }
  const sensorGroup = (heading,checks) => `<div class="sensor-group"><h3>${esc(heading)}</h3><div class="sensor-grid">${checks.map(check => `<article class="panel sensor-card">${checkRow(check)}</article>`).join("")}</div></div>`;
  const nativeCard = () => {
    const configured = state.capabilities.nativeEvents;
    const sensor = state.report?.behavior?.sensors?.find(item => item.name === "native_events");
    const connected = configured && sensor?.status === "healthy";
    const label = connected ? "CONNECTED" : configured ? "NEEDS ATTENTION" : "ENTITLEMENT PENDING";
    const copy = connected ? "RATtler is receiving a live collector heartbeat and Endpoint Security events." : configured ? "The native event stream exists, but its heartbeat or event continuity needs review in BluePulse." : "The collector is built, but Apple must approve its restricted entitlement before public live telemetry can connect.";
    return `<article class="panel native-card ${connected ? "connected" : ""}"><span class="native-symbol">${connected ? "◇" : "▣"}</span><div><h3>Endpoint Security telemetry <span class="native-state">${label}</span></h3><p>${copy}</p></div><a href="https://developer.apple.com/documentation/endpointsecurity">Apple documentation ↗</a></article>`;
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
  function renderAll() { renderDashboard(); renderFindings(); renderRansomware(); renderBluePulse(); renderActivity(); renderSettings(); renderChrome(); }
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
  const auto=$("#auto-scan"), storedAuto=localStorage.getItem("rattler-auto-scan"); auto.checked=storedAuto===null?true:storedAuto==="true"; const configureAuto=()=>{ clearInterval(state.autoTimer); state.autoTimer=null; if(auto.checked) state.autoTimer=setInterval(()=>native("scan"),60000); localStorage.setItem("rattler-auto-scan",auto.checked); }; auto.addEventListener("change",configureAuto); configureAuto();
  setInterval(()=>{ if ($("#bluepulse").classList.contains("active")) renderBluePulse(); },30000);
  native("capabilities");
})();
