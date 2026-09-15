(() => {
  "use strict";
  const state = { report: null, fileScan: null, detectionLab: null, quarantine: [], exceptions: [], capabilities: { baseline: false, nativeEvents: false, fileEvents: false, fileEventRoots: 0, yaraRules: false, detectionLab: false, recovery: false, recoveryFrozen: false, recoveryUpdating: false, recoveryError: false, installed: true, appPath: "", monitoringPaused: false, backgroundInterval: 60, menuBar: true, launchAtLogin: false, launchAtLoginStatus: "not registered", notificationsEnabled: false, version: "0.18.0" }, phase: "starting" };
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
  const fileEventCheck = behavior => (behavior?.sensors || []).find(item => item.name === "native_file_events");
  const persistenceCheck = behavior => (behavior?.sensors || []).find(item => item.name === "persistence_atlas");
  const operationCheck = behavior => (behavior?.sensors || []).find(item => item.name === "continuous_operation");
  const scanFreshness = report => {
    if (document.documentElement.classList.contains("snapshot")) return { fresh:true, age:0 };
    const observed = Date.parse(report?.observed_at || "");
    const age = Date.now() - observed;
    return { fresh: Number.isFinite(age) && age >= 0 && age <= 150000, age };
  };
  const ageLabel = age => !Number.isFinite(age) ? "Unknown" : age < 60000 ? "Just now" : `${Math.floor(age / 60000)} min ago`;
  const byteLabel = value => { const size=Number(value||0); if(size<1024)return `${size} B`; if(size<1048576)return `${(size/1024).toFixed(1)} KB`; if(size<1073741824)return `${(size/1048576).toFixed(1)} MB`; return `${(size/1073741824).toFixed(1)} GB`; };
  const combinedStatus = checks => {
    const statuses = checks.filter(Boolean).map(check => check.status || "unknown");
    return ["unhealthy","unknown","degraded","healthy"].find(status => statuses.includes(status)) || "unknown";
  };

  function endpointLayers(report) {
    const protection = report.protection || {}, behavior = report.behavior || {};
    const sensors = behavior.sensors || [], sensor = name => sensors.find(item => item.name === name);
    const findings = behavior.findings || [];
    const layerFindings = categories => findings.filter(item => categories.includes(item.category));
    const layerStatus = (checks,categories) => {
      const matches = layerFindings(categories);
      if (matches.some(item => ["critical","high"].includes(item.severity))) return "unhealthy";
      if (matches.length) return "degraded";
      return combinedStatus(checks);
    };
    const processes = sensor("processes"), listeners = sensor("listeners"), atlas = sensor("persistence_atlas") || sensor("persistence");
    const ransomware = sensor("ransomware"), fileEvents = sensor("native_file_events"), pulse = sensor("bluepulse"), loaded = sensor("loaded_images");
    const protectionChecks = protection.checks || [], fileChecks = [ransomware,fileEvents].filter(Boolean);
    const protectedCount = protectionChecks.filter(check => check.status === "healthy").length;
    const fileDetails = ransomware?.details || {}, eventDetails = fileEvents?.details || {}, pulseDetails = pulse?.details || {}, atlasDetails = atlas?.details || {};
    return [
      {id:"protection",label:"Platform protection",short:"Protection",icon:"shield",view:"bluepulse",status:combinedStatus(protectionChecks),message:`${protectedCount} of ${protectionChecks.length} built-in protection checks are healthy.`,facts:[["Provider",protection.provider||"Unknown"],["Healthy",`${protectedCount}/${protectionChecks.length}`],["Host",protection.hostname||"This Mac"]]},
      {id:"processes",label:"Process activity",short:"Processes",icon:"pulse",view:"findings",status:layerStatus([processes,loaded].filter(Boolean),["process","injection"]),message:layerFindings(["process","injection"]).length?`${layerFindings(["process","injection"]).length} process or loaded-code indicator${layerFindings(["process","injection"]).length===1?"":"s"} require review.`:processes?.message||"Process inventory is unavailable.",facts:[["Observed",Number(processes?.details?.count||0).toLocaleString()],["Loaded mappings",Number(loaded?.details?.mappings||0).toLocaleString()],["Findings",String(layerFindings(["process","injection"]).length)]]},
      {id:"network",label:"Network exposure",short:"Network",icon:"coverage",view:"findings",status:layerStatus([listeners].filter(Boolean),["network"]),message:layerFindings(["network"]).length?`${layerFindings(["network"]).length} network indicator${layerFindings(["network"]).length===1?"":"s"} require review.`:listeners?.message||"Network listener coverage is unavailable.",facts:[["Listeners",Number(listeners?.details?.count||0).toLocaleString()],["Activity",String((behavior.events||[]).filter(item=>String(item.event_type||"").includes("connection")).length)],["Findings",String(layerFindings(["network"]).length)]]},
      {id:"persistence",label:"Persistence Atlas",short:"Persistence",icon:"atlas",view:"persistence",status:layerStatus([atlas].filter(Boolean),["persistence"]),message:layerFindings(["persistence"]).length?`${layerFindings(["persistence"]).length} persistence indicator${layerFindings(["persistence"]).length===1?"":"s"} require review.`:atlas?.message||"Persistence coverage is unavailable.",facts:[["Sources",`${Number(atlasDetails.sources_healthy||0)}/${Number(atlasDetails.sources_checked||0)}`],["Objects",Number(atlasDetails.items||atlas?.details?.count||0).toLocaleString()],["Findings",String(layerFindings(["persistence"]).length)]]},
      {id:"files",label:"File defense",short:"Files",icon:"lock",view:"ransomware",status:layerStatus(fileChecks,["ransomware"]),message:layerFindings(["ransomware"]).length?`${layerFindings(["ransomware"]).length} ransomware indicator${layerFindings(["ransomware"]).length===1?"":"s"} require review.`:fileEvents?.status==="healthy"?"FSEvents is triggering bounded ransomware snapshots.":fileEvents?.message||ransomware?.message||"File-defense coverage is unavailable.",facts:[["Files watched",Number(fileDetails.monitored_files||0).toLocaleString()],["Native events",Number(eventDetails.events_seen||0).toLocaleString()],["Findings",String(layerFindings(["ransomware"]).length)]]},
      {id:"confidence",label:"BluePulse confidence",short:"BluePulse",icon:"check",view:"bluepulse",status:pulse?.status||"unknown",message:pulse?.message||"Detection confidence is unavailable.",facts:[["Confidence",title(pulseDetails.confidence||"unknown")],["Operational",`${Number(pulseDetails.operational||0)}/${Number(pulseDetails.monitored||0)}`],["Coverage gaps",String((pulseDetails.coverage_gaps||[]).length)]]}
    ];
  }

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
    const layers = endpointLayers(report), initialLayer = layers.findIndex(item => item.id === "files");
    const layerNodes = layers.map((item,index)=>`<button class="topology-node node-${index} ${esc(item.status)}" data-layer="${index}" aria-label="Inspect ${esc(item.label)}" aria-pressed="false"><span>${icon(item.icon)}</span><strong>${esc(item.short)}</strong><i></i></button>`).join("");
    const rays = layers.map((_,index)=>`<i class="map-ray ray-${index}"></i>`).join("");
    $("#dashboard-content").className = "";
    $("#dashboard-content").innerHTML = `
      <article class="panel hero ${esc(report.status)}"><div class="shield-orbit"></div><div class="hero-copy"><div class="status-kicker">${esc(statusLabel(report.status).toUpperCase())}</div><h2>${esc(heroCopy[0])}</h2><p>${esc(heroCopy[1])}</p><div class="hostline">▣ ${esc(protection.hostname || "This Mac")} &nbsp;•&nbsp; ${esc(observed)}</div></div><button class="scan-button dashboard-scan"><span>↻</span>Scan now</button></article>${installNotice}
      <div class="metrics">
        ${metric(findings.length,"Findings",findings.length ? "Review recommended" : "No active indicators","alert",findings.length ? "warning" : "")}
        ${metric(high,"High priority","Critical and high","shield",high ? "danger" : "")}
        ${metric(title(pulseConfidence),"BluePulse","Detection confidence","pulse",pulseKind)}
        ${metric((behavior.events || []).length,"Activity","Recent correlated events","clock","info")}
      </div>
      <article class="panel topology-panel"><div class="topology-head"><div><small>LIVE ENDPOINT MODEL</small><h3>Interactive defense overview</h3><p>Select a sensor layer to inspect current evidence.</p></div><span><i></i>${state.capabilities.monitoringPaused?"PAUSED":"LOCAL · LIVE"}</span></div><div class="topology-layout"><div class="endpoint-stage" tabindex="0" aria-label="Interactive three-dimensional endpoint sensor map"><div class="endpoint-scene"><div class="map-ring ring-a"></div><div class="map-ring ring-b"></div><div class="map-ring ring-c"></div><div class="map-rays">${rays}</div><div class="map-core ${esc(report.status)}"><b>R</b><span>${esc(statusLabel(report.status))}</span></div>${layerNodes}<div class="map-shadow"></div></div></div><aside id="topology-inspector" class="topology-inspector"><div id="topology-kicker" class="status-kicker"></div><h4 id="topology-name"></h4><p id="topology-message"></p><dl id="topology-facts"></dl><button id="topology-open" class="quiet-button">Open details →</button></aside></div></article>
      <div class="dashboard-grid"><article class="panel card-block"><div class="card-title"><div><h3>Priority findings</h3><p>Indicators that deserve attention first</p></div><span>${findings.length} total</span></div>${priority}</article><article class="panel card-block"><div class="card-title"><div><h3>Sensor coverage</h3><p>Latest health by layer</p></div></div>${coverage}${nativeNotice}</article></div>`;
    $(".dashboard-scan")?.addEventListener("click", () => native("scan"));
    $("#show-app-button")?.addEventListener("click", () => native("revealApp"));
    const stage = $(".endpoint-stage"), scene = $(".endpoint-scene");
    const selectLayer = index => {
      const item = layers[index] || layers[0], inspector = $("#topology-inspector");
      $$(".topology-node",stage).forEach((node,nodeIndex)=>{node.classList.toggle("selected",nodeIndex===index);node.setAttribute("aria-pressed",nodeIndex===index?"true":"false");});
      inspector.className=`topology-inspector ${item.status}`;
      $("#topology-kicker").textContent=statusLabel(item.status).toUpperCase();
      $("#topology-name").textContent=item.label;
      $("#topology-message").textContent=item.message;
      $("#topology-facts").innerHTML=item.facts.map(([key,value])=>`<div><dt>${esc(key)}</dt><dd>${esc(value)}</dd></div>`).join("");
      $("#topology-open").dataset.view=item.view;
    };
    $$(".topology-node",stage).forEach(node=>node.addEventListener("click",()=>selectLayer(Number(node.dataset.layer))));
    $("#topology-open")?.addEventListener("click",event=>document.querySelector(`[data-view="${event.currentTarget.dataset.view}"]`)?.click());
    if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      stage?.addEventListener("pointermove",event=>{const rect=stage.getBoundingClientRect(),x=(event.clientX-rect.left)/rect.width-.5,y=(event.clientY-rect.top)/rect.height-.5;scene.style.setProperty("--scene-x",`${-10-y*10}deg`);scene.style.setProperty("--scene-y",`${x*16}deg`);});
      stage?.addEventListener("pointerleave",()=>{scene.style.setProperty("--scene-x","-10deg");scene.style.setProperty("--scene-y","0deg");});
    }
    selectLayer(initialLayer < 0 ? 0 : initialLayer);
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
      const exception = exceptionCandidate(finding);
      const actions = [
        exception ? `<button class="exception-button" data-exception-index="${index}">Ignore 30 days</button>` : "",
        candidate ? `<button class="quarantine-button" data-path="${esc(candidate)}" data-rule="${esc(finding.rule_id)}">Review quarantine</button>` : ""
      ].join("");
      const response = actions ? `<div class="response-action"><span>Reviewed actions</span>${actions}</div>` : "";
      return `<article class="panel finding-card" data-index="${index}">${findingRow(finding)}${response}${evidence(finding.evidence)}</article>`;
    }).join("");
    $$(".finding-card", $("#findings-list")).forEach(card => card.addEventListener("click", event => { if (!event.target.closest("button")) card.classList.toggle("expanded"); }));
    $$(".quarantine-button", $("#findings-list")).forEach(button => button.addEventListener("click", () => native("quarantine", { path: button.dataset.path, ruleId: button.dataset.rule })));
    $$(".exception-button", $("#findings-list")).forEach(button => button.addEventListener("click", () => {
      const candidate = exceptionCandidate(findings[Number(button.dataset.exceptionIndex)]);
      if (candidate) native("addException", { exception:candidate });
    }));
  }
  const responseCandidate = finding => {
    const values = finding?.evidence || {};
    for (const key of ["image", "executable", "actor_path", "path", "plist"]) {
      const value = values[key];
      if (typeof value === "string" && value.startsWith("/") && !value.endsWith(" (deleted)")) return value;
    }
    return null;
  };
  const exceptionCandidate = finding => {
    const values = finding?.evidence || {}, path = responseCandidate(finding);
    if (!path) return null;
    const first = keys => keys.map(key => values[key]).find(value => typeof value === "string" && value.length);
    const cdhash = first(["cdhash","current_cdhash","module_cdhash","actor_cdhash","target_cdhash"]);
    const sha256 = first(["sha256","current_sha256"]);
    const teamId = first(["team_id","module_team_id","actor_team_id","target_team_id"]);
    const identifier = first(["identifier","module_identifier","actor_identifier","target_identifier"]);
    if (!cdhash && !sha256 && !(teamId && identifier)) return null;
    return { ruleId:finding.rule_id, path, cdhash, sha256, teamId, identifier };
  };
  function renderFileScan() {
    const scan = state.fileScan;
    if (!scan) {
      $("#file-scan-content").innerHTML = `
        <article class="panel deep-scan-start"><div class="deep-scan-emblem">${icon("scan")}<i></i></div><div><div class="status-kicker">ON-DEMAND · LOCAL ONLY</div><h2>Choose what you want RATtler to inspect</h2><p>Deep Scan reads selected file contents locally to calculate SHA-256, apply bundled YARA rules, validate Mach-O signing, and explain suspicious file traits. Nothing is uploaded.</p><small>2,000 files · 64 MB per file · 512 MB total · 120 seconds · symbolic links are not followed</small></div><button id="choose-file-scan" class="scan-button">Choose file or folder</button></article>
        <div class="deep-scan-principles"><article class="panel"><strong>Evidence, not labels</strong><p>Heuristic matches are shown as review signals. A match is not automatically called malware.</p></article><article class="panel"><strong>Bounded against hostile input</strong><p>File counts, bytes, recursion, YARA runtime, output, and errors all have explicit limits.</p></article><article class="panel"><strong>Exact response identity</strong><p>Quarantine and temporary exceptions remain bound to the reviewed file hash.</p></article></div>`;
      $("#choose-file-scan")?.addEventListener("click",()=>native("selectFileScan"));
      return;
    }
    const summary=scan.summary||{}, check=scan.check||{status:"unknown",message:"Coverage unavailable",details:{}}, findings=[...(scan.findings||[])].sort((a,b)=>severityRank(b.severity)-severityRank(a.severity));
    const stateClass=scan.status==="risk"?"unhealthy":scan.status==="review"?"degraded":"healthy";
    const headline=scan.status==="risk"?"Deep Scan found high-priority evidence":scan.status==="review"?"Deep Scan found items to review":"No rule or static indicator matched";
    const coverage=check.status==="healthy"?"YARA and static inspection completed within their safety budgets.":check.message;
    const findingList=findings.length?findings.map((finding,index)=>{
      const candidate=responseCandidate(finding), identity=exceptionCandidate(finding);
      const controls=`<div class="response-action"><span>Exact-hash actions</span>${identity?`<button class="exception-button scan-exception" data-index="${index}">Ignore 30 days</button>`:""}${candidate&&["critical","high"].includes(finding.severity)?`<button class="quarantine-button scan-quarantine" data-index="${index}">Review quarantine</button>`:""}</div>`;
      return `<article class="panel finding-card expanded">${findingRow(finding)}${controls}${evidence(finding.evidence)}</article>`;
    }).join(""):`<div class="ransom-clear"><span>✓</span><div><strong>No active file indicators</strong><p>RATtler did not find a bundled rule match or static trait above its review threshold.</p></div></div>`;
    const files=(scan.files||[]).slice(0,50).map(file=>`<div class="scan-file-row"><div><strong title="${esc(file.path)}">${esc(file.path)}</strong><small>${esc(String(file.sha256||"").slice(0,20))}… · ${byteLabel(file.size)} · entropy ${esc(file.entropy)}</small></div><span class="${Number(file.finding_count)>0?"warning":""}">${Number(file.finding_count)>0?`${file.finding_count} signal${file.finding_count===1?"":"s"}`:"CLEAR"}</span></div>`).join("");
    $("#file-scan-content").innerHTML=`
      <article class="panel hero ${esc(stateClass)} deep-scan-hero"><div class="shield-orbit"></div><div class="hero-copy"><div class="status-kicker">${esc(scan.status.toUpperCase())}</div><h2>${esc(headline)}</h2><p>${esc(coverage)}</p><div class="hostline">${esc(scan.target)}</div></div><button id="choose-file-scan" class="scan-button">Scan another target</button></article>
      <div class="metrics">${metric(Number(summary.scanned_files||0).toLocaleString(),"Files scanned",summary.limited?"Safety limit reached":"Bounded inspection","folder",summary.limited?"warning":"")}${metric(summary.yara_rules||0,"YARA files",check.details?.yara_error||"Bundled local rules","scan",check.details?.yara_error?"warning":"info")}${metric(findings.length,"Findings",findings.length?"Review evidence":"No active match","alert",findings.length?"danger":"")}${metric(byteLabel(summary.bytes_read),"Content read","Never uploaded","lock","")}</div>
      ${check.status!=="healthy"?`<div class="notice warning"><span>△</span><div><strong>Partial scan coverage</strong><p>${esc(check.message)}${check.details?.yara_error?` ${esc(check.details.yara_error)}`:""}</p></div></div>`:""}
      <div class="deep-scan-grid"><article class="scan-findings"><div class="card-title"><div><h3>File findings</h3><p>Rule matches and independently explainable traits</p></div><span>${findings.length} total</span></div>${findingList}</article><article class="panel card-block"><div class="card-title"><div><h3>Inspected files</h3><p>Showing up to 50 local records</p></div><span>${Number(summary.reported_files||0)} retained</span></div><div class="scan-file-list">${files||"<span>No readable files were retained.</span>"}</div></article></div>`;
    $("#choose-file-scan")?.addEventListener("click",()=>native("selectFileScan"));
    $$(".scan-quarantine").forEach(button=>button.addEventListener("click",()=>{const candidate=responseCandidate(findings[Number(button.dataset.index)]);if(candidate)native("quarantine",{path:candidate,ruleId:findings[Number(button.dataset.index)].rule_id,fileScan:true});}));
    $$(".scan-exception").forEach(button=>button.addEventListener("click",()=>{const candidate=exceptionCandidate(findings[Number(button.dataset.index)]);if(candidate)native("addException",{exception:candidate,fileScan:true});}));
  }
  function renderDetectionLab() {
    const target = $("#detection-lab-content"), lab = state.detectionLab;
    if (!lab) {
      target.innerHTML = `<article class="panel lab-start"><div class="lab-orb">${icon("lab")}<i></i></div><div><div class="status-kicker">SAFE · REPRODUCIBLE · LOCAL</div><h2>Turn detection claims into tests</h2><p>ReplayForge feeds versioned synthetic event metadata through RATtler’s production correlators. Chainlight then assembles related evidence into a stable, time-ordered chain.</p><small>No programs launch · no payloads · strict fixture limits · positive and negative tests</small></div><button id="run-lab-button" class="scan-button">Run bundled suite</button></article><div class="deep-scan-principles"><article class="panel"><strong>Same detection logic</strong><p>Fixtures exercise the correlation functions used by endpoint scans, preventing a separate demo-only path.</p></article><article class="panel"><strong>Regression budgets</strong><p>Expected rule IDs, chain counts, and runtime budgets are machine-readable and enforced in CI.</p></article><article class="panel"><strong>Community-ready evidence</strong><p>Stable IDs and privacy-tokenized bundles make review reproducible. ATT&amp;CK coverage context is not a verdict.</p></article></div>`;
      $("#run-lab-button")?.addEventListener("click",()=>native("runDetectionLab"));
      return;
    }
    const summary=lab.summary||{}, results=lab.results||[], passed=lab.status==="passed";
    const allChains=results.flatMap(result=>result.chains||[]), allAssertions=results.flatMap(result=>result.assertions||[]);
    const fixtures=results.map(result=>{const fixture=result.fixture||{}, ok=result.status==="passed", assertions=result.assertions||[];return `<article class="panel lab-fixture ${ok?"passed":"failed"}"><div class="lab-fixture-head"><span>${ok?"✓":"×"}</span><div><strong>${esc(fixture.title)}</strong><small>${esc(fixture.id)} · ${esc(fixture.safety)}</small></div><em>${ok?"PASS":"FAIL"}</em></div><p>${esc(fixture.description)}</p><div class="assertion-strip">${assertions.map(item=>`<span class="${item.passed?"":"failed"}">${item.passed?"✓":"×"} ${esc(title(item.name))}</span>`).join("")}</div></article>`;}).join("");
    const chains=allChains.length?allChains.map(chain=>`<article class="panel chain-card"><div class="chain-head"><div><div class="status-kicker">${esc(chain.severity.toUpperCase())} CHAIN</div><strong>${esc(chain.chain_id)}</strong></div><span>${chain.nodes.length} events · ${chain.rule_ids.length} rules</span></div><div class="chain-track">${chain.nodes.map((node,index)=>`<div class="chain-node ${esc(node.severity)}"><i>${index+1}</i><div><strong>${esc(title(node.event_type))}</strong><small>${esc(node.summary)}</small><em>${esc(node.event_id)}</em></div></div>`).join("")}</div><div class="technique-row">${(chain.techniques||[]).map(item=>`<span>${esc(item.id)} · ${esc(item.name)}</span>`).join("")||"<small>No high-confidence ATT&CK mapping for this chain.</small>"}<em>${esc(chain.attack_mapping_notice)}</em></div></article>`).join(""):`<div class="ransom-clear"><span>✓</span><div><strong>Negative fixture stayed quiet</strong><p>No attack chain was created where the expected rule set was empty.</p></div></div>`;
    target.innerHTML=`<article class="panel lab-hero ${passed?"passed":"failed"}"><div class="lab-orb">${icon("lab")}<i></i></div><div><div class="status-kicker">${passed?"ALL ASSERTIONS PASSED":"REGRESSION FOUND"}</div><h2>${passed?"The bundled detections reproduced cleanly":"A detection contract changed"}</h2><p>${passed?"ReplayForge completed every positive, negative, chain, and performance assertion.":"Review the failed fixture before accepting a rule change."}</p><small>Fixtures contain synthetic metadata only—no executable content.</small></div><button id="run-lab-button" class="scan-button">Run again</button></article><div class="metrics">${metric(summary.fixtures||0,"Fixtures",`${summary.passed||0} passed`,"lab",passed?"":"danger")}${metric(allAssertions.length,"Assertions",allAssertions.every(item=>item.passed)?"All contracts held":"Review failures","check",passed?"":"danger")}${metric(summary.findings||0,"Expected findings","Production correlators","shield","info")}${metric(summary.chains||0,"Attack chains","Stable evidence links","pulse","info")}</div><div class="lab-layout"><div><div class="card-title"><div><h3>Fixture results</h3><p>Positive and negative community detection contracts</p></div><span>${results.length} fixtures</span></div>${fixtures}</div><div><div class="card-title"><div><h3>Chainlight</h3><p>Time-ordered evidence with conservative ATT&amp;CK context</p></div><span>${allChains.length} chains</span></div>${chains}</div></div>`;
    $("#run-lab-button")?.addEventListener("click",()=>native("runDetectionLab"));
  }
  function renderRansomware() {
    if (!state.report) { $("#ransomware-content").innerHTML = empty("▣","No file-defense report yet","Run a scan to initialize protected-folder monitoring."); return; }
    const behavior = state.report.behavior || {};
    const sensor = ransomwareCheck(behavior) || {status:"unknown",message:"Ransomware sensor unavailable",details:{}};
    const fileEvents = fileEventCheck(behavior) || {status:"unknown",message:"Protected-folder event trigger unavailable",details:{}};
    const recoverySensor = (behavior.sensors || []).find(item => item.name === "recovery_vault");
    const details = sensor.details || {};
    const findings = (behavior.findings || []).filter(item => item.category === "ransomware").sort((a,b) => severityRank(b.severity)-severityRank(a.severity));
    const severe = findings.some(item => ["critical","high"].includes(item.severity));
    const warning = findings.length > 0 || sensor.status !== "healthy" || fileEvents.status !== "healthy";
    const heroStatus = severe ? "unhealthy" : warning ? "degraded" : "healthy";
    const initialized = details.initialized === true;
    const headline = severe ? "Encryption-like activity needs review" : warning ? "File defense needs attention" : initialized ? "No encryption pattern detected" : "Protected-folder baseline is ready";
    const copy = severe ? "RATtler found multiple changes associated with ransomware. Review the evidence before taking manual action." : warning ? "Some monitoring coverage or file activity needs review." : "RATtler compared protected folders with the previous scan and found no ransomware pattern.";
    const changed = Number(details.modified_files || 0) + Number(details.created_files || 0) + Number(details.deleted_files || 0);
    const folders = Array.isArray(details.protected_folders) ? details.protected_folders : [];
    const canary = details.canary || "unknown";
    const signals = [
      {name:"live_event_trigger",status:fileEvents.status,message:fileEvents.status==="healthy"?`${Number(fileEvents.details?.roots_watched||0)} protected folders trigger a bounded snapshot within seconds.`:fileEvents.message},
      {name:"canary_integrity",status:canary==="healthy"?"healthy":"unhealthy",message:canary==="healthy"?"The local ransomware decoy is intact.":`The local canary is ${canary}.`},
      {name:"rewrite_velocity",status:Number(details.modified_files||0)>=40?"degraded":"healthy",message:`${Number(details.modified_files||0)} protected files were rewritten since the previous scan.`},
      {name:"extension_churn",status:Number(details.extension_replacements||0)||Number(details.encrypted_names||0)>=5?"unhealthy":"healthy",message:`${Number(details.extension_replacements||0)} encryption-style replacements and ${Number(details.encrypted_names||0)} suspicious names.`},
      {name:"ransom_notes",status:Number(details.ransom_notes||0)?"unhealthy":"healthy",message:Number(details.ransom_notes||0)?`${Number(details.ransom_notes)} possible ransom note detected.`:"No new ransom-note filename was detected."}
    ];
    const indicatorList = findings.length ? findings.map(finding => `<div class="ransom-finding">${findingRow(finding)}${evidence(finding.evidence)}</div>`).join("") : `<div class="ransom-clear"><span>✓</span><div><strong>No active ransomware indicators</strong><p>Normal file changes can still occur; RATtler alerts only when a defined behavior threshold is crossed.</p></div></div>`;
    const recoveryEnabled = state.capabilities.recovery === true;
    const recoveryFrozen = state.capabilities.recoveryFrozen === true;
    const recoveryUpdating = state.capabilities.recoveryUpdating === true;
    const recoveryError = state.capabilities.recoveryError === true;
    const recoveryDetails = recoverySensor?.details || {};
    const recoveryHeadline = recoveryFrozen ? "Clean recovery versions are frozen" : recoveryUpdating ? recoveryEnabled?"Recovery Vault is refreshing":"Recovery Vault is being created" : !recoveryEnabled ? "Recovery Vault is off" : recoveryError ? "Recovery Vault needs attention" : "Recovery Vault is active";
    const recoveryCopy = recoveryFrozen ? recoveryEnabled?"RATtler stopped adding versions after ransomware evidence so known-good copies are not aged out.":"Recovery setup stopped before publishing a manifest because ransomware evidence appeared." : recoveryUpdating ? "Detection remains active while clean document and photo versions refresh in the background." : !recoveryEnabled ? "Opt in to keep quota-limited, versioned copies of common documents and photos entirely on this Mac." : recoveryError ? "The latest automatic backup failed. Open the vault and run another scan after checking free space and folder access." : `${Number(recoveryDetails.recoverable_files||0).toLocaleString()} files have protected versions. Backups refresh automatically while RATtler is open.`;
    const recoveryActions = recoveryUpdating ? `<button id="reveal-recovery-button" class="quiet-button">Open vault</button>` : !recoveryEnabled&&!recoveryFrozen ? `<button id="enable-recovery-button" class="quiet-button primary">Enable vault</button>` : `${recoveryEnabled&&(severe||recoveryFrozen)?`<button id="recover-files-button" class="quiet-button primary">Recover copies</button>`:""}<button id="reveal-recovery-button" class="quiet-button">Open vault</button>${recoveryFrozen?`<button id="resume-recovery-button" class="quiet-button warning">${recoveryEnabled?"Resume backups":"Clear freeze"}</button>`:""}`;
    $("#ransomware-content").innerHTML = `
      <article class="panel ransom-hero ${esc(heroStatus)}"><div class="ransom-emblem">${icon("lock")}<i></i></div><div class="ransom-copy"><div class="status-kicker">${severe?"ACTION REQUIRED":warning?"REVIEW COVERAGE":"MONITORING"}</div><h2>${esc(headline)}</h2><p>${esc(copy)}</p><small>FSEvents trigger snapshots within seconds while RATtler is running. Automatic write blocking is not enabled.</small></div><div class="ransom-sweep"><i></i></div></article>
      <div class="metrics ransom-metrics">
        ${metric(Number(details.monitored_files||0).toLocaleString(),"Files watched",folders.length?folders.join(", "):"Folder access needed","folder",sensor.status==="unknown"?"warning":"")}
        ${metric(changed,"Recent changes","Created, modified, or deleted","refresh",changed?"info":"")}
        ${metric(canary==="healthy"?"Intact":title(canary),"Canary","Tamper tripwire","shield",canary==="healthy"?"":"danger")}
        ${metric(findings.length,"Indicators",findings.length?"Review evidence":"No active pattern","alert",findings.length?"danger":"")}
      </div>
      <div class="ransom-layout">
        <article class="panel card-block"><div class="card-title"><div><h3>Ransomware signals</h3><p>Independent evidence checked on each triggered scan</p></div><span>${fileEvents.status==="healthy"?"FSEvents + snapshots":esc(details.detection_mode||"snapshot monitoring")}</span></div>${signals.map(checkRow).join("")}</article>
        <article class="panel card-block"><div class="card-title"><div><h3>Protected folders</h3><p>Metadata only—RATtler does not upload file contents</p></div></div><div class="folder-pills">${folders.length?folders.map(folder=>`<span>${icon("folder")}${esc(folder)}</span>`).join(""):`<p>Desktop, Documents, and Pictures could not be read. Review macOS folder permissions.</p>`}</div><div class="ransom-limit"><strong>${details.limited?"PARTIAL COVERAGE":"BOUNDED COVERAGE"}</strong><span>Up to ${Number(details.max_files||0).toLocaleString()} files per scan</span></div></article>
      </div>
      <article class="panel recovery-card ${recoveryFrozen||recoveryError?"frozen":recoveryEnabled||recoveryUpdating?"active":""}"><span class="recovery-symbol">${icon("shield")}</span><div><div class="status-kicker">${recoveryFrozen?"VAULT FROZEN":recoveryUpdating?"BACKGROUND REFRESH":!recoveryEnabled?"OPT-IN RECOVERY":recoveryError?"BACKUP ERROR":"VERSIONED LOCALLY"}</div><h3>${esc(recoveryHeadline)}</h3><p>${esc(recoveryCopy)}</p><small>Detection runs first · 512 MB quota · recovery never overwrites originals</small></div><div class="recovery-actions">${recoveryActions}</div></article>
      <article class="panel card-block ransom-indicators"><div class="card-title"><div><h3>Current ransomware indicators</h3><p>Evidence is also available in Findings and the local Activity timeline</p></div><span>${findings.length} active</span></div>${indicatorList}</article>`;
    $$(".ransom-finding", $("#ransomware-content")).forEach(row => row.addEventListener("click", () => row.classList.toggle("expanded")));
    $("#enable-recovery-button")?.addEventListener("click",()=>native("enableRecovery"));
    $("#recover-files-button")?.addEventListener("click",()=>native("recoverFiles"));
    $("#reveal-recovery-button")?.addEventListener("click",()=>native("revealRecovery"));
    $("#resume-recovery-button")?.addEventListener("click",()=>native("resumeRecovery"));
  }
  function renderPersistence() {
    const target = $("#persistence-content");
    if (!state.report) { target.innerHTML = empty("◎","No persistence map yet","Run a scan to inventory macOS autostart and security-drift sources."); return; }
    const behavior = state.report.behavior || {};
    const sensor = persistenceCheck(behavior) || {status:"unknown",message:"Persistence Atlas unavailable",details:{}};
    const details = sensor.details || {}, sources = Array.isArray(details.sources) ? details.sources : [];
    const findings = (behavior.findings || []).filter(item => item.category === "persistence").sort((a,b)=>severityRank(b.severity)-severityRank(a.severity));
    const urgent = findings.some(item => ["critical","high"].includes(item.severity));
    const heroStatus = urgent ? "unhealthy" : findings.length || sensor.status !== "healthy" ? "degraded" : "healthy";
    const headline = urgent ? "A persistence path needs investigation" : findings.length ? "Persistence changes need review" : sensor.status === "healthy" ? "Autostart surfaces are mapped" : "Some persistence sources are unavailable";
    const copy = urgent ? "RATtler found a high-confidence ownership, permission, signing, preload, or staging-path signal." : sensor.status === "healthy" ? "Every supported source reported independently, and no persistence rule crossed its alert threshold." : "Available sources remain visible; denied or limited sources are named instead of silently treated as clean.";
    const sourceCards = sources.map(source => {
      const sourceStatus = source.status || "unknown", count = Number(source.count || 0);
      const suffix = source.limited ? " · safety limit reached" : Array.isArray(source.errors) && source.errors.length ? ` · ${source.errors.length} coverage gap${source.errors.length===1?"":"s"}` : "";
      return `<article class="panel atlas-source ${esc(sourceStatus)}"><div class="atlas-source-head"><span>${sourceStatus === "healthy" ? "✓" : "!"}</span><div><strong>${esc(source.label || title(source.id))}</strong><small>${count.toLocaleString()} object${count===1?"":"s"}${esc(suffix)}</small></div><em>${esc(sourceStatus.toUpperCase())}</em></div><p>${esc(source.message || "Source state unavailable")}</p></article>`;
    }).join("");
    const objects = sources.flatMap(source => (source.items || []).map(item => ({...item, sourceLabel:source.label || title(source.id)}))).slice(0,10);
    const objectRows = objects.map(item => {
      const rawPath = typeof item.path === "string" ? item.path : "";
      const name = item.name || (rawPath ? rawPath.split("/").filter(Boolean).pop() : title(item.kind));
      const context = [item.sourceLabel, item.version ? `v${item.version}` : "", item.signature ? title(item.signature) : "", item.mode ? `mode ${item.mode}` : ""].filter(Boolean).join(" · ");
      return `<div class="atlas-object"><span>${icon(item.kind === "login_item" ? "refresh" : item.source === "browser_extensions" ? "coverage" : "folder")}</span><div><strong>${esc(name)}</strong><small>${esc(context)}</small></div><em>${item.symbolic_link ? "LINK" : item.signature_valid === false ? "REVIEW" : "OBSERVED"}</em></div>`;
    }).join("");
    const alertRows = findings.length ? findings.slice(0,4).map(finding => `<div class="atlas-finding">${findingRow(finding)}${evidence(finding.evidence)}</div>`).join("") : `<div class="ransom-clear"><span>✓</span><div><strong>No persistence alerts</strong><p>Installed profiles, extensions, and autostart entries are inventory context—not automatic malware labels.</p></div></div>`;
    target.innerHTML = `
      <article class="panel atlas-hero ${esc(heroStatus)}"><div class="atlas-orbit"><i></i><b></b><span>${icon("atlas")}</span></div><div><div class="status-kicker">${heroStatus === "healthy" ? "SOURCE-AWARE COVERAGE" : urgent ? "ACTION REQUIRED" : "PARTIAL COVERAGE"}</div><h2>${esc(headline)}</h2><p>${esc(copy)}</p><small>Bounded locally · symbolic links are never followed · each source can degrade independently</small></div><div class="atlas-radar"><i></i><i></i><i></i><span></span></div></article>
      <div class="metrics atlas-metrics">${metric(`${Number(details.sources_healthy||0)}/${Number(details.sources_checked||sources.length)}`,"Sources healthy","Independent collectors","check",sensor.status==="healthy"?"":"warning")}${metric(Number(details.items||0).toLocaleString(),"Objects mapped","Bounded inventory","atlas","info")}${metric(Number(details.baseline_assets||0).toLocaleString(),"Drift anchors","Eligible for hashing","shield","")}${metric(findings.length,"Alerts",findings.length?"Review evidence":"No active signal","alert",findings.length?"danger":"")}</div>
      <div class="atlas-layout"><div><div class="card-title"><div><h3>Source coverage</h3><p>One denied permission cannot hide the other collectors</p></div><span>${sources.length} sources</span></div><div class="atlas-source-grid">${sourceCards || empty("◎","No source detail","This report predates Persistence Atlas.")}</div></div><article class="panel card-block"><div class="card-title"><div><h3>Observed objects</h3><p>A compact preview; the exported report retains bounded context</p></div><span>${objects.length} shown</span></div><div class="atlas-objects">${objectRows || "<span>No objects were returned by available sources.</span>"}</div></article></div>
      <article class="panel card-block atlas-alerts"><div class="card-title"><div><h3>Persistence signals</h3><p>Precise rules for unsafe ownership, links, preload directives, risky paths, signing, and update transport</p></div><span>${findings.length} active</span></div>${alertRows}</article>`;
    $$(".atlas-finding", target).forEach(row => row.addEventListener("click", () => row.classList.toggle("expanded")));
  }
  function renderBluePulse() {
    if (!state.report) { $("#bluepulse-content").innerHTML = empty("⌁","No confidence report yet","Run a scan so BluePulse can verify each available layer."); return; }
    const protection = state.report.protection || {}, behavior = state.report.behavior || {};
    const pulse = pulseCheck(behavior) || { status:"unknown", message:"BluePulse data unavailable", details:{} };
    const details = pulse.details || {}, freshness = scanFreshness(state.report);
    const installed = state.capabilities.installed !== false;
    const paused = state.capabilities.monitoringPaused === true;
    const operation = operationCheck(behavior);
    const fileEvents = fileEventCheck(behavior);
    const decisiveStatus = ["unhealthy","unknown"].includes(pulse.status);
    const effectiveStatus = decisiveStatus ? pulse.status : paused || !freshness.fresh || !installed ? "degraded" : pulse.status;
    const confidence = decisiveStatus ? details.confidence || "low" : paused || !freshness.fresh || !installed ? "reduced" : details.confidence || "low";
    const headline = {healthy:"Sensors are reporting normally",degraded:"Detection confidence needs attention",unknown:"Detection confidence is incomplete",unhealthy:"A defensive layer is unhealthy"}[effectiveStatus] || "Detection confidence is incomplete";
    const explanation = effectiveStatus === "healthy" ? "BluePulse verified the available layers, event continuity, and local monitoring state behind this scan." : "Review the signals below before relying on a clean endpoint result.";
    const eventState = details.event_continuity || "not configured";
    const nativeState = details.native_telemetry || "not configured";
    const dropped = Number(details.native_dropped_events || 0);
    const artifactIssues = Array.isArray(details.artifact_issues) ? details.artifact_issues : [];
    const operationStatus = operation?.status || (paused ? "degraded" : state.capabilities.menuBar ? "healthy" : "unknown");
    const mode = paused ? "Paused" : details.monitoring_mode === "continuous local scheduling" ? "Continuous" : title(details.monitoring_mode || "Continuous");
    const signals = [
      {name:"scan_freshness",status:freshness.fresh?"healthy":"degraded",message:freshness.fresh?"The current report is recent.":"The current report is older than 2½ minutes."},
      {name:"app_placement",status:installed?"healthy":"degraded",message:installed?"RATtler is running from Applications.":"Move RATtler into Applications and reopen it."},
      {name:"background_monitoring",status:operationStatus,message:paused?"Continuous monitoring is explicitly paused; manual scans still work.":operation?.message || "The native menu-bar scheduler is active."},
      {name:"file_event_continuity",status:fileEvents?.status||"unknown",message:fileEvents?.status==="healthy"?`${Number(fileEvents.details?.roots_watched||0)} protected folders have a live FSEvents trigger.`:fileEvents?.message||"Protected-folder event continuity could not be verified."},
      {name:"event_continuity",status:["healthy","not configured"].includes(eventState)?"healthy":eventState,message:eventState==="not configured"?"One-time snapshot mode; continuous event state is not enabled.":`Continuous event state is ${eventState}.`},
      {name:"local_state_protection",status:artifactIssues.length?"degraded":"healthy",message:artifactIssues.length?`${artifactIssues.length} local monitoring artifact needs review.`:`${Number(details.artifacts_checked || 0)} local monitoring artifacts passed permission checks.`},
      {name:"native_event_loss",status:nativeState==="not configured"?"healthy":dropped?"degraded":nativeState,message:nativeState==="not configured"?"Native telemetry is optional and not provisioned.":dropped?`${dropped} native events were dropped.`:"No native event loss was reported."}
    ];
    const behavioral = (behavior.sensors || []).filter(item => item.name !== "bluepulse");
    $("#bluepulse-content").innerHTML = `
      <article class="panel bluepulse-hero ${esc(effectiveStatus)}"><div class="pulse-orb"><span></span><i></i></div><div class="bluepulse-copy"><div class="status-kicker">${esc(confidence.toUpperCase())} CONFIDENCE</div><h2>${esc(headline)}</h2><p>${esc(explanation)}</p><small>Confidence describes visibility—not whether findings are safe or malicious.</small></div><div class="pulse-trace"><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div></article>
      <div class="sensor-summary">${metric(ageLabel(freshness.age),"Last scan",freshness.fresh?"Current":"Refresh recommended","clock",freshness.fresh?"":"warning")}${metric(`${Number(details.operational || 0)}/${Number(details.monitored || 0)}`,"Operational","Available layers","check",pulse.status==="healthy"?"":"warning")}${metric(mode,"Mode",paused?"Scheduling stopped":"Local scheduling","coverage",paused?"warning":"info")}</div>
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
    const paused = state.capabilities.monitoringPaused === true;
    $("#monitoring-description").textContent = paused ? "Scheduled scans are paused. The menu-bar controller remains available and manual scans still work." : `The native scheduler checks this Mac every ${Number(state.capabilities.backgroundInterval || 60)} seconds, even when the window is closed.`;
    $("#monitoring-button").textContent = paused ? "Resume" : "Pause";
    const fileEventsActive = state.capabilities.fileEvents === true && Number(state.capabilities.fileEventRoots || 0) > 0;
    $("#file-event-description").textContent = fileEventsActive ? `${Number(state.capabilities.fileEventRoots)} protected folders trigger ransomware snapshots within seconds.` : "The protected-folder event stream is unavailable; scheduled scans still run.";
    $("#file-event-state").textContent = fileEventsActive ? "LIVE" : "CHECK";
    $("#file-event-state").classList.toggle("warning", !fileEventsActive);
    $("#login-switch").checked = state.capabilities.launchAtLogin === true;
    $("#login-description").textContent = state.capabilities.launchAtLoginStatus === "approval required" ? "Approval is required in System Settings → General → Login Items." : state.capabilities.launchAtLogin ? "RATtler will start after you sign in." : "Keep protection available after you sign in.";
    $("#notification-switch").checked = state.capabilities.notificationsEnabled === true;
    $("#native-settings").innerHTML = nativeCard();
    const active = state.quarantine.filter(entry => entry.status === "quarantined");
    $("#quarantine-list").innerHTML = active.length ? active.map(entry => `<div class="quarantine-entry"><div><strong title="${esc(entry.original_path)}">${esc(entry.original_path)}</strong><small>${esc(String(entry.sha256 || "").slice(0,16))}… · ${esc(entry.id)}</small></div><button class="quiet-button restore-button" data-id="${esc(entry.id)}">Review restore</button></div>`).join("") : `<span>No quarantined files are awaiting restore.</span>`;
    $$(".restore-button", $("#quarantine-list")).forEach(button => button.addEventListener("click", () => native("restore", { id: button.dataset.id })));
    const now = Date.now(), activeExceptions = state.exceptions.filter(entry => Date.parse(entry.expires_at) > now);
    $("#exception-list").innerHTML = activeExceptions.length ? activeExceptions.map(entry => {
      const identity = entry.match?.cdhash || entry.match?.sha256 || `${entry.match?.team_id || ""}/${entry.match?.identifier || ""}`;
      const expiry = new Date(entry.expires_at).toLocaleDateString([], {dateStyle:"medium"});
      return `<div class="quarantine-entry"><div><strong title="${esc(entry.match?.path)}">${esc(entry.rule_id)} · ${esc(entry.match?.path)}</strong><small>${esc(String(identity).slice(0,20))}${String(identity).length>20?"…":""} · expires ${esc(expiry)}</small></div><button class="quiet-button remove-exception-button" data-id="${esc(entry.id)}">Remove</button></div>`;
    }).join("") : `<span>No active reviewed exceptions.</span>`;
    $$(".remove-exception-button", $("#exception-list")).forEach(button => button.addEventListener("click", () => native("removeException", { id:button.dataset.id })));
  }
  function renderChrome() {
    const status = state.report?.status || "unknown";
    const paused = state.capabilities.monitoringPaused === true;
    $("#sidebar-dot").className = `status-dot ${paused ? "degraded" : status}`;
    $("#sidebar-label").textContent = paused ? "Monitoring paused" : state.report ? statusLabel(status) : "Awaiting scan";
    $("#pause-button").textContent = paused ? "Resume" : "Pause";
    $("#pause-button").classList.toggle("warning", paused);
    $("#export-button").disabled = !state.report;
  }
  function renderAll() { renderDashboard(); renderFindings(); renderFileScan(); renderDetectionLab(); renderRansomware(); renderPersistence(); renderBluePulse(); renderActivity(); renderSettings(); renderChrome(); }
  function showToast(message, success = false) { const toast=$("#toast"); $("strong",toast).textContent=success ? "Response completed" : "RATtler needs attention"; $("p",toast).textContent=message; toast.classList.toggle("success",success); toast.classList.add("visible"); clearTimeout(showToast.timer); showToast.timer=setTimeout(()=>toast.classList.remove("visible"),7000); }

  window.RATtler = {
    receiveReport(base64) { try { state.report=JSON.parse(decode(base64)); renderAll(); } catch(error) { showToast(`The report could not be displayed: ${error.message}`); } },
    receiveFileScan(base64) { try { state.fileScan=JSON.parse(decode(base64)); renderFileScan(); } catch(error) { showToast(`The file scan could not be displayed: ${error.message}`); } },
    receiveDetectionLab(base64) { try { state.detectionLab=JSON.parse(decode(base64)); renderDetectionLab(); } catch(error) { showToast(`The detection lab result could not be displayed: ${error.message}`); } },
    receiveCapabilities(base64) { try { state.capabilities={...state.capabilities,...JSON.parse(decode(base64))}; renderAll(); } catch(_) {} },
    receiveState(base64) { try { const next=JSON.parse(decode(base64)); state.phase=next.phase; $("#activity-message").textContent=next.message; const scanning=next.phase==="scanning"; $("#scan-button").classList.toggle("scanning",scanning); $("#scan-button").disabled=scanning; if(next.phase==="error") showToast(next.message); } catch(_) {} },
    receiveResponse(base64) { try { const result=JSON.parse(decode(base64)); if(Array.isArray(result.entries)) { state.quarantine=result.entries; renderSettings(); } if(Array.isArray(result.exceptions)) { state.exceptions=result.exceptions; renderSettings(); } if(result.clearFileScan) { state.fileScan=null; renderFileScan(); } if(result.message) showToast(result.message, Boolean(result.success)); } catch(_) {} }
  };

  $$(".nav-item").forEach(button => button.addEventListener("click", () => { $$(".nav-item").forEach(item=>item.classList.remove("active")); button.classList.add("active"); $$(".view").forEach(view=>view.classList.remove("active")); $(`#${button.dataset.view}`).classList.add("active"); if(button.dataset.view==="settings") { native("listQuarantine"); native("listExceptions"); } }));
  $("#scan-button").addEventListener("click",()=>native("scan")); $("#export-button").addEventListener("click",()=>native("export")); $("#reveal-button").addEventListener("click",()=>native("reveal")); $("#quarantine-folder-button").addEventListener("click",()=>native("revealQuarantine")); $("#quarantine-refresh-button").addEventListener("click",()=>native("listQuarantine"));
  const toggleMonitoring=()=>native("setMonitoringPaused",{paused:!state.capabilities.monitoringPaused});
  $("#pause-button").addEventListener("click",toggleMonitoring); $("#monitoring-button").addEventListener("click",toggleMonitoring);
  $("#login-switch").addEventListener("change",event=>native("setLaunchAtLogin",{enabled:event.target.checked}));
  $("#notification-switch").addEventListener("change",event=>native("setNotifications",{enabled:event.target.checked}));
  $("#baseline-button").addEventListener("click",()=>{ if(confirm(`${state.capabilities.baseline ? "Replace" : "Create"} the integrity baseline?\n\nOnly continue after reviewing the current scan and trusting this Mac’s present state.`)) native("baseline"); });
  $("#severity-filter").addEventListener("change",renderFindings); $("#finding-search").addEventListener("input",renderFindings); $("#toast button").addEventListener("click",()=>$("#toast").classList.remove("visible"));
  native("capabilities");
})();
