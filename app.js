/*
 * UCPGATE UI Controller (Zero External Dependencies, Browser-Local Execution)
 */
import {
  auditUcpReadiness,
  auditUcpText,
  buildSamplePresets,
  generateUcpBundle
} from "./engine.js";

const PRESETS = buildSamplePresets();

let currentReport = null;
let selectedGateIndex = 0;
let currentGeneratedBundle = null;
let activeArtifactTab = "manifest";

function el(id) {
  return document.getElementById(id);
}

function statusPillClass(status) {
  if (status === "compliant" || status === "pass") return "status-pill pill-positive";
  if (status === "action_required" || status === "warn") return "status-pill pill-warning";
  return "status-pill pill-negative";
}

function statusLabel(status) {
  if (status === "compliant") return "Compliant";
  if (status === "action_required") return "Action required";
  if (status === "non_compliant") return "Non-compliant";
  if (status === "pass") return "Pass";
  if (status === "warn") return "Warn";
  return "Fail";
}

function shortCapLabel(capKey) {
  if (capKey.startsWith("dev.ucp.shopping.")) {
    return "shopping." + capKey.slice("dev.ucp.shopping.".length);
  }
  if (capKey.startsWith("dev.ucp.")) {
    return "ucp." + capKey.slice("dev.ucp.".length);
  }
  return capKey.length > 24 ? capKey.slice(0, 22) + ".." : capKey;
}

function renderDagSvg(dag) {
  const svg = el("dag-svg");
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const ns = "http://www.w3.org/2000/svg";
  const width = 644;
  const height = 172;

  const defs = document.createElementNS(ns, "defs");
  function makeMarker(id, color) {
    const marker = document.createElementNS(ns, "marker");
    marker.setAttribute("id", id);
    marker.setAttribute("viewBox", "0 0 10 10");
    marker.setAttribute("refX", "9");
    marker.setAttribute("refY", "5");
    marker.setAttribute("markerWidth", "6");
    marker.setAttribute("markerHeight", "6");
    marker.setAttribute("orient", "auto-start-reverse");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", "M 0 1 L 10 5 L 0 9 z");
    path.setAttribute("fill", color);
    marker.appendChild(path);
    return marker;
  }
  defs.appendChild(makeMarker("arrow-valid", "#1b6c80"));
  defs.appendChild(makeMarker("arrow-fault", "#c4242a"));
  svg.appendChild(defs);

  const allNodes = [...(dag.nodes || [])];
  const missingParents = new Set();
  for (const d of dag.dangling_parents || []) {
    missingParents.add(d.missing_parent);
    if (!allNodes.includes(d.missing_parent)) {
      allNodes.push(d.missing_parent);
    }
  }

  if (allNodes.length === 0) {
    const txt = document.createElementNS(ns, "text");
    txt.setAttribute("x", String(width / 2));
    txt.setAttribute("y", String(height / 2));
    txt.setAttribute("text-anchor", "middle");
    txt.setAttribute("fill", "#55585a");
    txt.setAttribute("font-size", "12");
    txt.textContent = "No capabilities declared in ucp.capabilities.";
    svg.appendChild(txt);
    return;
  }

  const cycleNodes = new Set();
  for (const cyc of dag.cycles || []) {
    for (const n of cyc) cycleNodes.add(n);
  }

  // Place root capabilities on left lane, extensions on right lane
  const outgoingSet = new Set((dag.edges || []).map((e) => e.from));
  const roots = allNodes.filter((n) => !outgoingSet.has(n));
  const leaves = allNodes.filter((n) => outgoingSet.has(n));
  const leftLane = roots.length > 0 ? roots : allNodes.slice(0, Math.ceil(allNodes.length / 2));
  const rightLane = roots.length > 0 ? leaves : allNodes.slice(Math.ceil(allNodes.length / 2));

  const positions = new Map();
  const boxW = 204;
  const boxH = 30;

  leftLane.forEach((node, idx) => {
    const step = height / (leftLane.length + 1);
    positions.set(node, { x: 28, y: Math.round(step * (idx + 1) - boxH / 2) });
  });
  rightLane.forEach((node, idx) => {
    const step = height / (rightLane.length + 1);
    positions.set(node, { x: width - boxW - 28, y: Math.round(step * (idx + 1) - boxH / 2) });
  });

  for (const edge of dag.edges || []) {
    const src = positions.get(edge.from);
    const dst = positions.get(edge.to);
    if (!src || !dst) continue;

    const isFault =
      missingParents.has(edge.to) ||
      (cycleNodes.has(edge.from) && cycleNodes.has(edge.to));

    const line = document.createElementNS(ns, "path");
    let dStr = "";
    if (src.x === dst.x) {
      const xEdge = src.x + boxW;
      const y1 = src.y + boxH / 2;
      const y2 = dst.y + boxH / 2;
      const curveX = Math.min(width - 10, xEdge + 26);
      dStr = `M ${xEdge} ${y1} C ${curveX} ${y1}, ${curveX} ${y2}, ${xEdge} ${y2}`;
    } else if (src.x > dst.x) {
      const x1 = src.x;
      const y1 = src.y + boxH / 2;
      const x2 = dst.x + boxW;
      const y2 = dst.y + boxH / 2;
      const midX = Math.round((x1 + x2) / 2);
      dStr = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
    } else {
      const x1 = src.x + boxW;
      const y1 = src.y + boxH / 2;
      const x2 = dst.x;
      const y2 = dst.y + boxH / 2;
      const midX = Math.round((x1 + x2) / 2);
      dStr = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
    }

    line.setAttribute("d", dStr);
    line.setAttribute("fill", "none");
    line.setAttribute("stroke", isFault ? "#c4242a" : "#1b6c80");
    line.setAttribute("stroke-width", "1.6");
    if (isFault) {
      line.setAttribute("stroke-dasharray", "4 3");
    }
    line.setAttribute("marker-end", isFault ? "url(#arrow-fault)" : "url(#arrow-valid)");
    svg.appendChild(line);
  }

  for (const [node, pos] of positions.entries()) {
    const isMissing = missingParents.has(node);
    const isCyc = cycleNodes.has(node);
    const g = document.createElementNS(ns, "g");

    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("x", String(pos.x));
    rect.setAttribute("y", String(pos.y));
    rect.setAttribute("width", String(boxW));
    rect.setAttribute("height", String(boxH));
    rect.setAttribute("rx", "5");
    rect.setAttribute("fill", isMissing || isCyc ? "#ffedea" : "#ffffff");
    rect.setAttribute("stroke", isMissing || isCyc ? "#c4242a" : "#1b6c80");
    rect.setAttribute("stroke-width", "1.2");
    if (isMissing) {
      rect.setAttribute("stroke-dasharray", "3 2");
    }
    g.appendChild(rect);

    const label = document.createElementNS(ns, "text");
    label.setAttribute("x", String(pos.x + 10));
    label.setAttribute("y", String(pos.y + 19));
    label.setAttribute("fill", isMissing || isCyc ? "#831c1e" : "#131416");
    label.setAttribute("font-size", "12");
    label.setAttribute("font-weight", node === "dev.ucp.shopping.checkout" ? "600" : "500");
    label.textContent = shortCapLabel(node) + (isMissing ? " (undeclared)" : "");
    g.appendChild(label);

    svg.appendChild(g);
  }
}

function renderSelectedGateDetail() {
  if (!currentReport || !currentReport.gates[selectedGateIndex]) return;
  const gate = currentReport.gates[selectedGateIndex];
  el("gate-detail-heading").textContent = `${gate.gate_id} · ${gate.title}`;
  el("gate-detail-ref").textContent = gate.spec_ref;
  el("gate-detail-summary").textContent = gate.summary;

  const listEl = el("gate-finding-list");
  const emptyEl = el("gate-empty-findings");
  while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

  if (!gate.findings || gate.findings.length === 0) {
    listEl.hidden = true;
    emptyEl.hidden = false;
    return;
  }

  listEl.hidden = false;
  emptyEl.hidden = true;
  for (const f of gate.findings) {
    const li = document.createElement("li");
    li.className = "finding-item";

    const head = document.createElement("div");
    head.className = "finding-head";

    const sev = document.createElement("span");
    sev.className =
      f.severity === "critical" || f.severity === "high"
        ? "status-pill pill-negative"
        : "status-pill pill-warning";
    sev.textContent = f.severity;

    const code = document.createElement("code");
    code.textContent = f.code;

    const title = document.createElement("span");
    title.className = "finding-title";
    title.textContent = f.title;

    head.appendChild(sev);
    head.appendChild(code);
    head.appendChild(title);

    const fix = document.createElement("div");
    fix.className = "finding-fix";
    fix.textContent = "Remediation: " + f.remediation;

    li.appendChild(head);
    li.appendChild(fix);
    listEl.appendChild(li);
  }
}

function renderAuditReport(report) {
  currentReport = report;
  el("audit-parse-error").hidden = true;

  const pill = el("audit-overall-pill");
  pill.className = statusPillClass(report.status);
  pill.textContent = statusLabel(report.status);

  if (report.status === "compliant") {
    el("audit-headline-finding").textContent =
      `${report.domain} passes all 10 UCP ${report.ucp_version || "2026-01-23"}, Stateless MCP, Schema.org Offer, and AP2 mandate gates.`;
  } else {
    el("audit-headline-finding").textContent =
      `${report.domain} scored ${report.score}/100 (${report.gates_failed} failed, ${report.gates_warned} warning gates across ${report.findings_count} findings).`;
  }

  el("kpi-score").innerHTML = `${report.score}<span class="kpi-unit"> /100</span>`;
  el("kpi-grade").textContent = `Grade ${report.grade} · Spec ${report.ucp_version || "missing"}`;

  el("kpi-gates").innerHTML = `${report.gates_passed}<span class="kpi-unit"> /10 pass</span>`;
  el("kpi-findings").textContent = `${report.gates_warned} warn · ${report.gates_failed} fail · ${report.findings_count} findings`;

  const dag = report.dag || { nodes: [], edges: [], cycles: [], dangling_parents: [], is_acyclic: true };
  el("kpi-dag-nodes").innerHTML = `${dag.nodes.length}<span class="kpi-unit"> nodes</span>`;
  if (!dag.is_acyclic) {
    el("kpi-dag-state").textContent = `Cycle detected (${dag.cycles.length} loop)`;
    el("dag-caption").textContent = "Cycle detected in capability extends graph. Autonomous negotiation blocked.";
  } else if (dag.dangling_parents.length > 0) {
    el("kpi-dag-state").textContent = `${dag.dangling_parents.length} missing parent`;
    el("dag-caption").textContent = "Dangling extends parent detected. Declare the parent capability in ucp.capabilities.";
  } else {
    el("kpi-dag-state").textContent = `Acyclic · ${dag.edges.length} verified edge(s)`;
    el("dag-caption").textContent = `Topological order: ${(dag.topological_order || []).map(shortCapLabel).join(" -> ") || "none"}`;
  }

  const surf = report.surfaces || {};
  const surfParts = [...(surf.transports || []).map((t) => t.toUpperCase())];
  if (surf.has_a2a_agent_card) surfParts.push("A2A");
  if (surf.offers_count > 0) surfParts.push(`${surf.offers_count} Offer`);
  el("kpi-handlers").innerHTML = `${surf.payment_handlers_count || 0}<span class="kpi-unit"> rails</span>`;
  el("kpi-surfaces").textContent = surfParts.length > 0 ? surfParts.join(" + ") : "No active transports";

  renderDagSvg(dag);

  const firstFailedIdx = report.gates.findIndex((g) => g.status === "fail");
  const firstWarnIdx = report.gates.findIndex((g) => g.status === "warn");
  if (firstFailedIdx >= 0) selectedGateIndex = firstFailedIdx;
  else if (firstWarnIdx >= 0) selectedGateIndex = firstWarnIdx;
  else selectedGateIndex = 0;

  const tbody = el("gates-tbody");
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  report.gates.forEach((gate, idx) => {
    const tr = document.createElement("tr");
    tr.className = "gate-row";
    tr.tabIndex = 0;
    tr.setAttribute("aria-selected", idx === selectedGateIndex ? "true" : "false");

    const tdId = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = gate.gate_id;
    tdId.appendChild(code);

    const tdTitle = document.createElement("td");
    tdTitle.className = "gate-title-cell";
    tdTitle.textContent = gate.title;
    const sub = document.createElement("span");
    sub.className = "gate-summary-sub";
    sub.textContent = gate.summary;
    tdTitle.appendChild(sub);

    const tdStatus = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = statusPillClass(gate.status);
    badge.textContent = statusLabel(gate.status);
    tdStatus.appendChild(badge);

    const tdPts = document.createElement("td");
    tdPts.className = "num";
    tdPts.textContent = `${gate.earned_points} / ${gate.weight}`;

    tr.appendChild(tdId);
    tr.appendChild(tdTitle);
    tr.appendChild(tdStatus);
    tr.appendChild(tdPts);

    const selectRow = () => {
      selectedGateIndex = idx;
      for (const sibling of tbody.querySelectorAll(".gate-row")) {
        sibling.setAttribute("aria-selected", "false");
      }
      tr.setAttribute("aria-selected", "true");
      renderSelectedGateDetail();
    };
    tr.addEventListener("click", selectRow);
    tr.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        selectRow();
      }
    });

    tbody.appendChild(tr);
  });

  renderSelectedGateDetail();
}

function runAuditFromEditor() {
  const raw = el("txt-audit-input").value;
  try {
    const rep = auditUcpText(raw);
    renderAuditReport(rep);
  } catch (err) {
    const errBox = el("audit-parse-error");
    errBox.textContent = err.message || String(err);
    errBox.hidden = false;
  }
}

function loadPreset(presetKey) {
  const preset = PRESETS[presetKey];
  if (!preset) return;
  for (const btn of document.querySelectorAll("[data-preset]")) {
    btn.setAttribute("aria-pressed", btn.dataset.preset === presetKey ? "true" : "false");
  }
  el("txt-audit-input").value = JSON.stringify(preset, null, 2);
  runAuditFromEditor();
}

function switchMainTab(mode) {
  const isAudit = mode === "audit";
  el("tab-audit").setAttribute("aria-selected", isAudit ? "true" : "false");
  el("tab-builder").setAttribute("aria-selected", isAudit ? "false" : "true");
  el("view-audit").hidden = !isAudit;
  el("view-builder").hidden = isAudit;
}

function activeArtifactContentAndFilename() {
  if (!currentGeneratedBundle) return { content: "", filename: "ucp.json" };
  if (activeArtifactTab === "worker") {
    return {
      content: currentGeneratedBundle.cloudflare_worker_js,
      filename: "ucp-cloudflare-worker.js"
    };
  }
  if (activeArtifactTab === "nginx") {
    return {
      content: currentGeneratedBundle.nginx_conf,
      filename: "ucp-well-known-nginx.conf"
    };
  }
  if (activeArtifactTab === "agent_card") {
    return {
      content: JSON.stringify(currentGeneratedBundle.agent_card, null, 2) + "\n",
      filename: "agent.json"
    };
  }
  if (activeArtifactTab === "schema_org") {
    return {
      content: JSON.stringify(currentGeneratedBundle.schema_org_product_jsonld, null, 2) + "\n",
      filename: "product-offer.jsonld"
    };
  }
  return {
    content: JSON.stringify(currentGeneratedBundle.manifest, null, 2) + "\n",
    filename: "ucp.json"
  };
}

function renderActiveArtifact() {
  const { content } = activeArtifactContentAndFilename();
  el("artifact-code").textContent = content;
}

function rebuildGeneratorOutput() {
  const domain = el("inp-domain").value;
  const platform = el("sel-platform").value;
  const version = el("inp-version").value;

  const caps = Array.from(document.querySelectorAll("input[name='gen-cap']:checked")).map((i) => i.value);
  const handlers = Array.from(document.querySelectorAll("input[name='gen-handler']:checked")).map((i) => i.value);
  const currencies = Array.from(document.querySelectorAll("input[name='gen-cur']:checked")).map((i) => i.value);

  try {
    const bundle = generateUcpBundle(domain, {
      platform,
      version,
      capabilities: caps,
      paymentHandlers: handlers.length > 0 ? handlers : ["com.google.pay"],
      currencies: currencies.length > 0 ? currencies : ["USD"],
      includeA2aAgentCard: true
    });
    currentGeneratedBundle = bundle;
    el("builder-error").hidden = true;

    const roundTrip = auditUcpReadiness({
      domain: bundle.domain,
      platform: bundle.platform,
      status_code: 200,
      http_headers: bundle.http_headers,
      manifest: bundle.manifest,
      agent_card: bundle.agent_card,
      schema_org_offers: [bundle.schema_org_product_jsonld.offers]
    });

    const pill = el("builder-score-pill");
    pill.className = statusPillClass(roundTrip.status) + " num";
    pill.textContent = `${roundTrip.score} / 100 · Grade ${roundTrip.grade}`;
    renderActiveArtifact();
  } catch (err) {
    const errBox = el("builder-error");
    errBox.textContent = err.message || String(err);
    errBox.hidden = false;
  }
}

function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function init() {
  el("tab-audit").addEventListener("click", () => switchMainTab("audit"));
  el("tab-builder").addEventListener("click", () => switchMainTab("builder"));
  el("btn-open-builder").addEventListener("click", () => switchMainTab("builder"));
  el("btn-run-audit").addEventListener("click", runAuditFromEditor);

  for (const btn of document.querySelectorAll("[data-preset]")) {
    btn.addEventListener("click", () => loadPreset(btn.dataset.preset));
  }

  el("btn-load-remediated").addEventListener("click", () => {
    if (!currentReport || !currentReport.deployment_bundle) return;
    const db = currentReport.deployment_bundle;
    const remBundle = {
      domain: db.domain,
      platform: db.platform,
      status_code: 200,
      http_headers: db.http_headers,
      manifest: db.manifest,
      agent_card: db.agent_card,
      schema_org_offers: [db.schema_org_product_jsonld.offers]
    };
    for (const btn of document.querySelectorAll("[data-preset]")) {
      btn.setAttribute("aria-pressed", "false");
    }
    el("txt-audit-input").value = JSON.stringify(remBundle, null, 2);
    runAuditFromEditor();
  });

  el("inp-upload-json").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const text = await file.text();
    for (const btn of document.querySelectorAll("[data-preset]")) {
      btn.setAttribute("aria-pressed", "false");
    }
    el("txt-audit-input").value = text;
    runAuditFromEditor();
  });

  for (const ctrl of document.querySelectorAll(
    "#inp-domain, #sel-platform, #inp-version, input[name='gen-cap'], input[name='gen-handler'], input[name='gen-cur']"
  )) {
    ctrl.addEventListener("input", rebuildGeneratorOutput);
    ctrl.addEventListener("change", rebuildGeneratorOutput);
  }

  for (const btn of document.querySelectorAll("[data-artifact]")) {
    btn.addEventListener("click", () => {
      activeArtifactTab = btn.dataset.artifact;
      for (const b of document.querySelectorAll("[data-artifact]")) {
        b.setAttribute("aria-pressed", b === btn ? "true" : "false");
      }
      renderActiveArtifact();
    });
  }

  el("btn-copy-artifact").addEventListener("click", async () => {
    const { content } = activeArtifactContentAndFilename();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(content);
      const copyBtn = el("btn-copy-artifact");
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy active snippet";
      }, 1400);
    }
  });

  el("btn-download-artifact").addEventListener("click", () => {
    const { content, filename } = activeArtifactContentAndFilename();
    downloadTextFile(filename, content);
  });

  el("btn-send-to-auditor").addEventListener("click", () => {
    if (!currentGeneratedBundle) return;
    const b = currentGeneratedBundle;
    const auditPayload = {
      domain: b.domain,
      platform: b.platform,
      status_code: 200,
      http_headers: b.http_headers,
      manifest: b.manifest,
      agent_card: b.agent_card,
      schema_org_offers: [b.schema_org_product_jsonld.offers]
    };
    el("txt-audit-input").value = JSON.stringify(auditPayload, null, 2);
    switchMainTab("audit");
    runAuditFromEditor();
  });

  loadPreset("production-google-stripe-ucp");
  rebuildGeneratorOutput();
}

init();
