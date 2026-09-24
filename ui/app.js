/* Sentinel console. Talks to the versioned API; falls back to a static
   snapshot (computed by the same Python engine) when no backend is reachable.
   No decision logic lives here -- the console only renders what the engine returns. */
(() => {
"use strict";

// ---------- data access ----------------------------------------------------------------
const API = {
  live: null, snap: null,
  async init() {
    try { const r = await fetch("/v1/system", {cache: "no-store"}); if (!r.ok) throw 0; this.live = await r.json(); return "live"; }
    catch (e) {
      const r = await fetch("snapshot.json", {cache: "no-store"}); if (!r.ok) throw new Error("no API and no snapshot");
      this.snap = await r.json(); return "snapshot";
    }
  },
  isLive() { return !!this.live; },
  async get(path) {
    if (this.live) { const r = await fetch(path, {cache: "no-store"}); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j; }
    return this.fromSnapshot("GET", path);
  },
  async post(path, body) {
    if (this.live) { const r = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})}); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j; }
    return this.fromSnapshot("POST", path, body);
  },
  fromSnapshot(method, path, body) {
    const s = this.snap, p = path.split("?")[0];
    const m = (re) => p.match(re);
    if (p === "/v1/system") return s.system;
    if (p === "/v1/overview") return s.overview;
    if (p === "/v1/transactions") return s.transactions;
    if (m(/^\/v1\/transactions\/(.+)$/)) { const v = s.transaction_views[m(/^\/v1\/transactions\/(.+)$/)[1]]; if (!v) throw new Error("not in static snapshot"); return v; }
    if (p === "/v1/disputes") return s.disputes;
    if (p === "/v1/merchants") return s.merchants;
    if (m(/^\/v1\/merchants\/(.+)$/)) { const v = s.merchant_views[m(/^\/v1\/merchants\/(.+)$/)[1]]; if (!v) throw new Error("not in static snapshot"); return v; }
    if (p === "/v1/accounts") return s.accounts;
    if (m(/^\/v1\/accounts\/(.+)$/)) { const v = s.account_views[m(/^\/v1\/accounts\/(.+)$/)[1]]; if (!v) throw new Error("not in static snapshot"); return v; }
    if (p === "/v1/cases") return s.cases;
    if (m(/^\/v1\/cases\/([^/]+)$/)) { const v = s.case_views[m(/^\/v1\/cases\/([^/]+)$/)[1]]; if (!v) throw new Error("not in static snapshot"); return v; }
    if (p === "/v1/ai/security/events") return s.security_events;
    if (p === "/v1/policies") return s.policies;
    if (p === "/v1/audit") return s.audit;
    if (p === "/v1/audit/verify") return s.audit_verify;
    if (p === "/v1/decisions") return s.decisions;
    if (m(/^\/v1\/decisions\/(.+)$/)) { const v = s.decision_views[m(/^\/v1\/decisions\/(.+)$/)[1]]; if (!v) throw new Error("not in static snapshot"); return v; }
    if (p === "/v1/replays") return s.replays;
    if (p === "/v1/attacks") return s.attacks;
    if (p === "/v1/attacks/simulate") { if (body.narrative != null || body.document != null || body.unguarded) throw new Error("Custom attacks need the live API (run `make ui`). Presets shown are real engine output."); return s.attack_results[body.kind]; }
    if (p === "/v1/scenarios") return s.scenarios;
    if (m(/^\/v1\/scenarios\/([a-z_]+)\/run$/)) return s.scenario_results[m(/^\/v1\/scenarios\/([a-z_]+)\/run$/)[1]];
    if (p === "/v1/evaluations") return s.evaluations;
    throw new Error("This action needs the live API: run `make ui`.");
  }
};

// ---------- utils -------------------------------------------------------------------------
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const inr = (n) => "₹" + Number(n || 0).toLocaleString("en-IN");
const chip = (v, cls) => `<span class="chip ${esc(cls || v)}">${esc(v)}</span>`;
const trustChip = (t) => chip(t, (t === "TRUSTED_INTERNAL" || t === "VERIFIED_EXTERNAL") ? "trusted" : t === "MODEL_GENERATED" ? "model" : "untrusted");
const fmtTs = (s) => (s || "").replace("T", " ").slice(0, 19);
const toast = (m) => { const t = $("#toast"); t.textContent = m; t.classList.remove("hidden"); clearTimeout(t._h); t._h = setTimeout(() => t.classList.add("hidden"), 3500); };
const kv = (obj, keys) => `<div class="kv">${(keys || Object.keys(obj)).map(k => `<div class="k">${esc(k)}</div><div class="v">${esc(typeof obj[k] === "object" ? JSON.stringify(obj[k]) : obj[k])}</div>`).join("")}</div>`;
const card = (title, body, extra = "") => `<div class="card"><h3>${title}${extra}</h3>${body}</div>`;
const empty = (m) => `<div class="empty">${esc(m)}</div>`;

// ---------- charts (inline SVG) -------------------------------------------------------------
const COLORS = {LOW:"#3fbf7f",MEDIUM:"#e0a83a",HIGH:"#e2574f",CRITICAL:"#ff3b30",ALLOW:"#3fbf7f",DENY:"#e2574f",BLOCK:"#ff3b30",REQUIRE_HUMAN_REVIEW:"#e0a83a",STEP_UP:"#5da5ff",TEMPORARY_HOLD:"#9d7cff",NONE:"#7d8797",OPEN:"#5da5ff",TRIAGE:"#9d7cff",INVESTIGATING:"#e0a83a",WAITING_HUMAN:"#e0a83a",RESOLVED:"#3fbf7f",ESCALATED:"#e2574f"};
function barChart(data, {order = null, height = 170, color = null, pct = false} = {}) {
  const keys = order ? order.filter(k => k in data) : Object.keys(data);
  if (!keys.length) return empty("no data yet");
  const W = 420, H = height, pad = 26, bw = (W - pad * 2) / keys.length;
  const max = Math.max(1, ...keys.map(k => data[k]));
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  keys.forEach((k, i) => {
    const v = data[k], h = (H - 40) * v / max, x = pad + i * bw + bw * 0.15, y = H - 24 - h;
    const c = color ? color(k) : (COLORS[k] || "#4f8cff");
    s += `<rect x="${x}" y="${y}" width="${bw * 0.7}" height="${h}" rx="3" fill="${c}"/>`;
    s += `<text x="${x + bw * 0.35}" y="${y - 4}" text-anchor="middle" font-size="10" fill="#aab3c2" font-family="ui-monospace,monospace">${pct ? (v * 100).toFixed(1) + "%" : v}</text>`;
    s += `<text x="${x + bw * 0.35}" y="${H - 8}" text-anchor="middle" font-size="9" fill="#7d8797">${esc(k.replace(/_/g, " ").slice(0, 16))}</text>`;
  });
  return s + `</svg>`;
}
function hbarChart(data, {height = null, pct = false, color = "#4f8cff"} = {}) {
  const keys = Object.keys(data).sort((a, b) => data[b] - data[a]);
  if (!keys.length) return empty("no data yet");
  const W = 420, rh = 18, H = height || keys.length * rh + 10;
  const max = Math.max(1e-9, ...keys.map(k => data[k]));
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  keys.forEach((k, i) => {
    const v = data[k], w = (W - 190) * v / max, y = 5 + i * rh;
    s += `<text x="150" y="${y + 12}" text-anchor="end" font-size="9.5" fill="#aab3c2">${esc(k.replace(/_/g, " ").slice(0, 28))}</text>`;
    s += `<rect x="156" y="${y + 3}" width="${Math.max(1, w)}" height="${rh - 7}" rx="2" fill="${color}"/>`;
    s += `<text x="${160 + w}" y="${y + 12}" font-size="9.5" fill="#e6e9ef" font-family="ui-monospace,monospace">${pct ? (v * 100).toFixed(1) + "%" : v}</text>`;
  });
  return s + `</svg>`;
}
function lineChart(points, {height = 170, key = "avg_score", label = "bucket"} = {}) {
  if (!points || !points.length) return empty("no transaction decisions yet — run `sentinel analyze`");
  const W = 420, H = height, pad = 28;
  const max = Math.max(1, ...points.map(p => p[key]));
  const xs = points.map((_, i) => pad + i * (W - pad * 2) / Math.max(1, points.length - 1));
  const ys = points.map(p => H - 24 - (H - 44) * p[key] / max);
  let s = `<svg viewBox="0 0 ${W} ${H}"><polyline fill="none" stroke="#4f8cff" stroke-width="2" points="${xs.map((x, i) => x + "," + ys[i]).join(" ")}"/>`;
  points.forEach((p, i) => { s += `<circle cx="${xs[i]}" cy="${ys[i]}" r="2.5" fill="#7cc0ff"/>`; if (i % Math.ceil(points.length / 6) === 0) s += `<text x="${xs[i]}" y="${H - 8}" text-anchor="middle" font-size="9" fill="#7d8797">${esc(String(p[label]).slice(5, 13))}</text>`; });
  s += `<text x="${pad}" y="14" font-size="9" fill="#7d8797">max ${max}</text>`;
  return s + `</svg>`;
}
function graphSvg(g) {
  if (!g || !g.nodes || !g.nodes.length) return empty("no graph");
  const W = 700, H = 420, cx = W / 2, cy = H / 2;
  const root = g.root, depth = {}, adj = {};
  g.edges.forEach(e => { (adj[e.src] = adj[e.src] || []).push(e.dst); (adj[e.dst] = adj[e.dst] || []).push(e.src); });
  const q = [root]; depth[root] = 0;
  while (q.length) { const n = q.shift(); for (const m of (adj[n] || [])) if (!(m in depth)) { depth[m] = depth[n] + 1; q.push(m); } }
  const rings = {};
  g.nodes.forEach(n => { const d = depth[n.key] ?? 3; (rings[d] = rings[d] || []).push(n); });
  const pos = {};
  Object.keys(rings).forEach(d => { const r = d == 0 ? 0 : 70 + 95 * (d - 1); const arr = rings[d]; arr.forEach((n, i) => { const a = (2 * Math.PI * i) / arr.length - Math.PI / 2; pos[n.key] = [cx + r * Math.cos(a), cy + r * Math.sin(a)]; }); });
  const kc = {transaction:"#4f8cff",account:"#3fbf7f",customer:"#7cc0ff",merchant:"#e0a83a",device:"#e2574f",instrument:"#9d7cff",owner:"#d98b3a",domain:"#7d8797",session:"#5da5ff",ip:"#7d8797"};
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  g.edges.forEach(e => { const a = pos[e.src], b = pos[e.dst]; if (!a || !b) return; s += `<line class="edge" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}"/><text class="el" x="${(a[0] + b[0]) / 2}" y="${(a[1] + b[1]) / 2 - 2}" text-anchor="middle">${esc(e.rel)}</text>`; });
  g.nodes.forEach(n => { const p = pos[n.key]; if (!p) return; const r = n.key === root ? 9 : 6; s += `<circle cx="${p[0]}" cy="${p[1]}" r="${r}" fill="${kc[n.kind] || "#aab3c2"}" stroke="#0b0e13" stroke-width="1.5"/><text x="${p[0]}" y="${p[1] + r + 10}" text-anchor="middle">${esc(n.id.length > 14 ? n.id.slice(0, 14) + "…" : n.id)}</text>`; });
  s += `</svg><div class="legend">${Object.entries(kc).filter(([k]) => g.nodes.some(n => n.kind === k)).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join("")}</div>`;
  return `<div class="graph">${s}</div>`;
}

// ---------- shared renderers ---------------------------------------------------------------
function riskBlock(r) {
  if (!r) return empty("no risk assessment");
  const factors = [...(r.factors || [])].sort((a, b) => b.points - a.points);
  return `<div class="score"><span class="n">${r.score}</span><span class="m">/ 100</span> ${chip(r.level)} <span class="muted small">${esc(r.model_version || "")}</span></div>
  <div class="bar"><i style="width:${Math.min(100, r.score)}%"></i></div>
  <div class="factors">${factors.map(f => `<div class="factor" data-factor="${esc(f.code)}"><div class="p ${f.points >= 0 ? "pos" : "neg"}">${f.points >= 0 ? "+" : ""}${f.points}</div><div><div>${esc(f.label)}</div><div class="d">${esc(f.detail || f.code)}${f.evidence_ids && f.evidence_ids.length ? " · " + esc(f.evidence_ids.join(", ")) : ""}</div></div></div>`).join("") || `<div class="muted small">no factors fired</div>`}</div>
  ${r.recommended_action ? `<div class="small muted" style="margin-top:8px">risk recommendation: <b>${esc(r.recommended_action)}</b> — policy decides, not the score</div>` : ""}`;
}
function evidenceTable(items) {
  if (!items || !items.length) return empty("no evidence recorded");
  return `<table><thead><tr><th>id</th><th>kind</th><th>source</th><th>field</th><th>value</th><th>trust</th><th>status</th></tr></thead><tbody>${items.map(e => `<tr class="evidence-row"><td>${esc(e.evidence_id)}</td><td>${esc(e.kind)}</td><td>${esc(e.source)}</td><td class="mono">${esc(e.field)}</td><td class="mono">${esc(JSON.stringify(e.value))}</td><td>${trustChip(e.trust)}</td><td>${chip(e.status, e.status === "VERIFIED" ? "SUPPORTED" : e.status === "CONTRADICTED" ? "CONTRADICTED" : "INSUFFICIENT")}</td></tr>`).join("")}</tbody></table>`;
}
function decisionBlock(d) {
  if (!d) return empty("no decision yet — evaluate to compute one");
  const ai = d.ai_recommendation;
  return `<div class="grid c2">
    <div>${kv({
      "final action": d.final_action, "executed capability": d.executed_capability || "none", "requested capability": d.requested_capability || "none",
      "evidence verdict": d.evidence_verdict, "contradictions": d.contradiction_count, "security severity": d.security_severity,
      "policy": `${d.policy.policy_id}@v${d.policy.version} → ${d.policy.outcome}`, "matched rules": (d.policy.matched_rules || []).join(", ") || "none",
      "authorization": `${d.authorization.status} — ${d.authorization.reason}`, "blocked by": (d.blocked_by || []).join(", ") || "—",
      "human review": d.human_review.required ? ("required" + (d.case_id ? " · " + d.case_id : "")) : "no", "audit event": d.audit_event_id || "—", "decision id": d.decision_id,
    })}</div>
    <div>${card("LLM recommendation (MODEL_GENERATED)", ai ? kv({agent: ai.agent, recommended: ai.recommended_action, "requested capability": ai.requested_capability || "none", amount: ai.amount, rationale: ai.rationale, provider: `${ai.provider}/${ai.model}`, "agreed with outcome": d.ai_agreed}) : `<div class="muted">no model call (skip_agent)</div>`)}</div>
  </div>
  <h3 style="margin-top:12px">Decision trail</h3><div class="trail">${(d.trail || []).map(t => `<div class="e"><div class="s">${esc(t.stage)}</div><div class="m">${esc(t.summary)}</div>${t.detail && Object.keys(t.detail).length ? `<div class="d">${esc(JSON.stringify(t.detail)).slice(0, 400)}</div>` : ""}</div>`).join("")}</div>`;
}
function storyboard(sb) {
  const st = sb.stages || [];
  return `<div class="headline">${esc(sb.headline)}</div>
  <div class="split"><div>${card("Attacker input " + trustChip("USER_CONTROLLED"), `<pre>${esc(sb.attacker_input)}</pre>`)}${sb.attacker_document ? card("Attacker document " + trustChip("DOCUMENT_CONTROLLED"), `<pre>${esc(sb.attacker_document)}</pre>`) : ""}${card("Trusted ledger " + trustChip("TRUSTED_INTERNAL"), kv(sb.ledger || {}))}</div>
  <div class="flow">${st.map((s, i) => `<div class="stage ${s.status}"><div class="t">${esc(s.title)}</div><div class="v">${esc(s.value)}</div></div>${i < st.length - 1 ? `<div class="arrow">↓</div>` : ""}`).join("")}</div></div>
  <div class="card"><h3>Full decision</h3>${decisionBlock(sb.decision)}</div>
  ${sb.reconciliation ? card("Evidence (claims vs verified facts)", evidenceTable(sb.reconciliation.evidence.items) + (sb.reconciliation.contradictions.length ? `<div class="note" style="margin-top:8px">CONTRADICTION: ${sb.reconciliation.contradictions.map(c => `${esc(c.field)} claimed <b>${esc(String(c.claimed))}</b>, recorded <b>${esc(String(c.recorded))}</b> → ${esc(c.impact)}`).join("; ")}</div>` : "")) : ""}
  ${sb.risk ? card("Dispute risk", riskBlock(sb.risk)) : ""}`;
}

// ---------- views ---------------------------------------------------------------------------
const VIEWS = {};
VIEWS.overview = async () => {
  const o = await API.get("/v1/overview");
  const k = (v, l, s = "") => `<div class="card kpi"><div class="v">${v}</div><div class="l">${l}</div><div class="s">${s}</div></div>`;
  return `<div class="grid c4">
    ${k(o.transactions_analyzed, "Transactions analyzed", `of ${o.transactions} in the dataset`)}${k(o.high_risk_transactions, "High-risk transactions", "HIGH + CRITICAL")}${k(o.blocked_capabilities, "Blocked capabilities", "policy BLOCK on trusted inputs")}${k(o.cases_requiring_review, "Cases requiring review", `${o.open_investigations} open investigations`)}
    ${k(o.ai_security_events, "AI security events", Object.entries(o.security_severity || {}).map(([a, b]) => `${a} ${b}`).join(" · ") || "none")}${k(inr(o.refunds_prevented), "Unsupported refunds prevented", `AI recommended paying · ${o.ai_overruled} model recommendations overruled`)}${k(inr(o.dispute_exposure), "Dispute exposure", `held for human review · ${o.merchants_high_risk} merchants HIGH+`)}${k(o.audit_events, "Audit events", o.audit_chain.ok ? "chain verified ✓" : "CHAIN BROKEN")}
  </div>
  <div class="grid c3">
    ${card("Risk distribution (transaction decisions)", `<div class="chart">${barChart(o.risk_distribution, {order: ["LOW","MEDIUM","HIGH","CRITICAL"]})}</div>`)}
    ${card("Transaction risk over time (avg score / hour bucket)", `<div class="chart">${lineChart(o.risk_over_time)}</div>`)}
    ${card("Security event severity", `<div class="chart">${barChart(o.security_severity, {order: ["LOW","MEDIUM","HIGH","CRITICAL"]})}</div>`)}
    ${card("Policy actions", `<div class="chart">${barChart(o.policy_actions, {order: ["ALLOW","STEP_UP","REQUIRE_HUMAN_REVIEW","TEMPORARY_HOLD","BLOCK"]})}</div>`)}
    ${card("Case funnel", `<div class="chart">${barChart(o.case_funnel, {order: ["OPEN","TRIAGE","INVESTIGATING","WAITING_HUMAN","ESCALATED","RESOLVED"]})}</div>`)}
    ${card("Decision outcomes", `<div class="chart">${barChart(o.decision_outcomes, {order: ["ALLOW","STEP_UP","REQUIRE_HUMAN_REVIEW","TEMPORARY_HOLD","DENY","BLOCK"]})}</div>`)}
  </div>
  <div class="grid c2">${card("Attack classes observed", `<div class="chart">${hbarChart(o.attack_classes, {color: "#e2574f"})}</div>`)}${card("Decisions by workflow", `<div class="chart">${hbarChart(o.workflow_counts)}</div>`)}</div>
  <div class="note">Every number on this page is computed from decisions this engine actually made over the local synthetic dataset (seed ${esc(o.dataset.seed)}, ${o.dataset.customers} customers, ${o.dataset.merchants} merchants). Nothing is hard-coded.</div>`;
};

VIEWS.transactions = async () => {
  const d = await API.get("/v1/transactions?limit=120");
  return card(`Transactions <span class="muted small">${d.transactions.length} of ${d.total} · click a row to investigate</span>`, `<table><thead><tr><th>id</th><th>time</th><th>account</th><th>merchant</th><th class="num">amount</th><th>country</th><th>device</th><th>auth</th><th>risk</th><th>decision</th><th>case</th></tr></thead><tbody>${d.transactions.map(t => `<tr class="row" data-tx="${esc(t.transaction_id)}"><td class="mono">${esc(t.transaction_id)}</td><td class="mono">${fmtTs(t.timestamp)}</td><td class="mono">${esc(t.account_id)}</td><td class="mono">${esc(t.merchant_id)}</td><td class="num">${inr(t.amount)}</td><td>${esc(t.country)}</td><td class="mono">${esc(t.device_id)}</td><td>${esc(t.auth_strength)}</td><td>${t.decision ? `${t.decision.risk_score} ${chip(t.decision.risk_level)}` : `<span class="muted">—</span>`}</td><td>${t.decision ? chip(t.decision.final_action) : `<span class="muted">not evaluated</span>`}</td><td class="mono">${esc(t.decision && t.decision.case_id || "")}</td></tr>`).join("")}</tbody></table>`);
};
async function openTransaction(id) {
  const v = await API.get(`/v1/transactions/${id}`);
  const t = v.transaction;
  openDrawer(`<div class="row"><h2 style="margin:0">Transaction ${esc(t.transaction_id)}</h2>${v.decision ? chip(v.decision.final_action) : ""}<span style="margin-left:auto"></span>${API.isLive() ? `<button class="btn primary" id="tx-eval" data-tx="${esc(id)}">Evaluate now</button>` : ""}</div>
  <div class="grid c3">${card("Transaction", kv({amount: inr(t.amount), timestamp: fmtTs(t.timestamp), country: t.country, channel: t.channel, auth: t.auth_strength, delivery: t.delivery_status, instrument: t.instrument_id, label: t.label}))}${card("Customer & account", kv({customer: v.customer ? `${v.customer.name} (${v.customer.customer_id})` : "—", segment: v.customer && v.customer.segment, home: v.customer && v.customer.home_country, account: v.account && v.account.account_id, opened: v.account && v.account.opened_at, status: v.account && v.account.status, "account risk": v.entity_risk.account.score + " " + v.entity_risk.account.level}))}${card("Merchant & device", kv({merchant: v.merchant ? `${v.merchant.name} (${v.merchant.merchant_id})` : "—", mcc: v.merchant && `${v.merchant.mcc} (${v.merchant.mcc_risk})`, registration: v.merchant && v.merchant.registration_status, "merchant risk": v.entity_risk.merchant.score + " " + v.entity_risk.merchant.level, device: v.device && v.device.device_id, platform: v.device && v.device.platform, "device first seen": v.device && v.device.first_seen, "device risk": v.entity_risk.device.score + " " + v.entity_risk.device.level}))}</div>
  <div class="grid c2">${card("Historical behaviour (baseline)", kv(v.baseline, ["n","average_transaction_amount","transaction_stddev","median_amount","daily_transaction_count","common_countries","common_devices","common_merchants","usual_transaction_hours","chargeback_rate"]))}${card("Risk score — click a factor for its source", riskBlock(v.risk))}</div>
  ${card("Relationship graph (depth 2)", graphSvg(v.graph))}
  ${card("Evidence", evidenceTable(v.evidence.length ? v.evidence : (v.risk.factors || []).map(f => ({evidence_id: "risk:" + f.code, kind: "risk_signal", source: "risk_engine", field: f.code, value: f.points, trust: "TRUSTED_INTERNAL", status: "VERIFIED"}))))}
  ${card("Decision — why was this allowed / blocked / reviewed?", decisionBlock(v.decision))}
  ${v.audit_event ? card("Audit event", kv({sequence: v.audit_event.sequence, event_hash: v.audit_event.event_hash, previous_hash: v.audit_event.previous_hash, action: v.audit_event.action, policy: `${v.audit_event.policy_id}@v${v.audit_event.policy_version}`, evidence_ids: (v.audit_event.evidence_ids || []).join(", ")})) : ""}`);
  const b = $("#tx-eval"); if (b) b.onclick = async () => { b.disabled = true; try { await API.post("/v1/transactions/evaluate", {transaction_id: id}); toast("evaluated"); openTransaction(id); } catch (e) { toast(e.message); b.disabled = false; } };
}

VIEWS.risk = async () => {
  const bands = `<table><thead><tr><th>band</th><th>score</th><th>risk recommendation</th></tr></thead><tbody><tr><td>${chip("LOW")}</td><td class="mono">0–24</td><td>ALLOW</td></tr><tr><td>${chip("MEDIUM")}</td><td class="mono">25–49</td><td>STEP_UP</td></tr><tr><td>${chip("HIGH")}</td><td class="mono">50–74</td><td>REQUIRE_REVIEW</td></tr><tr><td>${chip("CRITICAL")}</td><td class="mono">75–100</td><td>BLOCK</td></tr></tbody></table><div class="muted small" style="margin-top:8px">Sentinel's internal scale for a transparent, replayable rule model over synthetic history — not an industry standard and not ML.</div>`;
  const sys = await API.get("/v1/system");
  return `<div class="grid c2">${card("Explain an entity's risk", `<div class="toolbar"><label class="f">entity type<select id="rk-type"><option>transaction</option><option>account</option><option>merchant</option><option>device</option><option>customer</option></select></label><label class="f" style="flex:1">entity id<input id="rk-id" placeholder="TX-000123 / ACC-000004 / MER-000002"></label><button class="btn primary" id="rk-go">Explain</button></div><div id="rk-out" style="margin-top:12px" class="muted small">Pick any id from the Transactions, Accounts or Merchants pages.</div>`)}${card("Risk bands & models", bands + `<div style="margin-top:10px" class="pill-list">${(sys.risk_models || []).map(m => chip(m, "trusted")).join("")}</div>`)}</div>
  <div class="note">Every point on a score is a named factor with the evidence it read. The score is a <b>recommendation</b>; the versioned policy decides the outcome and the capability registry decides who may execute it.</div>`;
};

VIEWS.disputes = async () => {
  const d = await API.get("/v1/disputes?limit=80");
  return card(`Disputes <span class="muted small">narrative and documents are UNTRUSTED input; the ledger decides</span>`, `<table><thead><tr><th>id</th><th>transaction</th><th>account</th><th class="num">amount</th><th>submitted</th><th>claim (declared)</th><th>narrative</th><th>doc</th><th>decision</th><th></th></tr></thead><tbody>${d.disputes.map(x => `<tr><td class="mono">${esc(x.dispute_id)}</td><td class="mono">${esc(x.transaction_id)}</td><td class="mono">${esc(x.account_id)}</td><td class="num">${inr(x.amount)}</td><td class="mono">${fmtTs(x.submitted_at)}</td><td>${esc(x.claim_type_declared)}</td><td class="small">${esc((x.texts && x.texts.narrative || "").slice(0, 90))}</td><td>${x.texts && x.texts.document ? trustChip("DOCUMENT_CONTROLLED") : ""}</td><td>${x.decision ? `${chip(x.decision.final_action)} <span class="small muted">${esc(x.decision.evidence_verdict)}</span>` : `<span class="muted">—</span>`}</td><td>${API.isLive() ? `<button class="btn small" data-dsp="${esc(x.dispute_id)}">Evaluate</button>` : ""}</td></tr>`).join("")}</tbody></table>`);
};
async function evaluateDispute(id) {
  try { const d = await API.post("/v1/disputes/evaluate", {dispute_id: id}); openDrawer(`<h2 style="margin:0">Dispute ${esc(id)} ${chip(d.final_action)}</h2>` + card("Decision", decisionBlock(d))); } catch (e) { toast(e.message); }
}

VIEWS.merchants = async () => {
  const d = await API.get("/v1/merchants?limit=80");
  return card("Merchants <span class='muted small'>entity risk from dispute ratio, registration, flags, age and owner links</span>", `<table><thead><tr><th>id</th><th>name</th><th>mcc</th><th>tier</th><th>registration</th><th class="num">flags</th><th>registered</th><th>risk</th><th>factors</th></tr></thead><tbody>${d.merchants.map(m => `<tr class="row" data-mer="${esc(m.merchant_id)}"><td class="mono">${esc(m.merchant_id)}</td><td>${esc(m.name)}</td><td class="mono">${esc(m.mcc)}</td><td>${esc(m.mcc_risk)}</td><td>${esc(m.registration_status)}</td><td class="num">${m.prior_flags}</td><td class="mono">${fmtTs(m.registered_at).slice(0, 10)}</td><td>${m.risk.score} ${chip(m.risk.level)}</td><td class="small muted">${esc(m.risk.factors.map(f => f.label).join("; ").slice(0, 80))}</td></tr>`).join("")}</tbody></table>`);
};
async function openMerchant(id) {
  const v = await API.get(`/v1/merchants/${id}`);
  openDrawer(`<h2 style="margin:0">${esc(v.merchant.name)} <span class="muted mono small">${esc(id)}</span></h2><div class="grid c2">${card("Merchant", kv(v.merchant))}${card("Entity risk", riskBlock(v.risk))}</div>${card("Relationship graph", graphSvg(v.graph))}${card("Onboarding applications", v.applications.length ? `<table><thead><tr><th>application</th><th>status</th><th>flags</th><th>label</th><th>document</th></tr></thead><tbody>${v.applications.map(a => `<tr><td class="mono">${esc(a.application_id)}</td><td>${esc(a.registration_status)}</td><td>${a.prior_flags}</td><td>${esc(a.label)}</td><td class="small">${esc((a.texts.document || "").slice(0, 120))}</td></tr>`).join("")}</tbody></table>` : empty("none"))}${card("Recent transactions", `<table><thead><tr><th>id</th><th>account</th><th class="num">amount</th><th>time</th><th>delivery</th></tr></thead><tbody>${v.transactions.map(t => `<tr class="row" data-tx="${esc(t.transaction_id)}"><td class="mono">${esc(t.transaction_id)}</td><td class="mono">${esc(t.account_id)}</td><td class="num">${inr(t.amount)}</td><td class="mono">${fmtTs(t.timestamp)}</td><td>${esc(t.delivery_status)}</td></tr>`).join("")}</tbody></table>`)}`);
}

VIEWS.accounts = async () => {
  const d = await API.get("/v1/accounts?limit=80");
  return card("Accounts <span class='muted small'>entity risk from disputes, security events, age, device links and merchant exposure</span>", `<table><thead><tr><th>id</th><th>customer</th><th>opened</th><th>status</th><th>mfa</th><th>risk</th><th>factors</th><th>linked</th></tr></thead><tbody>${d.accounts.map(a => `<tr class="row" data-acc="${esc(a.account_id)}"><td class="mono">${esc(a.account_id)}</td><td class="mono">${esc(a.customer_id)}</td><td class="mono">${fmtTs(a.opened_at).slice(0, 10)}</td><td>${esc(a.status)}</td><td>${a.mfa_enabled ? "on" : "off"}</td><td>${a.risk.score} ${chip(a.risk.level)}</td><td class="small muted">${esc(a.risk.factors.map(f => f.label).join("; ").slice(0, 70))}</td><td class="small mono">${esc((a.risk.linked_entities || []).slice(0, 3).join(", "))}</td></tr>`).join("")}</tbody></table>`);
};
async function openAccount(id) {
  const v = await API.get(`/v1/accounts/${id}`);
  openDrawer(`<div class="row"><h2 style="margin:0">Account ${esc(id)}</h2><span style="margin-left:auto"></span>${API.isLive() ? `<button class="btn" id="acc-inv" data-acc="${esc(id)}">Run investigation</button>` : ""}</div>
  <div class="grid c2">${card("Account & customer", kv({...v.account, customer: v.customer ? `${v.customer.name} · ${v.customer.segment} · ${v.customer.home_country}` : "—", "linked accounts": (v.linked_accounts || []).join(", ") || "none"}))}${card("Entity risk", riskBlock(v.risk))}</div>
  ${card("Relationship graph", graphSvg(v.graph))}
  <div class="grid c2">${card("Login sessions", `<table><thead><tr><th>session</th><th>device</th><th>country</th><th>time</th><th>mfa</th><th>events</th><th>decision</th><th></th></tr></thead><tbody>${v.sessions.map(s => `<tr><td class="mono">${esc(s.session_id)}</td><td class="mono">${esc(s.device_id)}</td><td>${esc(s.country)}</td><td class="mono">${fmtTs(s.started_at)}</td><td>${s.mfa_passed ? "✓" : "✗"}</td><td class="small">${esc((s.events || []).join(", "))}</td><td>${v.decisions.filter(d => d.subject_id === s.session_id).map(d => chip(d.final_action)).join("") || ""}</td><td>${API.isLive() ? `<button class="btn small" data-ses="${esc(s.session_id)}">Evaluate</button>` : ""}</td></tr>`).join("")}</tbody></table>`)}${card("Disputes", v.disputes.length ? `<table><thead><tr><th>id</th><th class="num">amount</th><th>claim</th><th>label</th></tr></thead><tbody>${v.disputes.map(d => `<tr><td class="mono">${esc(d.dispute_id)}</td><td class="num">${inr(d.amount)}</td><td>${esc(d.claim_type_declared)}</td><td>${esc(d.label)}</td></tr>`).join("")}</tbody></table>` : empty("none"))}</div>
  ${card("Recent transactions", `<table><thead><tr><th>id</th><th>merchant</th><th class="num">amount</th><th>time</th><th>country</th><th>device</th><th>label</th></tr></thead><tbody>${v.transactions.map(t => `<tr class="row" data-tx="${esc(t.transaction_id)}"><td class="mono">${esc(t.transaction_id)}</td><td class="mono">${esc(t.merchant_id)}</td><td class="num">${inr(t.amount)}</td><td class="mono">${fmtTs(t.timestamp)}</td><td>${esc(t.country)}</td><td class="mono">${esc(t.device_id)}</td><td class="small muted">${esc(t.label)}</td></tr>`).join("")}</tbody></table>`)}
  ${card("Decisions on this account", v.decisions.length ? `<table><thead><tr><th>decision</th><th>workflow</th><th>subject</th><th>final</th><th>risk</th><th>case</th></tr></thead><tbody>${v.decisions.map(d => `<tr class="row" data-dec="${esc(d.decision_id)}"><td class="mono">${esc(d.decision_id)}</td><td>${esc(d.workflow)}</td><td class="mono">${esc(d.subject_id)}</td><td>${chip(d.final_action)}</td><td>${d.risk_score} ${chip(d.risk_level)}</td><td class="mono">${esc(d.case_id || "")}</td></tr>`).join("")}</tbody></table>` : empty("none yet"))}`);
  const b = $("#acc-inv"); if (b) b.onclick = async () => { b.disabled = true; try { const d = await API.post("/v1/investigations/evaluate", {account_id: id}); toast(`investigation: ${d.final_action} (risk ${d.risk_score})`); openAccount(id); } catch (e) { toast(e.message); b.disabled = false; } };
}

VIEWS.investigations = async () => {
  const d = await API.get("/v1/cases?limit=150");
  const st = (window.__caseFilter || "");
  const rows = d.cases.filter(c => !st || c.status === st);
  return card(`Cases & investigations <span class="muted small">${rows.length} shown</span>`, `<div class="tabs">${["", "OPEN", "TRIAGE", "INVESTIGATING", "WAITING_HUMAN", "ESCALATED", "RESOLVED"].map(s => `<button class="${s === st ? "active" : ""}" data-cf="${s}">${s || "all"}</button>`).join("")}</div><table><thead><tr><th>case</th><th>priority</th><th>status</th><th>type</th><th>title</th><th>rule</th><th>entities</th><th>created</th></tr></thead><tbody>${rows.map(c => `<tr class="row" data-case="${esc(c.case_id)}"><td class="mono">${esc(c.case_id)}</td><td>${chip(c.priority)}</td><td>${chip(c.status)}</td><td>${esc(c.case_type)}</td><td>${esc(c.title)}</td><td class="mono small">${esc(c.opened_by_rule)}</td><td class="mono small">${esc(c.entities.slice(0, 2).join(", "))}</td><td class="mono">${fmtTs(c.created_at)}</td></tr>`).join("") || `<tr><td colspan="8">${empty("no cases")}</td></tr>`}</tbody></table>`);
};
async function openCase(id) {
  const v = await API.get(`/v1/cases/${id}`);
  const c = v.case;
  const live = API.isLive();
  openDrawer(`<div class="row"><h2 style="margin:0">${esc(c.title)}</h2>${chip(c.priority)}${chip(c.status)}</div>
  <div class="grid c2">${card("Case", kv({case_id: c.case_id, type: c.case_type, opened_by_rule: c.opened_by_rule, entities: c.entities.join(", "), decisions: c.decision_ids.join(", "), evidence: c.evidence_ids.length + " items", "AI recommendations": c.ai_recommendations.join(", ") || "—", "policy decisions": c.policy_decisions.join(", "), resolution: c.resolution || "—", audit: c.audit_event_ids.join(", ")}))}
  ${card("Human review", live ? `<div class="row"><select id="case-status"><option>TRIAGE</option><option>INVESTIGATING</option><option>WAITING_HUMAN</option><option>ESCALATED</option></select><button class="btn" id="case-move">Transition</button></div><div class="row" style="margin-top:8px"><select id="case-outcome"><option>approve</option><option>deny</option><option>escalate</option></select><input id="case-note" placeholder="reviewer note"><button class="btn primary" id="case-decide">Record human decision</button></div><div class="muted small" style="margin-top:6px">Only a human actor can resolve a case. The model has no path to this control.</div>` : `<div class="muted small">Case actions need the live console.</div>`)}</div>
  ${card("Timeline", `<div class="trail">${c.events.map(e => `<div class="e"><div class="s">${esc(e.kind)}</div><div class="m">${fmtTs(e.created_at)} · ${esc(e.actor)} · ${esc(JSON.stringify(e.detail))}</div></div>`).join("")}${c.human_decisions.map(h => `<div class="e"><div class="s">human decision</div><div class="m">${fmtTs(h.created_at)} · ${esc(h.reviewer)} → <b>${esc(h.outcome)}</b> ${esc(h.note)}</div></div>`).join("")}</div>`)}
  ${(v.decisions || []).map(d => card(`Decision ${esc(d.decision_id)} ${chip(d.final_action)}`, decisionBlock(d))).join("")}
  ${(v.security_events || []).map(e => card(`Security event ${esc(e.event_id)}`, incidentView(e))).join("")}`);
  if (live) {
    $("#case-move").onclick = async () => { try { await API.post(`/v1/cases/${id}/transition`, {status: $("#case-status").value, actor: "analyst"}); toast("transitioned"); openCase(id); } catch (e) { toast(e.message); } };
    $("#case-decide").onclick = async () => { try { await API.post(`/v1/cases/${id}/decision`, {reviewer: "reviewer", outcome: $("#case-outcome").value, note: $("#case-note").value}); toast("recorded"); openCase(id); } catch (e) { toast(e.message); } };
  }
}

function incidentView(e) {
  return `<div class="flow">${[["Agent", e.agent], ["Severity", e.severity], ["Attack", (e.threat_classes || []).join(", ") || "—"], ["Requested capability", e.requested_capability || "none"], ["AI recommendation", e.ai_recommendation || "—"], ["Trusted evidence", e.evidence_verdict || "n/a"], ["Policy", e.policy_id || "—"], ["Final Sentinel decision", e.final_action || "—"], ["Blocked by", (e.blocked_by || []).join(" + ") || "—"]].map(([t, v], i, a) => `<div class="stage ${t === "Final Sentinel decision" ? (v === "ALLOW" ? "ok" : "alert") : ""}"><div class="t">${t}</div><div class="v">${esc(v)}</div></div>${i < a.length - 1 ? `<div class="arrow">↓</div>` : ""}`).join("")}</div><div class="small muted" style="margin-top:8px">findings: ${(e.findings || []).map(f => `${esc(f.signal)} (${f.weight}, span ${esc(f.span_hash)})`).join("; ") || "structural only"} · content hash ${esc(e.content_hash)} · decision ${esc(e.decision_id || "—")}</div>`;
}

VIEWS.aisecurity = async () => {
  const [ev, atk] = await Promise.all([API.get("/v1/ai/security/events?limit=60"), API.get("/v1/attacks")]);
  const sel = atk.attacks.map(a => `<option value="${esc(a.key)}">${esc(a.name)}</option>`).join("");
  return `<div class="card"><h3>Attack the financial AI <span class="muted">select an attack, edit it, run it against the real engine</span></h3>
    <div class="toolbar"><label class="f" style="min-width:260px">attack<select id="atk-kind">${sel}</select></label><label class="f"><span>unguarded (no controls)</span><select id="atk-ung"><option value="0">off — full Sentinel</option><option value="1">on — model executes</option></select></label><button class="btn primary" id="atk-run">Run attack</button><span class="muted small" id="atk-desc"></span></div>
    <div class="grid c2" style="margin-top:10px"><label class="f">attacker text (USER_CONTROLLED)<textarea id="atk-text"></textarea></label><label class="f">attacker document (DOCUMENT_CONTROLLED)<textarea id="atk-doc"></textarea></label></div>
    <div id="atk-out" style="margin-top:12px"></div></div>
  ${card(`AI security events <span class="muted">${ev.events.length}</span>`, ev.events.length ? `<table><thead><tr><th>event</th><th>time</th><th>agent</th><th>severity</th><th>attack</th><th>requested</th><th>AI said</th><th>evidence</th><th>final</th></tr></thead><tbody>${ev.events.map(e => `<tr class="row" data-sec="${esc(e.event_id)}"><td class="mono">${esc(e.event_id)}</td><td class="mono">${fmtTs(e.created_at)}</td><td>${esc(e.agent)}</td><td>${chip(e.severity)}</td><td class="small">${esc((e.threat_classes || []).join(", "))}</td><td class="mono small">${esc(e.requested_capability || "")}</td><td class="mono small">${esc(e.ai_recommendation || "")}</td><td>${e.evidence_verdict ? chip(e.evidence_verdict) : ""}</td><td>${e.final_action ? chip(e.final_action) : ""}</td></tr>`).join("")}</tbody></table>` : empty("no security events yet"))}`;
};
let ATTACKS = null;
async function wireAttacks() {
  if (!ATTACKS) ATTACKS = (await API.get("/v1/attacks")).attacks;
  const kind = $("#atk-kind"), text = $("#atk-text"), doc = $("#atk-doc"), desc = $("#atk-desc");
  const load = () => { const a = ATTACKS.find(x => x.key === kind.value); text.value = a.turns && a.turns.length ? a.turns.map((t, i) => `Turn ${i + 1}: ${t}`).join("\n") : a.narrative; doc.value = a.document || ""; desc.textContent = a.description + " Ledger: " + JSON.stringify(a.ledger); };
  kind.onchange = load; load();
  $("#atk-run").onclick = async () => {
    const a = ATTACKS.find(x => x.key === kind.value);
    const body = {kind: kind.value, unguarded: $("#atk-ung").value === "1"};
    if (text.value !== (a.turns && a.turns.length ? a.turns.map((t, i) => `Turn ${i + 1}: ${t}`).join("\n") : a.narrative)) body.narrative = text.value;
    if (doc.value !== (a.document || "")) body.document = doc.value || null;
    $("#atk-out").innerHTML = `<div class="muted">running…</div>`;
    try { const sb = await API.post("/v1/attacks/simulate", body); $("#atk-out").innerHTML = storyboard(sb); } catch (e) { $("#atk-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; }
  };
}
async function openSecurityEvent(id) { const ev = (await API.get("/v1/ai/security/events?limit=200")).events.find(e => e.event_id === id); if (ev) openDrawer(`<h2 style="margin:0">AI security event ${esc(id)}</h2>` + card("Incident", incidentView(ev))); }

VIEWS.policies = async () => {
  const p = await API.get("/v1/policies");
  const byId = {}; p.policies.forEach(x => (byId[x.policy_id] = byId[x.policy_id] || []).push(x));
  return `<div class="grid c2">${Object.entries(byId).map(([id, versions]) => card(`${esc(id)} <span class="muted">${versions.map(v => "v" + v.version).join(" · ")}</span>`, versions.map(v => `<div style="margin-bottom:10px"><div class="row"><b>v${v.version}</b> <span class="muted small">${esc(v.workflow)} · effective ${esc(v.effective_from)} · default ${esc(v.default_outcome)}</span></div><div class="small muted">${esc(v.description)}</div><table style="margin-top:6px"><tbody>${v.rules.map(r => `<tr><td class="mono small">${esc(r.id)}</td><td class="mono small">${r.when.map(c => `${esc(c.field)} ${esc(c.op)} ${c.value !== undefined ? esc(JSON.stringify(c.value)) : ""}`).join(" AND ")}</td><td>${chip(r.outcome)}</td><td class="small muted">${esc(r.reason)}</td></tr>`).join("")}</tbody></table></div>`).join(""))).join("")}</div>
  ${card("Policy sandbox — evaluate a context against a versioned policy", `<div class="toolbar"><label class="f">policy<select id="pol-id">${Object.keys(byId).map(k => `<option>${esc(k)}</option>`).join("")}</select></label><label class="f">version<input id="pol-ver" placeholder="latest"></label><button class="btn primary" id="pol-go">Evaluate</button></div><label class="f" style="margin-top:8px">context (JSON, trusted fields only — see catalog)<textarea id="pol-ctx">{"amount": 185000, "evidence_verdict": "SUPPORTED", "security_severity": "NONE", "capability_escalation": false, "risk_score": 34, "policy_auto_limit": 50000, "prior_disputes_90d": 0}</textarea></label><div id="pol-out" style="margin-top:10px"></div>`)}
  <div class="note">Policies are explicit, versioned, schema-validated data. All rules are evaluated, the most severe outcome wins, and every match is explained. The policy engine never sees a model recommendation.</div>`;
};

VIEWS.audit = async () => {
  const [a, v] = await Promise.all([API.get("/v1/audit?limit=120"), API.get("/v1/audit/verify")]);
  return `<div class="grid c3"><div class="card kpi"><div class="v">${a.length}</div><div class="l">events in chain</div></div><div class="card kpi"><div class="v" style="font-size:14px;word-break:break-all">${esc(a.head)}</div><div class="l">head hash</div></div><div class="card kpi"><div class="v" style="color:${v.ok ? "var(--ok)" : "var(--bad)"}">${v.ok ? "VERIFIED" : "TAMPERED"}</div><div class="l">hash chain</div><div class="s">${v.problems && v.problems.length ? esc(v.problems[0]) : "hash_n = SHA256(event_n ‖ hash_n−1) · " + v.length + " checked"}</div></div></div>
  ${card("Audit events <span class='muted'>hashes of untrusted content only — never prose</span>", `<table><thead><tr><th>#</th><th>time</th><th>kind</th><th>workflow</th><th>action</th><th>decision</th><th>capability</th><th>risk</th><th>policy</th><th>security</th><th>case</th><th>hash</th></tr></thead><tbody>${a.events.map(e => `<tr class="row" data-dec="${esc(e.decision_id || "")}"><td class="num">${e.sequence}</td><td class="mono">${fmtTs(e.timestamp)}</td><td>${esc(e.kind)}</td><td>${esc(e.workflow)}</td><td>${chip(e.action.replace("REPLAY:", ""), e.action.replace("REPLAY:", ""))}</td><td class="mono small">${esc(e.decision_id || "")}</td><td class="mono small">${esc(e.capability || "")}</td><td class="num">${e.risk_score}</td><td class="mono small">${esc(e.policy_id ? e.policy_id + "@v" + e.policy_version : "")}</td><td>${chip(e.security_severity)}</td><td class="mono small">${esc(e.case_id || "")}</td><td class="mono small">${esc(e.event_hash.slice(0, 12))}…</td></tr>`).join("")}</tbody></table>`)}`;
};
async function openDecision(id) {
  if (!id) return;
  const v = await API.get(`/v1/decisions/${id}`);
  openDrawer(`<h2 style="margin:0">Decision ${esc(id)} ${chip(v.decision.final_action)}</h2>${card("Decision", decisionBlock(v.decision))}${card("Evidence", evidenceTable(v.evidence))}${v.audit_event ? card("Audit event", kv(v.audit_event, ["sequence", "event_hash", "previous_hash", "action", "capability", "policy_id", "policy_version", "evidence_ids", "input_hash"])) : ""}`);
}

VIEWS.replay = async () => {
  const [d, r] = await Promise.all([API.get("/v1/decisions?limit=60"), API.get("/v1/replays")]);
  const opts = d.decisions.filter(x => x.controls && x.controls.includes("policy")).map(x => `<option value="${esc(x.decision_id)}">${esc(x.decision_id)} · ${esc(x.workflow)} · ${esc(x.final_action)} · ${x.policy.policy_id}@v${x.policy.version} · risk ${x.risk_score}</option>`).join("");
  return `${card("Decision replay — rerun a stored decision under different versions", `<div class="grid c2"><label class="f">decision<select id="rp-dec">${opts}</select></label><label class="f">policy version<input id="rp-pv" placeholder="e.g. 1 or 2"></label><label class="f">risk model<select id="rp-rm"><option value="">(keep)</option><option>txn-1.0</option><option>txn-1.1</option></select></label><label class="f">rule threshold override (rule_id=value)<input id="rp-rule" placeholder="review-critical-risk=70"></label><label class="f">AI recommendation override (demonstrates irrelevance)<select id="rp-ai"><option value="">(keep)</option><option>approve_refund</option><option>deny</option><option>release_funds</option><option>unfreeze_account</option><option>skip_review</option></select></label><label class="f">controls<select id="rp-ctl"><option value="">(keep)</option><option value="none">none — unguarded</option></select></label></div><div class="row" style="margin-top:10px"><button class="btn primary" id="rp-go">Replay</button><span class="muted small">Replay is deterministic: the composer is a pure function of the stored input snapshot.</span></div><div id="rp-out" style="margin-top:12px"></div>`)}
  ${card(`Replay history <span class="muted">${r.replays.length}</span>`, r.replays.length ? `<table><thead><tr><th>replay</th><th>decision</th><th>overrides</th><th>before</th><th>after</th><th>changed</th><th>explanation</th></tr></thead><tbody>${r.replays.map(x => `<tr><td class="mono">${esc(x.replay_id)}</td><td class="mono">${esc(x.decision_id)}</td><td class="small">${esc(x.overrides.join("; "))}</td><td>${chip(x.original.final_action)}</td><td>${chip(x.replayed.final_action)}</td><td>${x.changed ? "yes" : "no"}</td><td class="small">${esc(x.explanation)}</td></tr>`).join("")}</tbody></table>` : empty("no replays yet"))}`;
};
function replayView(x) {
  const keys = Object.keys(x.original);
  return `<div class="headline">${esc(x.explanation)}</div><div class="diff"><div class="h">field</div><div class="h">original</div><div class="h">replayed</div>${keys.map(k => { const ch = JSON.stringify(x.original[k]) !== JSON.stringify(x.replayed[k]); return `<div>${esc(k)}</div><div>${esc(JSON.stringify(x.original[k]))}</div><div class="${ch ? "changed" : ""}">${esc(JSON.stringify(x.replayed[k]))}</div>`; }).join("")}</div>`;
}

VIEWS.evaluations = async () => {
  const e = await API.get("/v1/evaluations");
  const R = e.results || {};
  if (!e.available || !e.available.length) return card("Evaluations", empty("No results yet. Run `make eval` (sentinel eval run --suite full) to produce results/*.json."));
  const s = R.security, h = R.heldout, ab = R.ablation, b = R.baselines, f = R.financial, it = R.integrity, p = R.performance, k = R.kyb, m = R.models;
  const pctc = (v) => v == null ? "—" : (v * 100).toFixed(1) + "%";
  let html = "";
  if (s) html += `<div class="grid c4"><div class="card kpi"><div class="v">${pctc(s.asr_unguarded)}</div><div class="l">attack success — no controls</div><div class="s">${s.n_attacks} attacks, ${s.n_controls} controls</div></div><div class="card kpi"><div class="v" style="color:var(--ok)">${pctc(s.asr_guarded)}</div><div class="l">attack success — Sentinel</div><div class="s">unauthorised capability executed</div></div><div class="card kpi"><div class="v">${pctc(s.detection_recall)}</div><div class="l">gateway detection recall</div><div class="s">lexical; not the backstop</div></div><div class="card kpi"><div class="v" style="color:var(--ok)">${pctc(s.fp_rate)}</div><div class="l">false positives</div><div class="s">deserved refunds wrongly held</div></div></div>`;
  if (s) html += `<div class="grid c2">${card("Attack success by class (no controls → Sentinel)", `<div class="chart">${hbarChart(Object.fromEntries(Object.entries(s.by_class).map(([k, v]) => [k, v.asr_unguarded])), {pct: true, color: "#e2574f"})}</div>`)}${card("Gateway detection recall by class", `<div class="chart">${hbarChart(Object.fromEntries(Object.entries(s.by_class).map(([k, v]) => [k, v.detection_recall])), {pct: true, color: "#e0a83a"})}</div>`)}</div>`;
  if (ab) html += card("Ablation — which control carries the result (ASR)", `<div class="chart">${barChart(Object.fromEntries(Object.entries(ab).map(([k, v]) => [k, v.asr])), {pct: true, color: (k) => ab[k].asr > 0.2 ? "#e2574f" : ab[k].asr > 0 ? "#e0a83a" : "#4f8cff", height: 190})}</div>`);
  html += `<div class="grid c2">${b ? card("Beating the obvious defence (ASR)", `<div class="chart">${barChart({no_defence: b.no_defence, hardened_prompt: b.hardened_prompt, sentinel: b.sentinel}, {pct: true, color: (k) => k === "no_defence" ? "#e2574f" : k === "hardened_prompt" ? "#e0a83a" : "#4f8cff"})}</div><div class="muted small">hardened prompt still fails: ${esc(Object.entries(b.hardened_by_class).filter(([, v]) => v > 0).map(([k, v]) => `${k} ${pctc(v)}`).join(", ") || "—")}</div>`) : ""}${h ? card("Held-out generalisation (unseen wording)", kv({attacks: h.n_attacks, "deserved controls": h.n_deserved_controls, "ASR no controls": pctc(h.asr_unguarded), "ASR Sentinel": pctc(h.asr_guarded), "detection recall": pctc(h.detection_recall), "false positives": pctc(h.fp_rate)})) : ""}</div>`;
  if (it) html += card("Decision integrity — can untrusted input loosen a decision?", `<div class="chart">${barChart({"text · no controls": it.text_influence_permissive_unguarded, "text · Sentinel": it.text_influence_permissive_protected, "model output · Sentinel": it.model_influence_protected, "legit+injection loosened": it.legit_plus_injection_loosened}, {pct: true, color: (k) => k.includes("no controls") ? "#e2574f" : "#4f8cff"})}</div><div class="muted small">${esc(it.note)}</div>`);
  if (f) html += `<div class="grid c2">${card("Financial risk on labelled synthetic data", kv({transactions: f.dataset.transactions, model: f.risk_model, positive: f.positive_definition, precision: pctc(f.precision), recall: pctc(f.recall), "false positive rate": pctc(f.false_positive_rate), "false negative rate": pctc(f.false_negative_rate), prevalence: pctc(f.prevalence), "policy: fraud allowed": pctc(f.policy_sample.fraud_allowed_rate), "policy: legit blocked/denied": pctc(f.policy_sample.legit_blocked_or_denied_rate)}))}${card("Recall by scenario / calibration", `<div class="chart">${hbarChart(Object.fromEntries(Object.entries(f.recall_by_scenario).map(([k, v]) => [k.replace("fraud:", ""), v.recall])), {pct: true})}</div><div class="chart">${barChart(Object.fromEntries(Object.entries(f.calibration).map(([k, v]) => [k, v.observed_fraud_rate])), {order: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], pct: true, height: 140})}</div><div class="muted small">observed fraud rate per band</div>`)}</div>`;
  if (k) html += card("Second surface — KYB onboarding", kv({attacks: k.attacks, controls: k.controls, "ASR no controls": pctc(k.asr_unguarded), "ASR Sentinel": pctc(k.asr_guarded), "false positives": pctc(k.fp_rate), "borderline → review": pctc(k.borderline_to_review)}));
  if (p) html += card(`Performance (offline, ${esc(p.platform)})`, `<table><thead><tr><th>component</th><th class="num">p50 ms</th><th class="num">p95 ms</th><th class="num">p99 ms</th><th class="num">ops/s</th></tr></thead><tbody>${Object.entries(p.components).map(([n, v]) => `<tr><td class="mono">${esc(n)}</td><td class="num">${v.p50_ms}</td><td class="num">${v.p95_ms}</td><td class="num">${v.p99_ms}</td><td class="num">${v.throughput_per_sec}</td></tr>`).join("")}</tbody></table><div class="muted small">${esc(p.workloads.note)}</div>`);
  if (m) html += card("Model / provider evaluation", `<table><thead><tr><th>provider</th><th>model</th><th>status</th><th class="num">ASR no controls</th><th class="num">ASR Sentinel</th><th class="num">FP</th><th class="num">agent latency ms</th></tr></thead><tbody>${m.results.map(x => `<tr><td>${esc(x.provider)}</td><td class="mono">${esc(x.model)}</td><td>${esc(x.status)}${x.reason ? ` <span class="muted small">${esc(x.reason)}</span>` : ""}</td><td class="num">${pctc(x.asr_unguarded)}</td><td class="num">${pctc(x.asr_guarded)}</td><td class="num">${pctc(x.fp_rate)}</td><td class="num">${x.mean_agent_latency_ms ?? "—"}</td></tr>`).join("")}</tbody></table><div class="muted small">${esc(m.note)}</div>`);
  return html + `<div class="note">All figures are measured by <code>sentinel eval run --suite full</code> on synthetic corpora and datasets. Limitations are documented in docs/EVALUATION.md and docs/LIMITATIONS.md.</div>`;
};

VIEWS.system = async () => {
  const s = await API.get("/v1/system");
  return `<div class="grid c2">${card("System", kv({name: s.name, version: s.version, mode: s.mode, provider: s.provider, model: s.model, store: s.store, "audit chain": s.audit.ok ? `verified (${s.audit.length} events)` : "TAMPERED", "console source": API.isLive() ? "live API" : "static snapshot (read-only)"}))}${card("Policies & risk models", `<div class="pill-list">${s.policies.map(p => chip(p, "trusted")).join("")}</div><div class="pill-list" style="margin-top:8px">${s.risk_models.map(m => chip(m, "model")).join("")}</div>`)}</div>
  ${card("In-process metrics", `<div class="grid c2"><div>${kv(s.metrics.counters || {})}</div><div>${Object.keys(s.metrics.latency || {}).length ? `<table><thead><tr><th>key</th><th class="num">n</th><th class="num">p50</th><th class="num">p95</th><th class="num">p99</th></tr></thead><tbody>${Object.entries(s.metrics.latency).map(([k, v]) => `<tr><td class="mono small">${esc(k)}</td><td class="num">${v.n}</td><td class="num">${v.p50_ms}</td><td class="num">${v.p95_ms}</td><td class="num">${v.p99_ms}</td></tr>`).join("")}</tbody></table>` : empty("no latency samples yet")}</div></div>`)}
  ${card("Architecture", `<pre>untrusted information → AI Security Gateway (provenance · normalisation · detection)
        ↓
risk intelligence (transaction · behavioural · entity · graph · monitoring)
        ↓
AI recommendation (MODEL_GENERATED — recorded, never authoritative)
        ↓
trusted-evidence reconciliation (claims vs verified facts · contradictions)
        ↓
versioned policy-as-code → capability authorization → human review
        ↓
action · case · tamper-evident audit chain · replay</pre>`)}`;
};

// ---------- router & wiring --------------------------------------------------------------------
const NAV = [["overview", "Overview"], ["transactions", "Transactions"], ["risk", "Risk"], ["disputes", "Disputes"], ["merchants", "Merchants"], ["accounts", "Accounts"], ["investigations", "Investigations"], ["aisecurity", "AI Security"], ["policies", "Policies"], ["audit", "Audit"], ["replay", "Replay"], ["evaluations", "Evaluations"], ["system", "System"]];
function openDrawer(html) { $("#drawer-body").innerHTML = html; $("#drawer").classList.remove("hidden"); $(".drawer-inner").scrollTop = 0; }
function closeDrawer() { $("#drawer").classList.add("hidden"); }
async function render() {
  const key = (location.hash || "#overview").slice(1).split("/")[0];
  const view = VIEWS[key] || VIEWS.overview;
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active", a.dataset.key === key));
  $("#crumb").textContent = (NAV.find(n => n[0] === key) || NAV[0])[1];
  $("#view").innerHTML = `<div class="muted">loading…</div>`;
  try { $("#view").innerHTML = await view(); } catch (e) { $("#view").innerHTML = `<div class="note">${esc(e.message)}</div>`; }
  if (key === "aisecurity") wireAttacks();
  if (key === "risk") $("#rk-go").onclick = async () => { try { const r = await API.get(`/v1/risk/${$("#rk-type").value}/${encodeURIComponent($("#rk-id").value.trim())}`); $("#rk-out").innerHTML = riskBlock(r); } catch (e) { $("#rk-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; } };
  if (key === "policies") $("#pol-go").onclick = async () => { try { const ctx = JSON.parse($("#pol-ctx").value); const body = {policy_id: $("#pol-id").value, context: ctx}; if ($("#pol-ver").value) body.version = parseInt($("#pol-ver").value, 10); const r = await API.post("/v1/policies/evaluate", body); $("#pol-out").innerHTML = `<div class="row">${chip(r.outcome)} <span class="muted small">${esc(r.policy_id)}@v${r.version} · matched ${r.matched_rules.length}</span></div><ul class="small">${r.explanations.map(x => `<li>${esc(x)}</li>`).join("") || "<li>no rule matched — default outcome</li>"}</ul>`; } catch (e) { $("#pol-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; } };
  if (key === "replay") $("#rp-go").onclick = async () => { const body = {decision_id: $("#rp-dec").value}; if ($("#rp-pv").value) body.policy_version = parseInt($("#rp-pv").value, 10); if ($("#rp-rm").value) body.risk_model = $("#rp-rm").value; if ($("#rp-rule").value) { const [k, v] = $("#rp-rule").value.split("="); body.rule_values = {[k.trim()]: isNaN(Number(v)) ? v : Number(v)}; } if ($("#rp-ai").value) { body.ai_recommendation = $("#rp-ai").value; const caps = {approve_refund: "APPROVE_REFUND", release_funds: "RELEASE_FUNDS", unfreeze_account: "UNFREEZE_ACCOUNT", skip_review: "SKIP_REVIEW"}; if (caps[body.ai_recommendation]) body.ai_capability = caps[body.ai_recommendation]; } if ($("#rp-ctl").value === "none") body.controls = []; try { const r = await API.post("/v1/replay", body); $("#rp-out").innerHTML = replayView(r); } catch (e) { $("#rp-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; } };
}
document.addEventListener("click", (ev) => {
  const t = ev.target.closest("[data-tx],[data-mer],[data-acc],[data-case],[data-sec],[data-dec],[data-dsp],[data-ses],[data-cf],[data-factor]");
  if (!t) return;
  if (t.dataset.tx) openTransaction(t.dataset.tx);
  else if (t.dataset.mer) openMerchant(t.dataset.mer);
  else if (t.dataset.acc) openAccount(t.dataset.acc);
  else if (t.dataset.case) openCase(t.dataset.case);
  else if (t.dataset.sec) openSecurityEvent(t.dataset.sec);
  else if (t.dataset.dec !== undefined) openDecision(t.dataset.dec);
  else if (t.dataset.dsp) evaluateDispute(t.dataset.dsp);
  else if (t.dataset.ses) API.post("/v1/accounts/evaluate", {session_id: t.dataset.ses}).then(d => openDrawer(`<h2 style="margin:0">Login ${esc(t.dataset.ses)} ${chip(d.final_action)}</h2>` + card("Decision", decisionBlock(d)))).catch(e => toast(e.message));
  else if (t.dataset.cf !== undefined) { window.__caseFilter = t.dataset.cf; render(); }
  else if (t.dataset.factor) toast(`factor ${t.dataset.factor}: ${t.querySelector(".d").textContent}`);
});
$("#drawer-close").onclick = closeDrawer;
$("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
$("#refresh").onclick = render;
window.addEventListener("hashchange", render);
(async () => {
  $("#nav").innerHTML = NAV.map(([k, l], i) => `<a href="#${k}" data-key="${k}"><span class="k">${String(i + 1).padStart(2, "0")}</span>${l}</a>`).join("");
  try {
    const src = await API.init();
    const sys = API.live || API.snap.system;
    $("#mode-badge").className = "badge " + (sys.mode === "live" ? "purple" : "info"); $("#mode-badge").textContent = `${sys.mode} · ${sys.model}`;
    $("#chain-badge").className = "badge " + (sys.audit.ok ? "ok" : "bad"); $("#chain-badge").textContent = sys.audit.ok ? `audit chain ✓ ${sys.audit.length}` : "audit chain broken";
    $("#source-badge").textContent = src === "live" ? "live API" : "static snapshot — run `make ui` for live";
    render();
  } catch (e) { $("#view").innerHTML = `<div class="note">Could not reach the API or a snapshot: ${esc(e.message)}. Start the console with <code>make ui</code>.</div>`; }
})();
})();
