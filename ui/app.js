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
    const view = (table, key) => { const v = (s[table] || {})[key]; if (!v) throw new Error("not in static snapshot"); return v; };
    if (p === "/v1/system") return s.system;
    if (p === "/v1/overview") return s.overview;
    if (p === "/v1/transactions") return s.transactions;
    if (m(/^\/v1\/transactions\/(.+)$/)) return view("transaction_views", m(/^\/v1\/transactions\/(.+)$/)[1]);
    if (p === "/v1/disputes") return s.disputes;
    if (p === "/v1/merchants") return s.merchants;
    if (m(/^\/v1\/merchants\/(.+)$/)) return view("merchant_views", m(/^\/v1\/merchants\/(.+)$/)[1]);
    if (p === "/v1/accounts") return s.accounts;
    if (m(/^\/v1\/accounts\/(.+)$/)) return view("account_views", m(/^\/v1\/accounts\/(.+)$/)[1]);
    if (p === "/v1/cases") return s.cases;
    if (m(/^\/v1\/cases\/([^/]+)\/review$/)) return view("case_reviews", m(/^\/v1\/cases\/([^/]+)\/review$/)[1]);
    if (m(/^\/v1\/cases\/([^/]+)$/)) return view("case_views", m(/^\/v1\/cases\/([^/]+)$/)[1]);
    if (p === "/v1/ai/security/events") return s.security_events;
    if (p === "/v1/policies") return s.policies;
    if (p === "/v1/policies/lint") { const k = `${body.policy_id}@v${body.version}`; const f = (s.policy_lint || {})[k] || []; return {valid: true, clean: !f.length, findings: f, policy: k}; }
    if (p === "/v1/capabilities") return s.capabilities;
    if (p === "/v1/audit") return s.audit;
    if (p === "/v1/audit/verify") return s.audit_verify;
    if (p === "/v1/decisions") return s.decisions;
    if (m(/^\/v1\/decisions\/(.+)$/)) return view("decision_views", m(/^\/v1\/decisions\/(.+)$/)[1]);
    if (p === "/v1/replays") return s.replays;
    if (p === "/v1/attacks") return s.attacks;
    if (p === "/v1/attacks/simulate") {
      if (body.narrative != null || body.document != null || body.unguarded) throw new Error("Custom attacks need the live API (run `make api`). Presets shown are real engine output.");
      return body.compare ? view("attack_compare", body.kind) : view("attack_results", body.kind);
    }
    if (p === "/v1/scenarios") return s.scenarios;
    if (m(/^\/v1\/scenarios\/([a-z_]+)\/run$/)) return view("scenario_results", m(/^\/v1\/scenarios\/([a-z_]+)\/run$/)[1]);
    if (p === "/v1/evaluations") return s.evaluations;
    throw new Error("This action needs the live API: run `make api`.");
  }
};

// ---------- utils -------------------------------------------------------------------------
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const inr = (n) => "₹" + Number(n || 0).toLocaleString("en-IN");
const pctc = (v, d = 1) => v == null ? "—" : (v * 100).toFixed(d) + "%";
const chip = (v, cls) => `<span class="chip ${esc(cls || v)}">${esc(v)}</span>`;
const kind = (k) => chip(k, "kind-" + k);
const trustChip = (t) => chip(t, (t === "TRUSTED_INTERNAL" || t === "VERIFIED_EXTERNAL") ? "trusted" : t === "MODEL_GENERATED" ? "model" : "untrusted");
const fmtTs = (s) => (s || "").replace("T", " ").slice(0, 19);
const toast = (m) => { const t = $("#toast"); t.textContent = m; t.classList.remove("hidden"); clearTimeout(t._h); t._h = setTimeout(() => t.classList.add("hidden"), 3500); };
const kv = (obj, keys) => `<div class="kv">${(keys || Object.keys(obj)).map(k => `<div class="k">${esc(k)}</div><div class="v">${esc(typeof obj[k] === "object" && obj[k] !== null ? JSON.stringify(obj[k]) : obj[k])}</div>`).join("")}</div>`;
const card = (title, body, extra = "", src = "") => `<div class="card"><h3>${title}${extra}</h3>${body}${src ? `<div class="src">source · ${esc(src)}</div>` : ""}</div>`;
const empty = (m) => `<div class="empty">${esc(m)}</div>`;
const legend = () => `<div class="trust-legend"><span><i class="t-user"></i>USER / MERCHANT / DOCUMENT INPUT — untrusted</span><span><i class="t-model"></i>MODEL OUTPUT — untrusted, recorded only</span><span><i class="t-trusted"></i>TRUSTED EVIDENCE — institution records</span><span><i class="t-decision"></i>DETERMINISTIC DECISION — gateway · policy · authorization</span></div>`;
const claimLine = (rec) => { const c = rec && rec.claim; if (!c) return `<div class="src">claim read from prose: none (records-only workflow)</div>`; const k = c.kind || "claim"; return `<div class="src">claim read from prose ${trustChip(c.trust || "USER_CONTROLLED")}: <b>${esc(c.claim_type)}</b> · ${esc(k === "abstain" ? "ABSTAIN — could not read a claim; held for a human" : k === "non_claim" ? "recognised non-claim — nothing refundable asserted" : "claim")} · confidence ${esc(((c.confidence ?? 1) * 100).toFixed(0))}% · signals: ${esc((c.signals || []).join(", ") || "—")} · the claim only selects which trusted field is checked</div>`; };
const meth = (r, file) => r && r.methodology ? `<div class="src">source · results/${esc(file)}.json · ${esc(r.methodology.kind)} · method: ${esc(r.methodology.method)} · limitations: ${esc(r.methodology.limitations)}${r.methodology.sample ? " · sample: " + esc(Object.entries(r.methodology.sample).filter(([, v]) => typeof v !== "object").map(([a, b]) => a + "=" + b).join(", ")) : ""}</div>` : "";
const STAGE_KIND = {untrusted_input: "user", ai_security_gateway: "decision", ai_recommendation: "model", trusted_evidence: "trusted", policy: "decision", authorization: "decision", final: "decision", case: "decision", audit: "decision"};

// ---------- charts (inline SVG) -------------------------------------------------------------
const COLORS = {LOW:"#3fbf7f",MEDIUM:"#e0a83a",HIGH:"#e2574f",CRITICAL:"#ff3b30",ALLOW:"#3fbf7f",DENY:"#e2574f",BLOCK:"#ff3b30",REQUIRE_HUMAN_REVIEW:"#e0a83a",STEP_UP:"#5da5ff",TEMPORARY_HOLD:"#9d7cff",NONE:"#7d8797",OPEN:"#5da5ff",TRIAGE:"#9d7cff",INVESTIGATING:"#e0a83a",WAITING_HUMAN:"#e0a83a",RESOLVED:"#3fbf7f",ESCALATED:"#e2574f"};
function barChart(data, {order = null, height = 170, color = null, pct = false} = {}) {
  const keys = order ? order.filter(k => k in data) : Object.keys(data);
  if (!keys.length) return empty("no data yet");
  const W = 420, H = height, pad = 26, bw = (W - pad * 2) / keys.length;
  const max = Math.max(1e-9, ...keys.map(k => data[k]));
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  keys.forEach((k, i) => {
    const v = data[k], h = (H - 40) * v / max, x = pad + i * bw + bw * 0.15, y = H - 24 - h;
    const c = color ? color(k) : (COLORS[k] || "#4f8cff");
    s += `<rect x="${x}" y="${y}" width="${bw * 0.7}" height="${Math.max(0, h)}" rx="3" fill="${c}"/>`;
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
  g.edges.forEach(e => { const a = pos[e.src], b = pos[e.dst]; if (!a || !b) return; s += `<line class="edge" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}"/><text class="el" x="${(a[0] + b[0]) / 2}" y="${(a[1] + b[1]) / 2 - 2}" text-anchor="middle">${esc(e.rel)}${e.ts ? " · " + esc(String(e.ts).slice(0, 10)) : ""}</text>`; });
  g.nodes.forEach(n => { const p = pos[n.key]; if (!p) return; const r = n.key === root ? 9 : 6; s += `<circle cx="${p[0]}" cy="${p[1]}" r="${r}" fill="${kc[n.kind] || "#aab3c2"}" stroke="#0b0e13" stroke-width="1.5"/><text x="${p[0]}" y="${p[1] + r + 10}" text-anchor="middle">${esc(n.id.length > 14 ? n.id.slice(0, 14) + "…" : n.id)}</text>`; });
  s += `</svg><div class="legend">${Object.entries(kc).filter(([k]) => g.nodes.some(n => n.kind === k)).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join("")}${g.truncated ? `<span class="subtle">showing ${g.nodes.length} of ${g.total_nodes} nodes — structural entities kept, event nodes trimmed</span>` : ""}</div>`;
  return `<div class="graph">${s}</div>`;
}

// ---------- shared renderers ---------------------------------------------------------------
function components(c) {
  const keys = Object.keys(c || {});
  if (!keys.length) return "";
  const max = Math.max(1, ...keys.map(k => Math.abs(c[k])));
  return `<div class="components">${keys.sort().map(k => `<div>${esc(k.replace(/_/g, " "))}</div><div class="cb"><i style="width:${Math.min(100, Math.abs(c[k]) * 100 / max)}%"></i></div><div class="cn">${c[k] >= 0 ? "+" : ""}${c[k]}</div>`).join("")}</div>`;
}
function riskBlock(r) {
  if (!r) return empty("no risk assessment");
  const factors = [...(r.factors || [])].sort((a, b) => b.points - a.points);
  const raw = factors.reduce((s, f) => s + f.points, 0);
  return `<div class="score"><span class="n">${r.score}</span><span class="m">/ 100${raw !== r.score ? ` <span class="subtle">(uncapped ${raw})</span>` : ""}</span> ${chip(r.level)} <span class="muted small">${esc(r.model_version || "")}${r.as_of ? " · as of " + esc(fmtTs(r.as_of)) : ""}</span></div>
  <div class="bar"><i style="width:${Math.min(100, r.score)}%"></i></div>
  ${components(r.components)}
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
    <div class="callout decision"><div class="sec-h" style="margin-bottom:6px">Deterministic decision ${chip("DETERMINISTIC", "kind-empirical")}</div>${kv({
      "final action": d.final_action, "executed capability": d.executed_capability || "none", "requested capability": d.requested_capability || "none",
      "evidence verdict": d.evidence_verdict, "contradictions": d.contradiction_count, "security severity": d.security_severity,
      "policy": `${d.policy.policy_id}@v${d.policy.version} → ${d.policy.outcome}`, "policy hash": d.policy.policy_hash || "—", "matched rules": (d.policy.matched_rules || []).join(", ") || "none",
      "authorization": `${d.authorization.status} — ${d.authorization.reason}`, "blocked by": (d.blocked_by || []).join(", ") || "—",
      "human review": d.human_review.required ? ("required" + (d.case_id ? " · " + d.case_id : "")) : "no", "audit event": d.audit_event_id || "—", "decision id": d.decision_id, "controls": (d.controls || []).join(", ") || "none (unguarded)",
    })}</div>
    <div class="callout model"><div class="sec-h" style="margin-bottom:6px">LLM recommendation ${trustChip("MODEL_GENERATED")}</div>${ai ? kv({agent: ai.agent, recommended: ai.recommended_action, "requested capability": ai.requested_capability || "none", "model's amount": ai.amount, rationale: ai.rationale, provider: `${ai.provider}/${ai.model}`, "agreed with outcome": d.ai_agreed}) : `<div class="muted">no model call (skip_agent)</div>`}<div class="subtle" style="margin-top:6px">Recorded for explainability and measurement. Never an input to the decision.</div></div>
  </div>
  <h3 style="margin-top:12px">Decision trail</h3><div class="trail">${(d.trail || []).map(t => `<div class="e"><div class="s">${esc(t.stage)}</div><div class="m">${esc(t.summary)}</div>${t.detail && Object.keys(t.detail).length ? `<div class="d">${esc(JSON.stringify(t.detail)).slice(0, 400)}</div>` : ""}</div>`).join("")}</div>`;
}
function stages(st) {
  return `<div class="flow">${st.map((s, i) => `<div class="stage ${s.status} k-${STAGE_KIND[s.stage] || "decision"}"><div class="t">${esc(s.title)}</div><div class="v">${esc(s.value)}</div></div>${i < st.length - 1 ? `<div class="arrow">↓</div>` : ""}`).join("")}</div>`;
}
function storyboard(sb) {
  const meta = `<div class="row small muted" style="margin:6px 0">${sb.attack_class ? chip(sb.attack_class, "untrusted") : ""} target ${chip(sb.target_workflow || "dispute", "trusted")} → ${chip(sb.target_capability || "APPROVE_REFUND", "kind-structural")} · controls: <span class="mono">${esc((sb.controls || []).join(", ") || "none")}</span> · first blocked at: <span class="mono">${esc(sb.blocked_layer || "—")}</span></div>`;
  return `<div class="headline">${esc(sb.headline)}</div>${meta}${legend()}
  <div class="split"><div>${card("Attacker input " + trustChip("USER_CONTROLLED"), `<pre>${esc(sb.attacker_input)}</pre>`)}${sb.attacker_document ? card("Attacker document " + trustChip("DOCUMENT_CONTROLLED"), `<pre>${esc(sb.attacker_document)}</pre>`) : ""}${card("Trusted ledger " + trustChip("TRUSTED_INTERNAL"), kv(sb.ledger || {}))}</div>
  <div>${stages(sb.stages || [])}</div></div>
  <div class="card"><h3>Full decision</h3>${decisionBlock(sb.decision)}</div>
  ${sb.reconciliation ? card("Evidence (claims vs verified facts)", claimLine(sb.reconciliation) + evidenceTable(sb.reconciliation.evidence.items) + (sb.reconciliation.contradictions.length ? `<div class="note" style="margin-top:8px">CONTRADICTION: ${sb.reconciliation.contradictions.map(c => `${esc(c.field)} claimed <b>${esc(String(c.claimed))}</b>, recorded <b>${esc(String(c.recorded))}</b> → ${esc(c.impact)}`).join("; ")}</div>` : "")) : ""}
  ${sb.risk ? card("Dispute risk", riskBlock(sb.risk)) : ""}`;
}
function compareView(c) {
  const side = (s, cls) => `<div class="side ${cls}"><h4>${esc(s.label)}</h4>${s.caveat ? `<div class="caveat">${esc(s.caveat)}</div>` : ""}${stages(s.stages || [])}<div class="headline" style="margin-top:10px;font-size:14px">${esc(s.headline)}</div></div>`;
  const sm = c.summary || {};
  return `<div class="row small muted" style="margin:6px 0">${chip(c.attack_class, "untrusted")} target ${chip(c.target_workflow, "trusted")} → ${chip(c.target_capability, "kind-structural")}</div>${legend()}
  <div class="compare">${side(c.without_sentinel, "bad")}${side(c.with_sentinel, "good")}</div>
  <div class="note" style="margin-top:10px">Agent recommended <b>${esc(sm.agent_recommendation)}</b>. Without Sentinel the executed capability was <b>${esc(sm.without_sentinel_executed || "none")}</b>. With Sentinel: <b>${esc(sm.with_sentinel_final_action)}</b> (executed ${esc(sm.with_sentinel_executed || "none")}), first blocked at <b>${esc(sm.blocked_layer || "—")}</b>; blocked by ${esc((sm.blocked_by || []).join(", "))}.</div>
  <div class="card"><h3>WITH SENTINEL — full decision</h3>${decisionBlock(c.with_sentinel.decision)}</div>
  ${c.with_sentinel.reconciliation ? card("Evidence (claims vs verified facts)", claimLine(c.with_sentinel.reconciliation) + evidenceTable(c.with_sentinel.reconciliation.evidence.items)) : ""}`;
}
function timelineView(items, meId) {
  if (!items || !items.length) return empty("no activity in the window");
  return `<div class="timeline">${items.map(x => `<div class="tl ${esc(x.kind)} ${x.id === meId ? "me" : ""} ${x.future ? "future" : ""}"><div class="when">${fmtTs(x.at)}</div><div>${chip(x.kind, x.kind === "transaction" ? "trusted" : x.kind === "session" ? "model" : "REQUIRE_HUMAN_REVIEW")}</div><div class="what">${esc(x.summary)}${x.id === meId ? " <b>← this transaction</b>" : ""}${x.future ? ' <span class="subtle">(after this transaction — not visible to its decision)</span>' : ""}</div></div>`).join("")}</div>`;
}
function evolution(points) {
  if (!points || !points.length) return empty("no decisions on this account yet");
  return `<div class="evo">${points.map(p => `<i class="${esc(p.risk_level)}" style="height:${Math.max(4, p.risk_score)}%" title="${esc(fmtTs(p.event_time))} · ${esc(p.subject_id)} · ${p.risk_score} ${esc(p.risk_level)} · ${esc(p.final_action)}"></i>`).join("")}</div><div class="subtle">${points.length} decisions on this account's transactions and investigations, oldest → newest; hover for detail. Each score was computed as of its own event time.</div>`;
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
  <div class="src">source · GET /v1/overview — aggregates over the decisions, cases, security events and audit chain stored in this instance; every figure is recomputed on refresh and nothing is hard-coded</div>
  ${legend()}
  <div class="grid c3">
    ${card("Risk distribution (transaction decisions)", `<div class="chart">${barChart(o.risk_distribution, {order: ["LOW","MEDIUM","HIGH","CRITICAL"]})}</div>`)}
    ${card("Transaction risk over time (avg score / hour bucket)", `<div class="chart">${lineChart(o.risk_over_time)}</div>`)}
    ${card("Security event severity", `<div class="chart">${barChart(o.security_severity, {order: ["LOW","MEDIUM","HIGH","CRITICAL"]})}</div>`)}
    ${card("Policy actions", `<div class="chart">${barChart(o.policy_actions, {order: ["ALLOW","STEP_UP","REQUIRE_HUMAN_REVIEW","TEMPORARY_HOLD","BLOCK"]})}</div>`)}
    ${card("Case funnel", `<div class="chart">${barChart(o.case_funnel, {order: ["OPEN","TRIAGE","INVESTIGATING","WAITING_HUMAN","ESCALATED","RESOLVED"]})}</div>`)}
    ${card("Decision outcomes", `<div class="chart">${barChart(o.decision_outcomes, {order: ["ALLOW","STEP_UP","REQUIRE_HUMAN_REVIEW","TEMPORARY_HOLD","DENY","BLOCK"]})}</div>`)}
  </div>
  <div class="grid c2">${card("Attack classes observed", `<div class="chart">${hbarChart(o.attack_classes, {color: "#e2574f"})}</div>`)}${card("Decisions by workflow", `<div class="chart">${hbarChart(o.workflow_counts)}</div>`)}</div>
  <div class="note">Every number on this page is computed from decisions this engine actually made over the local <b>synthetic</b> dataset (seed ${esc(o.dataset.seed)}, ${o.dataset.customers} customers, ${o.dataset.merchants} merchants). Nothing is hard-coded, and nothing here is a production statistic.</div>`;
};

VIEWS.transactions = async () => {
  const d = await API.get("/v1/transactions?limit=120");
  return card(`Transactions <span class="muted small">${d.transactions.length} of ${d.total} · click a row to investigate</span>`, `<table><thead><tr><th>id</th><th>time</th><th>account</th><th>merchant</th><th class="num">amount</th><th>country</th><th>device</th><th>auth</th><th>status</th><th>risk</th><th>decision</th><th>case</th></tr></thead><tbody>${d.transactions.map(t => `<tr class="row" data-tx="${esc(t.transaction_id)}"><td class="mono">${esc(t.transaction_id)}</td><td class="mono">${fmtTs(t.timestamp)}</td><td class="mono">${esc(t.account_id)}</td><td class="mono">${esc(t.merchant_id)}</td><td class="num">${inr(t.amount)}</td><td>${esc(t.country)}</td><td class="mono">${esc(t.device_id)}</td><td>${esc(t.auth_strength)}</td><td>${esc(t.status || "settled")}</td><td>${t.decision ? `${t.decision.risk_score} ${chip(t.decision.risk_level)}` : `<span class="muted">—</span>`}</td><td>${t.decision ? chip(t.decision.final_action) : `<span class="muted">not evaluated</span>`}</td><td class="mono">${esc(t.decision && t.decision.case_id || "")}</td></tr>`).join("")}</tbody></table>`);
};
async function openTransaction(id) {
  const v = await API.get(`/v1/transactions/${id}`);
  const t = v.transaction;
  openDrawer(`<div class="row"><h2 style="margin:0">Transaction ${esc(t.transaction_id)}</h2>${v.decision ? chip(v.decision.final_action) : ""}<span style="margin-left:auto"></span>${API.isLive() ? `<button class="btn primary" id="tx-eval" data-tx="${esc(id)}">Evaluate now</button>` : ""}</div>
  ${legend()}
  <div class="grid c3">${card("Transaction " + trustChip("TRUSTED_INTERNAL"), kv({amount: inr(t.amount), timestamp: fmtTs(t.timestamp), country: t.country, channel: t.channel, auth: t.auth_strength, delivery: t.delivery_status, status: t.status || "settled", instrument: t.instrument_id, label: t.label}), "", "payment-switch record in the store; 'label' is the generator's evaluation-only tag, never read by the engine")}${card("Customer & account", kv({customer: v.customer ? `${v.customer.name} (${v.customer.customer_id})` : "—", segment: v.customer && v.customer.segment, home: v.customer && v.customer.home_country, account: v.account && v.account.account_id, opened: v.account && v.account.opened_at, status: v.account && v.account.status, "account risk (as of txn)": v.entity_risk.account.score + " " + v.entity_risk.account.level}))}${card("Merchant & device", kv({merchant: v.merchant ? `${v.merchant.name} (${v.merchant.merchant_id})` : "—", mcc: v.merchant && `${v.merchant.mcc} (${v.merchant.mcc_risk})`, registration: v.merchant && v.merchant.registration_status, "merchant risk (as of txn)": v.entity_risk.merchant.score + " " + v.entity_risk.merchant.level, device: v.device && v.device.device_id, platform: v.device && v.device.platform, "device first seen": v.device && v.device.first_seen, "device risk (as of txn)": v.entity_risk.device.score + " " + v.entity_risk.device.level}))}</div>
  ${card("Timeline — trusted account activity ±7 days (point-in-time: greyed items came after and were invisible to this decision)", timelineView(v.timeline, t.transaction_id))}
  <div class="grid c2">${card("Historical behaviour (baseline, before this transaction)", kv(v.baseline, ["n","average_transaction_amount","transaction_stddev","median_amount","daily_transaction_count","median_gap_hours","merchants_seen","common_countries","common_devices","usual_transaction_hours","chargeback_rate"]), "", "computed from this account's transactions and disputes dated before this transaction (point-in-time)")}${card("Risk score — components and factors", riskBlock(v.risk), "", "risk engine, recomputed over trusted records as of the transaction; point values are Sentinel heuristics (docs/RISK_ENGINE.md)")}</div>
  ${card("Relationship graph (depth 2, current)", graphSvg(v.graph), "", "entity graph as it stands now (edges carry their timestamp); the decision itself used the graph as of the transaction")}
  ${card("Evidence " + trustChip("TRUSTED_INTERNAL"), evidenceTable(v.evidence.length ? v.evidence : (v.risk.factors || []).map(f => ({evidence_id: "risk:" + f.code, kind: "risk_signal", source: "risk_engine", field: f.code, value: f.points, trust: "TRUSTED_INTERNAL", status: "VERIFIED"}))))}
  ${v.security_events && v.security_events.length ? card("AI security events on this decision", v.security_events.map(incidentView).join("")) : ""}
  ${card("Decision — why was this allowed / blocked / reviewed?", decisionBlock(v.decision), "", "the stored decision record: policy, authorization and final action computed from trusted inputs only; the model's recommendation is shown beside it, never inside it")}
  ${v.audit_event ? card("Audit event", kv({sequence: v.audit_event.sequence, event_hash: v.audit_event.event_hash, previous_hash: v.audit_event.previous_hash, action: v.audit_event.action, policy: `${v.audit_event.policy_id}@v${v.audit_event.policy_version}`, evidence_ids: (v.audit_event.evidence_ids || []).join(", ")})) : ""}`);
  const b = $("#tx-eval"); if (b) b.onclick = async () => { b.disabled = true; try { await API.post("/v1/transactions/evaluate", {transaction_id: id}); toast("evaluated"); openTransaction(id); } catch (e) { toast(e.message); b.disabled = false; } };
}

VIEWS.risk = async () => {
  const bands = `<table><thead><tr><th>band</th><th>score</th><th>risk recommendation</th></tr></thead><tbody><tr><td>${chip("LOW")}</td><td class="mono">0–24</td><td>ALLOW</td></tr><tr><td>${chip("MEDIUM")}</td><td class="mono">25–49</td><td>STEP_UP</td></tr><tr><td>${chip("HIGH")}</td><td class="mono">50–74</td><td>REQUIRE_REVIEW</td></tr><tr><td>${chip("CRITICAL")}</td><td class="mono">75–100</td><td>BLOCK</td></tr></tbody></table><div class="muted small" style="margin-top:8px">Sentinel's internal scale for a transparent, replayable rule model over synthetic history — not an industry standard and not ML. Point values are heuristics documented in docs/RISK_ENGINE.md.</div>`;
  const sys = await API.get("/v1/system");
  return `<div class="grid c2">${card("Explain an entity's risk", `<div class="toolbar"><label class="f">entity type<select id="rk-type"><option>transaction</option><option>account</option><option>merchant</option><option>device</option><option>customer</option></select></label><label class="f" style="flex:1">entity id<input id="rk-id" placeholder="TX-000123 / ACC-000004 / MER-000002"></label><button class="btn primary" id="rk-go">Explain</button></div><div id="rk-out" style="margin-top:12px" class="muted small">Pick any id from the Transactions, Accounts or Merchants pages. Entity profiles are computed as of the dataset's "now"; a transaction's profile is computed as of the transaction.</div>`)}${card("Risk bands & models", bands + `<div style="margin-top:10px" class="pill-list">${(sys.risk_models || []).map(m => chip(m, m === sys.default_transaction_model ? "trusted" : "NONE")).join("")}</div><div class="subtle" style="margin-top:6px">default transaction model: ${esc(sys.default_transaction_model || "")}</div>`)}</div>
  <div class="note">Every point on a score is a named factor with the evidence it read, grouped into anomaly · velocity · device/geo · entity · security components. The score is a <b>recommendation</b>; the versioned policy decides the outcome and the capability registry decides who may execute it.</div>`;
};

VIEWS.disputes = async () => {
  const d = await API.get("/v1/disputes?limit=80");
  return card(`Disputes <span class="muted small">narrative and documents are UNTRUSTED input; the ledger decides</span>`, `<table><thead><tr><th>id</th><th>transaction</th><th>account</th><th class="num">amount</th><th>submitted</th><th>claim (declared)</th><th>refund</th><th>merchant</th><th>narrative</th><th>doc</th><th>decision</th><th></th></tr></thead><tbody>${d.disputes.map(x => `<tr><td class="mono">${esc(x.dispute_id)}</td><td class="mono">${esc(x.transaction_id)}</td><td class="mono">${esc(x.account_id)}</td><td class="num">${inr(x.amount)}</td><td class="mono">${fmtTs(x.submitted_at)}</td><td>${esc(x.claim_type_declared)}</td><td>${esc(x.refund_state || "none")}</td><td>${esc(x.merchant_response || "none")}</td><td class="small">${esc((x.texts && x.texts.narrative || "").slice(0, 90))}</td><td>${x.texts && x.texts.document ? trustChip("DOCUMENT_CONTROLLED") : ""}</td><td>${x.decision ? `${chip(x.decision.final_action)} <span class="small muted">${esc(x.decision.evidence_verdict)}</span>` : `<span class="muted">—</span>`}</td><td>${API.isLive() ? `<button class="btn small" data-dsp="${esc(x.dispute_id)}">Evaluate</button>` : ""}</td></tr>`).join("")}</tbody></table>`);
};
async function evaluateDispute(id) {
  try { const d = await API.post("/v1/disputes/evaluate", {dispute_id: id}); openDrawer(`<h2 style="margin:0">Dispute ${esc(id)} ${chip(d.final_action)}</h2>${legend()}` + card("Decision", decisionBlock(d))); } catch (e) { toast(e.message); }
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
  const linked = Object.entries(v.linked_risk || {});
  openDrawer(`<div class="row"><h2 style="margin:0">Account ${esc(id)}</h2><span style="margin-left:auto"></span>${API.isLive() ? `<button class="btn" id="acc-inv" data-acc="${esc(id)}">Run investigation</button>` : ""}</div>
  <div class="grid c2">${card("Account & customer", kv({...v.account, customer: v.customer ? `${v.customer.name} · ${v.customer.segment} · ${v.customer.home_country}` : "—", "linked accounts": (v.linked_accounts || []).join(", ") || "none"}))}${card("Entity risk (as of now)", riskBlock(v.risk))}</div>
  <div class="grid c2">${card("Risk evolution", evolution(v.risk_evolution))}${card("Transaction monitoring (investigation indicators)", v.monitoring ? riskBlock(v.monitoring) : empty("none"))}</div>
  ${linked.length ? card("Linked accounts (shared device / payout instrument)", `<table><thead><tr><th>account</th><th>risk</th><th>factors</th></tr></thead><tbody>${linked.map(([k, r]) => `<tr class="row" data-acc="${esc(k)}"><td class="mono">${esc(k)}</td><td>${r.score} ${chip(r.level)}</td><td class="small muted">${esc((r.factors || []).map(f => f.label).join("; "))}</td></tr>`).join("")}</tbody></table>`) : ""}
  ${card("Relationship graph", graphSvg(v.graph))}
  <div class="grid c2">${card("Login sessions " + trustChip("TRUSTED_INTERNAL"), `<table><thead><tr><th>session</th><th>device</th><th>country</th><th>time</th><th>mfa</th><th>events</th><th>decision</th><th></th></tr></thead><tbody>${v.sessions.map(s => `<tr><td class="mono">${esc(s.session_id)}</td><td class="mono">${esc(s.device_id)}</td><td>${esc(s.country)}</td><td class="mono">${fmtTs(s.started_at)}</td><td>${s.mfa_passed ? "✓" : "✗"}</td><td class="small">${esc((s.events || []).join(", "))}</td><td>${v.decisions.filter(d => d.subject_id === s.session_id).map(d => chip(d.final_action)).join("") || ""}</td><td>${API.isLive() ? `<button class="btn small" data-ses="${esc(s.session_id)}">Evaluate</button>` : ""}</td></tr>`).join("")}</tbody></table>`)}${card("Disputes", v.disputes.length ? `<table><thead><tr><th>id</th><th class="num">amount</th><th>claim</th><th>refund</th><th>merchant</th><th>label</th></tr></thead><tbody>${v.disputes.map(d => `<tr><td class="mono">${esc(d.dispute_id)}</td><td class="num">${inr(d.amount)}</td><td>${esc(d.claim_type_declared)}</td><td>${esc(d.refund_state || "none")}</td><td>${esc(d.merchant_response || "none")}</td><td>${esc(d.label)}</td></tr>`).join("")}</tbody></table>` : empty("none"))}</div>
  ${card("Recent transactions", `<table><thead><tr><th>id</th><th>merchant</th><th class="num">amount</th><th>time</th><th>country</th><th>device</th><th>label</th></tr></thead><tbody>${v.transactions.map(t => `<tr class="row" data-tx="${esc(t.transaction_id)}"><td class="mono">${esc(t.transaction_id)}</td><td class="mono">${esc(t.merchant_id)}</td><td class="num">${inr(t.amount)}</td><td class="mono">${fmtTs(t.timestamp)}</td><td>${esc(t.country)}</td><td class="mono">${esc(t.device_id)}</td><td class="small muted">${esc(t.label)}</td></tr>`).join("")}</tbody></table>`)}
  ${card("Decisions on this account", v.decisions.length ? `<table><thead><tr><th>decision</th><th>workflow</th><th>subject</th><th>final</th><th>risk</th><th>case</th></tr></thead><tbody>${v.decisions.map(d => `<tr class="row" data-dec="${esc(d.decision_id)}"><td class="mono">${esc(d.decision_id)}</td><td>${esc(d.workflow)}</td><td class="mono">${esc(d.subject_id)}</td><td>${chip(d.final_action)}</td><td>${d.risk_score} ${chip(d.risk_level)}</td><td class="mono">${esc(d.case_id || "")}</td></tr>`).join("")}</tbody></table>` : empty("none yet"))}`);
  const b = $("#acc-inv"); if (b) b.onclick = async () => { b.disabled = true; try { const d = await API.post("/v1/investigations/evaluate", {account_id: id}); toast(`investigation: ${d.final_action} (risk ${d.risk_score})`); openAccount(id); } catch (e) { toast(e.message); b.disabled = false; } };
}

VIEWS.investigations = async () => {
  const d = await API.get("/v1/cases?limit=150");
  const st = (window.__caseFilter || "");
  const rows = d.cases.filter(c => !st || c.status === st);
  return card(`Cases & investigations <span class="muted small">${rows.length} shown · open a case for the review packet</span>`, `<div class="tabs">${["", "OPEN", "TRIAGE", "INVESTIGATING", "WAITING_HUMAN", "ESCALATED", "RESOLVED"].map(s => `<button class="${s === st ? "active" : ""}" data-cf="${s}">${s || "all"}</button>`).join("")}</div><table><thead><tr><th>case</th><th>priority</th><th>status</th><th>type</th><th>title</th><th>rule</th><th>entities</th><th>created</th></tr></thead><tbody>${rows.map(c => `<tr class="row" data-case="${esc(c.case_id)}"><td class="mono">${esc(c.case_id)}</td><td>${chip(c.priority)}</td><td>${chip(c.status)}</td><td>${esc(c.case_type)}</td><td>${esc(c.title)}</td><td class="mono small">${esc(c.opened_by_rule)}</td><td class="mono small">${esc(c.entities.slice(0, 2).join(", "))}</td><td class="mono">${fmtTs(c.created_at)}</td></tr>`).join("") || `<tr><td colspan="8">${empty("no cases")}</td></tr>`}</tbody></table>`);
};
async function openCase(id) {
  const pk = await API.get(`/v1/cases/${id}/review`);
  const c = pk.case, why = pk.why_this_case_exists, live = API.isLive();
  const cap = pk.capability || {};
  openDrawer(`<div class="row"><h2 style="margin:0">${esc(c.title)}</h2>${chip(c.priority)}${chip(c.status)}<span class="mono muted small">${esc(c.case_id)}</span></div>
  <div class="headline" style="font-size:14px">Why this case exists — <b>${esc(why.rule)}</b>: ${esc(why.human_review_reason || why.reason)} · final action ${chip(why.final_action || "—")}</div>
  ${legend()}
  <div class="review-grid">
    <div class="card"><h3>Risk ${chip("TRUSTED", "trusted")}</h3>${riskBlock({score: pk.risk.score, level: pk.risk.level, factors: pk.risk.factors, components: pk.risk.components, model_version: pk.risk.model_version})}</div>
    <div class="card"><h3>Policy · capability · authorization ${chip("DETERMINISTIC", "kind-empirical")}</h3>${pk.policy ? kv({policy: `${pk.policy.policy_id}@v${pk.policy.version} → ${pk.policy.outcome}`, "policy hash": pk.policy.policy_hash || "—", "matched rules": (pk.policy.matched_rules || []).join(", ") || "none", capability: cap.requested || "none", authorization: cap.authorization ? `${cap.authorization.status} — ${cap.authorization.reason}` : "—", executed: cap.executed || "none", contradictions: pk.contradictions}) : empty("no policy decision")}<ul class="small">${(pk.policy && pk.policy.explanations || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>
  </div>
  <div class="review-grid">
    <div class="card"><h3>Trusted evidence ${trustChip("TRUSTED_INTERNAL")}</h3>${evidenceTable(pk.trusted_evidence)}</div>
    <div class="card"><h3>Untrusted claims ${trustChip("USER_CONTROLLED")}</h3>${evidenceTable(pk.untrusted_claims)}</div>
  </div>
  <div class="review-grid">
    <div class="callout model"><div class="sec-h" style="margin-bottom:6px">AI recommendation ${trustChip("MODEL_GENERATED")}</div>${pk.ai_recommendation ? kv({recommended: pk.ai_recommendation.recommended_action, "requested capability": pk.ai_recommendation.requested_capability || "none", rationale: pk.ai_recommendation.rationale, provider: `${pk.ai_recommendation.provider}/${pk.ai_recommendation.model}`}) + `<div class="subtle" style="margin-top:6px">${esc(pk.ai_recommendation.note)}</div>` : `<div class="muted">no model recommendation recorded</div>`}</div>
    <div class="card"><h3>Human review ${chip("HUMAN", "kind-empirical")}</h3>${live ? `<div class="row"><select id="case-status"><option>TRIAGE</option><option>INVESTIGATING</option><option>WAITING_HUMAN</option><option>ESCALATED</option></select><button class="btn" id="case-move">Transition</button></div><div class="row" style="margin-top:8px"><select id="case-outcome"><option>approve</option><option>deny</option><option>escalate</option></select><input id="case-note" placeholder="reviewer note"><button class="btn primary" id="case-decide">Record human decision</button></div>` : `<div class="muted small">Case actions need the live console.</div>`}<div class="subtle" style="margin-top:6px">${esc(pk.principle)}</div>${pk.human_decisions.length ? `<div class="trail" style="margin-top:8px">${pk.human_decisions.map(h => `<div class="e"><div class="s">human decision</div><div class="m">${fmtTs(h.created_at)} · ${esc(h.reviewer)} → <b>${esc(h.outcome)}</b> ${esc(h.note)}</div></div>`).join("")}</div>` : ""}</div>
  </div>
  ${card("Case timeline", `<div class="trail">${pk.timeline.map(e => `<div class="e"><div class="s">${esc(e.kind)}</div><div class="m">${fmtTs(e.created_at)} · ${esc(e.actor)} · ${esc(JSON.stringify(e.detail))}</div></div>`).join("")}</div>`)}
  ${card("Entities", `<div class="pill-list">${c.entities.map(e => { const [k, v] = e.split(":"); const attr = k === "account" ? `data-acc="${esc(v)}"` : k === "transaction" ? `data-tx="${esc(v)}"` : k === "merchant" ? `data-mer="${esc(v)}"` : ""; return `<span class="chip trusted" ${attr} style="cursor:${attr ? "pointer" : "default"}">${esc(e)}</span>`; }).join("")}</div>`)}
  ${(pk.security_events || []).map(e => card(`Security event ${esc(e.event_id)}`, incidentView(e))).join("")}
  ${card("Audit history " + chip("hash-chained", "kind-structural"), pk.audit_history.length ? `<table><thead><tr><th>#</th><th>time</th><th>action</th><th>policy</th><th>hash</th></tr></thead><tbody>${pk.audit_history.map(a => `<tr><td class="num">${a.sequence}</td><td class="mono">${fmtTs(a.timestamp)}</td><td>${chip(a.action.replace("REPLAY:", ""), a.action.replace("REPLAY:", ""))}</td><td class="mono small">${esc(a.policy_id ? a.policy_id + "@v" + a.policy_version : "")}</td><td class="mono small">${esc(a.event_hash.slice(0, 16))}…</td></tr>`).join("")}</tbody></table>` : empty("none"))}
  ${(pk.decisions || []).map(d => card(`Decision ${esc(d.decision_id)} ${chip(d.final_action)}`, decisionBlock(d))).join("")}`);
  if (live) {
    $("#case-move").onclick = async () => { try { await API.post(`/v1/cases/${id}/transition`, {status: $("#case-status").value, actor: "analyst"}); toast("transitioned"); openCase(id); } catch (e) { toast(e.message); } };
    $("#case-decide").onclick = async () => { try { await API.post(`/v1/cases/${id}/decision`, {reviewer: "reviewer", outcome: $("#case-outcome").value, note: $("#case-note").value}); toast("recorded"); openCase(id); } catch (e) { toast(e.message); } };
  }
}

function incidentView(e) {
  const rows = [["Source / trust", `${e.source_trust || "—"}`, "user"], ["Attack class", (e.threat_classes || []).join(", ") || "—", "decision"], ["Agent", e.agent, "model"], ["Requested capability", e.requested_capability || "none", "model"], ["AI recommendation", e.ai_recommendation || "—", "model"], ["Trusted evidence", e.evidence_verdict || "n/a", "trusted"], ["Policy", e.policy_id || "—", "decision"], ["Authorization / blocked by", (e.blocked_by || []).join(" + ") || "—", "decision"], ["Final Sentinel decision", e.final_action || "—", "decision"]];
  return `<div class="row small" style="margin-bottom:6px">${chip(e.severity)} <span class="mono muted">${esc(e.event_id)} · ${fmtTs(e.created_at)} · ${esc(e.workflow)}</span></div><div class="flow">${rows.map(([t, v, k], i) => `<div class="stage k-${k} ${t === "Final Sentinel decision" ? (v === "ALLOW" ? "ok" : "alert") : ""}"><div class="t">${t}</div><div class="v">${esc(v)}</div></div>${i < rows.length - 1 ? `<div class="arrow">↓</div>` : ""}`).join("")}</div><div class="small muted" style="margin-top:8px">findings: ${(e.findings || []).map(f => `${esc(f.signal)} (${f.weight}, span ${esc(f.span_hash)})`).join("; ") || "structural only"} · content hash ${esc(e.content_hash)} · decision ${esc(e.decision_id || "—")}</div>`;
}

VIEWS.aisecurity = async () => {
  const [ev, atk] = await Promise.all([API.get("/v1/ai/security/events?limit=60"), API.get("/v1/attacks")]);
  const sel = atk.attacks.map(a => `<option value="${esc(a.key)}">${esc(a.name)}</option>`).join("");
  return `<div class="card"><h3>Attack the financial AI <span class="muted">select an attack, edit it, run it against the real engine</span></h3>
    ${legend()}
    <div class="toolbar"><label class="f" style="min-width:260px">attack<select id="atk-kind">${sel}</select></label><label class="f"><span>mode</span><select id="atk-mode"><option value="compare">WITHOUT vs WITH Sentinel (side by side)</option><option value="guarded">WITH Sentinel only</option><option value="unguarded">WITHOUT Sentinel only — simulated agent, no controls</option></select></label><button class="btn primary" id="atk-run">Run attack</button><span class="muted small" id="atk-desc"></span></div>
    <div class="grid c2" style="margin-top:10px"><label class="f">attacker text (USER_CONTROLLED)<textarea id="atk-text"></textarea></label><label class="f">attacker document (DOCUMENT_CONTROLLED)<textarea id="atk-doc"></textarea></label></div>
    <div class="subtle" style="margin-top:6px">The "without Sentinel" path is the deterministic offline simulator of a naive tool-calling agent, not a real LLM; it shows what the architecture prevents, not a measured model failure rate.</div>
    <div id="atk-out" style="margin-top:12px"></div></div>
  ${card(`AI security events <span class="muted">${ev.events.length}</span>`, ev.events.length ? `<table><thead><tr><th>event</th><th>time</th><th>agent</th><th>severity</th><th>attack class</th><th>source trust</th><th>requested</th><th>AI said</th><th>evidence</th><th>final</th></tr></thead><tbody>${ev.events.map(e => `<tr class="row" data-sec="${esc(e.event_id)}"><td class="mono">${esc(e.event_id)}</td><td class="mono">${fmtTs(e.created_at)}</td><td>${esc(e.agent)}</td><td>${chip(e.severity)}</td><td class="small">${esc((e.threat_classes || []).join(", "))}</td><td>${e.source_trust ? trustChip(e.source_trust) : ""}</td><td class="mono small">${esc(e.requested_capability || "")}</td><td class="mono small">${esc(e.ai_recommendation || "")}</td><td>${e.evidence_verdict ? chip(e.evidence_verdict) : ""}</td><td>${e.final_action ? chip(e.final_action) : ""}</td></tr>`).join("")}</tbody></table>` : empty("no security events yet"))}`;
};
let ATTACKS = null;
async function wireAttacks() {
  if (!ATTACKS) ATTACKS = (await API.get("/v1/attacks")).attacks;
  const kindSel = $("#atk-kind"), text = $("#atk-text"), doc = $("#atk-doc"), desc = $("#atk-desc");
  const preset = () => ATTACKS.find(x => x.key === kindSel.value);
  const shownText = (a) => a.turns && a.turns.length ? a.turns.map((t, i) => `Turn ${i + 1}: ${t}`).join("\n") : a.narrative;
  const load = () => { const a = preset(); text.value = shownText(a); doc.value = a.document || ""; desc.textContent = `${a.description} Target: ${a.workflow || "dispute"} / ${a.target_capability}. Ledger: ${JSON.stringify(a.ledger)}`; };
  kindSel.onchange = load; load();
  $("#atk-run").onclick = async () => {
    const a = preset(), mode = $("#atk-mode").value;
    const body = {kind: kindSel.value, compare: mode === "compare", unguarded: mode === "unguarded"};
    if (text.value !== shownText(a)) body.narrative = text.value;
    if (doc.value !== (a.document || "")) body.document = doc.value || null;
    $("#atk-out").innerHTML = `<div class="muted">running…</div>`;
    try { const r = await API.post("/v1/attacks/simulate", body); $("#atk-out").innerHTML = mode === "compare" ? compareView(r) : storyboard(r); } catch (e) { $("#atk-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; }
  };
}
async function openSecurityEvent(id) { const ev = (await API.get("/v1/ai/security/events?limit=200")).events.find(e => e.event_id === id); if (ev) openDrawer(`<h2 style="margin:0">AI security event ${esc(id)}</h2>${legend()}` + card("Incident", incidentView(ev))); }

VIEWS.policies = async () => {
  const p = await API.get("/v1/policies");
  const byId = {}; p.policies.forEach(x => (byId[x.policy_id] = byId[x.policy_id] || []).push(x));
  const lint = {};
  await Promise.all(p.policies.map(async v => { try { lint[`${v.policy_id}@v${v.version}`] = await API.post("/v1/policies/lint", v); } catch (e) { lint[`${v.policy_id}@v${v.version}`] = null; } }));
  const lintLine = (v) => { const l = lint[`${v.policy_id}@v${v.version}`]; if (!l) return ""; return l.clean ? `<span class="lint-ok">lint: clean</span>` : `<span class="lint-bad">lint: ${esc(l.findings.join("; "))}</span>`; };
  return `<div class="grid c2">${Object.entries(byId).map(([id, versions]) => card(`${esc(id)} <span class="muted">${versions.map(v => "v" + v.version).join(" · ")}</span>`, versions.map(v => `<div style="margin-bottom:10px"><div class="row"><b>v${v.version}</b> <span class="muted small">${esc(v.workflow)} · effective ${esc(v.effective_from)} · default ${esc(v.default_outcome)} · required: ${esc((v.required_fields || []).join(", "))}</span> ${lintLine(v)}</div><div class="small muted">${esc(v.description)}</div><table style="margin-top:6px"><tbody>${v.rules.map(r => `<tr><td class="mono small">${esc(r.id)}</td><td class="mono small wrap">${r.when.map(c => `${esc(c.field)} ${esc(c.op)} ${c.value !== undefined ? esc(JSON.stringify(c.value)) : ""}`).join(" AND ")}</td><td>${chip(r.outcome)}</td><td class="small muted wrap">${esc(r.reason)}</td></tr>`).join("")}</tbody></table></div>`).join(""))).join("")}</div>
  ${card("Policy sandbox — evaluate a context against a versioned policy (fail-closed: every referenced field must be present)", `<div class="toolbar"><label class="f">policy<select id="pol-id">${Object.keys(byId).map(k => `<option ${k === "dispute-refund" ? "selected" : ""}>${esc(k)}</option>`).join("")}</select></label><label class="f">version<input id="pol-ver" placeholder="latest"></label><button class="btn primary" id="pol-go">Evaluate</button></div><label class="f" style="margin-top:8px">context (JSON, trusted fields only — see catalog)<textarea id="pol-ctx">{"amount": 185000, "evidence_verdict": "SUPPORTED", "security_severity": "NONE", "capability_escalation": false, "risk_score": 34, "policy_auto_limit": 50000, "prior_disputes_90d": 0, "refund_state": "none", "transaction_status": "settled", "merchant_response": "none", "auth_strength": "otp", "claim_type": "non_receipt"}</textarea></label><div id="pol-out" style="margin-top:10px"></div>`)}
  <div class="note">Policies are explicit, versioned, content-hashed, schema-validated data. All rules are evaluated, the most severe outcome wins, every match is explained, and a missing input is an error rather than a rule that silently fails to fire. The policy engine never sees a model recommendation.</div>`;
};

VIEWS.audit = async () => {
  const [a, v] = await Promise.all([API.get("/v1/audit?limit=120"), API.get("/v1/audit/verify")]);
  return `<div class="grid c3"><div class="card kpi"><div class="v">${a.length}</div><div class="l">events in chain</div></div><div class="card kpi"><div class="v" style="font-size:14px;word-break:break-all">${esc(a.head)}</div><div class="l">head hash</div></div><div class="card kpi"><div class="v" style="color:${v.ok ? "var(--ok)" : "var(--bad)"}">${v.ok ? "VERIFIED" : "TAMPERED"}</div><div class="l">tamper-evident application audit chain</div><div class="s">${v.problems && v.problems.length ? esc(v.problems[0]) : "hash_n = SHA256(event_n ‖ hash_n−1) · " + v.length + " checked"}</div></div></div>
  <div class="note">Detects modification, deletion, insertion and reordering of any record. It is not a blockchain and not an immutable ledger: a consistent rewrite from genesis is detected only against an exported checkpoint (<code>sentinel audit checkpoint</code>, HMAC-signed with SENTINEL_AUDIT_KEY). It stores hashes of untrusted content, never prose.</div>
  ${card("Audit events", `<table><thead><tr><th>#</th><th>time</th><th>kind</th><th>workflow</th><th>action</th><th>decision</th><th>capability</th><th>risk</th><th>policy</th><th>security</th><th>case</th><th>hash</th></tr></thead><tbody>${a.events.map(e => `<tr class="row" data-dec="${esc(e.decision_id || "")}"><td class="num">${e.sequence}</td><td class="mono">${fmtTs(e.timestamp)}</td><td>${esc(e.kind)}</td><td>${esc(e.workflow)}</td><td>${chip(e.action.replace("REPLAY:", ""), e.action.replace("REPLAY:", ""))}</td><td class="mono small">${esc(e.decision_id || "")}</td><td class="mono small">${esc(e.capability || "")}</td><td class="num">${e.risk_score}</td><td class="mono small">${esc(e.policy_id ? e.policy_id + "@v" + e.policy_version : "")}</td><td>${chip(e.security_severity)}</td><td class="mono small">${esc(e.case_id || "")}</td><td class="mono small">${esc(e.event_hash.slice(0, 12))}…</td></tr>`).join("")}</tbody></table>`)}`;
};
async function openDecision(id) {
  if (!id) return;
  const v = await API.get(`/v1/decisions/${id}`);
  openDrawer(`<h2 style="margin:0">Decision ${esc(id)} ${chip(v.decision.final_action)}</h2>${legend()}${card("Decision", decisionBlock(v.decision))}${card("Evidence", evidenceTable(v.evidence))}${v.audit_event ? card("Audit event", kv(v.audit_event, ["sequence", "event_hash", "previous_hash", "action", "capability", "policy_id", "policy_version", "evidence_ids", "input_hash"])) : ""}`);
}

VIEWS.replay = async () => {
  const [d, r, p] = await Promise.all([API.get("/v1/decisions?limit=60"), API.get("/v1/replays"), API.get("/v1/policies")]);
  const decs = d.decisions.filter(x => x.controls && x.controls.includes("policy"));
  const opts = decs.map(x => `<option value="${esc(x.decision_id)}" data-policy="${esc(x.policy.policy_id)}">${esc(x.decision_id)} · ${esc(x.workflow)} · ${esc(x.final_action)} · ${x.policy.policy_id}@v${x.policy.version} · risk ${x.risk_score}</option>`).join("");
  window.__policyVersions = {}; p.policies.forEach(x => (window.__policyVersions[x.policy_id] = window.__policyVersions[x.policy_id] || []).push(x.version));
  return `${card("Decision replay — rerun a stored decision under different versions", `<div class="grid c2"><label class="f">decision<select id="rp-dec">${opts}</select></label><label class="f">policy version<select id="rp-pv"><option value="">(keep)</option></select></label><label class="f">risk configuration (model version)<select id="rp-rm"><option value="">(keep)</option><option>txn-1.0</option><option>txn-1.1</option><option>txn-2.0</option></select></label><label class="f">rule threshold override (rule_id=value)<input id="rp-rule" placeholder="review-critical-risk=70"></label><label class="f">AI recommendation override (demonstrates irrelevance)<select id="rp-ai"><option value="">(keep)</option><option>approve_refund</option><option>deny</option><option>release_funds</option><option>unfreeze_account</option><option>skip_review</option></select></label><label class="f">controls<select id="rp-ctl"><option value="">(keep)</option><option value="none">none — unguarded</option></select></label></div><div class="row" style="margin-top:10px"><button class="btn primary" id="rp-go">Replay</button><span class="muted small">Deterministic: the composer is a pure function of the stored input snapshot. The result reports policy_drift (the named version's content changed) and engine_drift (the recorded outcome no longer reproduces).</span></div><div id="rp-out" style="margin-top:12px"></div>`)}
  ${card(`Replay history <span class="muted">${r.replays.length}</span>`, r.replays.length ? `<table><thead><tr><th>replay</th><th>decision</th><th>overrides</th><th>before</th><th>after</th><th>changed</th><th>drift</th><th>explanation</th></tr></thead><tbody>${r.replays.map(x => `<tr><td class="mono">${esc(x.replay_id)}</td><td class="mono">${esc(x.decision_id)}</td><td class="small wrap">${esc(x.overrides.join("; "))}</td><td>${chip(x.original.final_action)}</td><td>${chip(x.replayed.final_action)}</td><td>${x.changed ? "yes" : "no"}</td><td class="small">${x.policy_drift ? chip("policy drift", "CONTRADICTED") : ""}${x.original_drift ? chip("engine drift", "CONTRADICTED") : ""}${!x.policy_drift && !x.original_drift ? chip("none", "SUPPORTED") : ""}</td><td class="small wrap">${esc(x.explanation)}</td></tr>`).join("")}</tbody></table>` : empty("no replays yet"))}`;
};
function replayView(x) {
  const keys = Object.keys(x.original);
  const diffs = (x.decision_diff || x.diffs || []);
  return `<div class="headline">${esc(x.explanation)}</div><div class="row small" style="margin:8px 0">changed: <b>${x.changed ? "yes" : "no"}</b> · policy drift: ${x.policy_drift ? chip("YES", "CONTRADICTED") : chip("no", "SUPPORTED")} · engine drift: ${(x.engine_drift || x.original_drift) ? chip("YES", "CONTRADICTED") : chip("no", "SUPPORTED")} · ${diffs.length} field(s) differ</div><div class="diff"><div class="h">field</div><div class="h">original</div><div class="h">replayed</div>${keys.map(k => { const ch = JSON.stringify(x.original[k]) !== JSON.stringify(x.replayed[k]); return `<div>${esc(k)}</div><div>${esc(JSON.stringify(x.original[k]))}</div><div class="${ch ? "changed" : ""}">${esc(JSON.stringify(x.replayed[k]))}</div>`; }).join("")}</div>`;
}

VIEWS.evaluations = async () => {
  const e = await API.get("/v1/evaluations");
  const R = e.results || {};
  if (!e.available || !e.available.length) return card("Evaluations", empty("No results yet. Run `make eval` (sentinel eval run --suite full) to produce results/*.json."));
  const s = R.security, h = R.heldout, sf = R.surfaces, ab = R.ablation, b = R.baselines, f = R.financial, it = R.integrity, tl = R.temporal, p = R.performance, k = R.kyb, m = R.models, cl = R.claims;
  const kinds = (...ks) => ks.map(kind).join(" ");
  const head = (t, ...ks) => `<div class="sec-h">${t} ${kinds(...ks)}</div>`;
  let html = `<div class="note">Everything below is measured by <code>sentinel eval run --suite full</code> on <b>synthetic</b> corpora and datasets with the <b>offline</b> simulated agent. ${kind("structural")} numbers are 0 by construction (an attack on records that do not support it cannot execute under the design) and are regression checks; ${kind("empirical")} numbers can move; ${kind("design")} numbers describe intended behaviour, not a target. Sample sizes are shown. Limitations: docs/EVALUATION.md, docs/LIMITATIONS.md.</div>`;
  // ---- AI security
  if (s) html += head("AI security — dispute surface", "synthetic", "offline") + `<div class="grid c4"><div class="card kpi"><div class="v">${pctc(s.asr_unguarded)}</div><div class="l">attack success — simulated agent, no controls</div><div class="s">${s.n_attacks} attacks / ${Object.keys(s.by_class || {}).length} classes · ${kind("empirical")}</div></div><div class="card kpi"><div class="v" style="color:var(--ok)">${pctc(s.asr_guarded)}</div><div class="l">attack success — Sentinel</div><div class="s">unauthorised capability executed · ${kind("structural")}</div></div><div class="card kpi"><div class="v">${pctc(s.detection_recall)}</div><div class="l">gateway detection recall</div><div class="s">text scan or model-output check; not the backstop · ${kind("empirical")}</div></div><div class="card kpi"><div class="v" style="color:var(--ok)">${pctc(s.fp_rate)}</div><div class="l">false positives</div><div class="s">${s.n_deserved_controls} deserved refunds · ${kind("empirical")}</div></div></div>`;
  if (s) html += `<div class="grid c2">${card("Attack success by class (simulated agent, no controls)", `<div class="chart">${hbarChart(Object.fromEntries(Object.entries(s.by_class).map(([k2, v]) => [k2, v.asr_unguarded])), {pct: true, color: "#e2574f"})}</div>`)}${card("Gateway detection recall by class (0% = nothing to detect; blocked anyway)", `<div class="chart">${hbarChart(Object.fromEntries(Object.entries(s.by_class).map(([k2, v]) => [k2, v.detection_recall])), {pct: true, color: "#e0a83a"})}</div>`)}</div>` + meth(s, "security");
  html += `<div class="grid c3">${h ? card("Held-out generalisation (unseen wording)", kv({attacks: h.n_attacks, "deserved controls": h.n_deserved_controls, "ASR simulated agent": pctc(h.asr_unguarded), "ASR Sentinel (structural)": pctc(h.asr_guarded), "detection recall": pctc(h.detection_recall), "false positives": pctc(h.fp_rate)})) : ""}${sf ? card("Other surfaces: transaction · account security · investigation", kv({attacks: sf.n_attacks, "ASR simulated agent": pctc(sf.asr_unguarded), "ASR Sentinel (structural)": pctc(sf.asr_guarded), "detection recall": pctc(sf.detection_recall), "loosened the text-free baseline": pctc(sf.loosened_vs_baseline), ...Object.fromEntries(Object.entries(sf.by_workflow || {}).map(([w, v]) => [w, `n=${v.n} · ${pctc(v.asr_unguarded)} → ${pctc(v.asr_guarded)}`]))})) : ""}${k ? card("KYB onboarding (records-only ground truth)", kv({cases: k.corpus ? k.corpus.cases : k.controls + k.attacks, attacks: k.attacks, "records approve / review / reject": k.corpus ? `${k.corpus.records_approve} / ${k.corpus.records_review} / ${k.corpus.records_reject}` : "—", "ASR simulated agent": pctc(k.asr_unguarded), "ASR Sentinel (structural)": pctc(k.asr_guarded), "false negatives (bad merchant went live)": pctc(k.fn_rate), "FP benign input": pctc(k.fp_rate_benign_input), "FP any input (clean merchant held for hostile upload)": pctc(k.fp_rate), "manual review rate": pctc(k.manual_review_rate)})) : ""}</div>` + meth(h, "heldout") + meth(sf, "surfaces") + meth(k, "kyb");
  if (k && k.by_category) html += card("KYB by category", `<table><thead><tr><th>category</th><th class="num">n</th><th class="num">fp</th><th class="num">fn</th><th class="num">reviewed</th><th class="num">breach simulated → Sentinel</th></tr></thead><tbody>${Object.entries(k.by_category).map(([c, v]) => `<tr><td>${esc(c)}</td><td class="num">${v.n}</td><td class="num">${v.fp}</td><td class="num">${v.fn}</td><td class="num">${v.reviewed}</td><td class="num">${v.ug_breach} → ${v.g_breach}</td></tr>`).join("")}</tbody></table>`);
  if (ab) html += card("Ablation — which control carries the result (ASR)", `<div class="chart">${barChart(Object.fromEntries(Object.entries(ab).map(([k2, v]) => [k2, v.asr])), {pct: true, color: (k2) => ab[k2].asr > 0.2 ? "#e2574f" : ab[k2].asr > 0 ? "#e0a83a" : "#4f8cff", height: 190})}</div><div class="subtle">detection only holds exactly what it flags; policy only runs over the model's asserted verdict; adjudication only executes iff the ledger supports the claim.</div>`) + meth(ab, "ablation");
  if (b) html += card("Beating the obvious defence (ASR)", `<div class="chart">${barChart({no_defence: b.no_defence, hardened_prompt: b.hardened_prompt, sentinel: b.sentinel}, {pct: true, color: (k2) => k2 === "no_defence" ? "#e2574f" : k2 === "hardened_prompt" ? "#e0a83a" : "#4f8cff"})}</div><div class="muted small">hardened prompt still fails: ${esc(Object.entries(b.hardened_by_class).filter(([, v]) => v > 0).map(([k2, v]) => `${k2} ${pctc(v)}`).join(", ") || "—")}</div>`) + meth(b, "baselines");
  // ---- financial
  if (f) {
    const tlv = f.transaction_level, al = f.account_level, ml = f.merchant_level, sr = f.seed_range || {};
    const rng = (lvl, met) => sr[lvl] ? `${pctc(sr[lvl][met].min)}–${pctc(sr[lvl][met].max)}` : "—";
    html += head("Financial risk — labelled synthetic dataset", "synthetic", "empirical") + `<div class="note">Development seed ${f.dataset.seed} (${f.dataset.transactions.toLocaleString()} transactions; the point values were tuned on it) with the range over held-out seeds ${(f.seeds && f.seeds.held_out || []).join(", ")} in brackets. Screening = transaction band; decisioning = policy outcome; triage = account monitoring. The model is a hand-weighted rule table, not ML.</div>
    <table><thead><tr><th>level</th><th>scenarios</th><th class="num">precision</th><th class="num">recall</th><th class="num">FPR</th><th class="num">tp / fp / fn / tn</th></tr></thead><tbody>
    <tr><td>screening — transaction</td><td class="small">${esc((tlv.scenarios || []).join(", "))}</td><td class="num">${pctc(tlv.precision)} <span class="subtle">(${rng("transaction_level", "precision")})</span></td><td class="num">${pctc(tlv.recall)} <span class="subtle">(${rng("transaction_level", "recall")})</span></td><td class="num">${pctc(tlv.false_positive_rate, 2)}</td><td class="num">${tlv.tp} / ${tlv.fp} / ${tlv.fn} / ${tlv.tn}</td></tr>
    <tr><td>triage — account monitoring</td><td class="small">${esc((al.scenarios || []).join(", "))}</td><td class="num">${pctc(al.precision)} <span class="subtle">(${rng("account_level", "precision")})</span></td><td class="num">${pctc(al.recall)} <span class="subtle">(${rng("account_level", "recall")})</span></td><td class="num">${pctc(al.false_positive_rate, 2)}</td><td class="num">${al.tp} / ${al.fp} / ${al.fn} / ${al.tn}</td></tr>
    <tr><td>merchant profile</td><td class="small">${esc(ml.definition || "")} (n=${ml.bad_merchants} positives — too few to conclude)</td><td class="num">${pctc(ml.precision)}</td><td class="num">${pctc(ml.recall)}</td><td class="num">${pctc(ml.false_positive_rate, 2)}</td><td class="num">${ml.tp} / ${ml.fp} / ${ml.fn} / ${ml.tn}</td></tr></tbody></table>`;
    html += `<div class="grid c2">${card("Transaction recall by scenario (n)", `<div class="chart">${hbarChart(Object.fromEntries(Object.entries(f.recall_by_scenario).map(([k2, v]) => [`${k2.replace("fraud:", "")} (n=${v.n})`, v.recall])), {pct: true})}</div>`)}${card("Calibration — observed fraud rate per transaction band (n)", `<div class="chart">${barChart(Object.fromEntries(Object.entries(f.calibration).map(([k2, v]) => [k2, v.observed_fraud_rate])), {order: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], pct: true, height: 140})}</div><div class="subtle">${Object.entries(f.calibration).map(([k2, v]) => `${k2} n=${v.n}`).join(" · ")}</div>`)}</div>`;
    if (tlv.miss_breakdown) html += card("Why transactions are missed — dominant signals per scenario", `<table><thead><tr><th>scenario</th><th class="num">n</th><th class="num">detected</th><th class="num">missed</th><th>signals when detected</th><th>signals when missed</th></tr></thead><tbody>${Object.entries(tlv.miss_breakdown).map(([sc, v]) => `<tr><td>${esc(sc)}</td><td class="num">${v.n}</td><td class="num">${v.detected}</td><td class="num">${v.missed}</td><td class="small wrap">${esc(Object.entries(v.dominant_signals_detected).map(([a, c]) => `${a} ×${c}`).join(", "))}</td><td class="small wrap">${esc(Object.entries(v.dominant_signals_missed).map(([a, c]) => `${a} ×${c}`).join(", ")) || "—"}</td></tr>`).join("")}</tbody></table>`);
    if (f.held_out_seeds) html += card("Held-out seeds (point values never inspected against these)", `<table><thead><tr><th>seed</th><th>level</th><th class="num">precision</th><th class="num">recall</th><th class="num">FPR</th><th class="num">tp / fp / fn / tn</th></tr></thead><tbody>${Object.entries(f.held_out_seeds).flatMap(([seed, v]) => ["transaction_level", "account_level", "merchant_level"].map(l => `<tr><td class="mono">${esc(seed)}</td><td>${esc(l.replace("_level", ""))}</td><td class="num">${pctc(v[l].precision)}</td><td class="num">${pctc(v[l].recall)}</td><td class="num">${pctc(v[l].false_positive_rate, 2)}</td><td class="num">${v[l].tp} / ${v[l].fp} / ${v[l].fn} / ${v[l].tn}</td></tr>`)).join("")}</tbody></table>`);
    if (f.policy_sample) html += card("Decisioning — policy outcomes on a sample through the full pipeline (no agent)", kv({n: f.policy_sample.n, policy: f.policy_sample.policy, "fraud-labelled allowed": pctc(f.policy_sample.fraud_allowed_rate), "legitimate blocked or denied": pctc(f.policy_sample.legit_blocked_or_denied_rate), outcomes: f.policy_sample.outcomes}));
    if (tlv.signal_stats) html += card("Signals — how often each factor fires on fraud vs legitimate transactions (seed " + f.dataset.seed + ")", `<table><thead><tr><th>factor</th><th>family</th><th class="num">points</th><th class="num">fired on fraud (rate)</th><th class="num">fired on legit (rate)</th><th class="num">precision when fired</th></tr></thead><tbody>${Object.entries(tlv.signal_stats).slice(0, 18).map(([c2, v]) => `<tr><td class="mono">${esc(c2)}</td><td>${esc(v.family)}</td><td class="num">+${v.points}</td><td class="num">${v.fired_on_fraud} (${pctc(v.fraud_fire_rate)})</td><td class="num">${v.fired_on_legit} (${pctc(v.legit_fire_rate, 2)})</td><td class="num">${pctc(v.precision_when_fired)}</td></tr>`).join("")}</tbody></table><div class="subtle">a factor that fires on many legitimate transactions is a weak signal on this generator; nothing was tuned to change that. Family precision: ${esc(Object.entries(tlv.family_stats || {}).map(([a, v]) => `${a} ${pctc(v.precision_when_fired)}`).join(" · "))}</div>`);
    html += meth(f, "financial");
  }
  // ---- decision integrity + temporal
  if (it) html += head("Decision integrity", "synthetic", "structural") + card("Can untrusted input or model output loosen a decision?", `<div class="chart">${barChart({"text · no controls": it.text_influence_permissive_unguarded, "text · Sentinel": it.text_influence_permissive_protected, "model output · Sentinel": it.model_influence_protected, "legit+injection loosened": it.legit_plus_injection_loosened, "beyond ledger ceiling": it.text_beyond_ledger_ceiling, "executed unsupported": it.executed_without_ledger_support}, {pct: true, color: (k2) => k2.includes("no controls") ? "#e2574f" : "#4f8cff"})}</div>${kv({attacks: it.n_attacks, "deserved controls": it.n_legit, "text selected the claim on a supporting ledger (by design)": pctc(it.text_selected_claim_on_supporting_ledger), "attack text approved on a supporting ledger (deserved)": pctc(it.attack_text_approved_on_supporting_ledger), "model influence replays": it.model_influence_n})}<div class="subtle" style="margin-top:6px">${esc(it.note)}</div>`) + meth(it, "integrity");
  if (tl) html += head("Temporal leakage benchmark", "synthetic", "structural") + card("A decision at T1 reads only records at or before T1", kv({"sampled transactions": tl.dataset && tl.dataset.sample, "perturbation comparisons": tl.comparisons, "future records appended": tl.future_records, "truncation mismatch (full vs cut at T1)": pctc(tl.truncation_mismatch_rate), "future perturbation changed a T1 transaction score": pctc(tl.perturbation_transaction_change_rate), "future perturbation changed T1 account monitoring": pctc(tl.perturbation_monitoring_change_rate), "future offsets (days)": (tl.future_offsets_days || []).join(", "), expected: tl.expected}) + (tl.perturbation_by_kind ? `<table style="margin-top:8px"><thead><tr><th>future record kind</th><th>what is appended (at every offset)</th><th class="num">records</th><th class="num">transaction changed</th><th class="num">monitoring changed</th></tr></thead><tbody>${Object.entries(tl.perturbation_by_kind).map(([kd, v]) => `<tr><td class="mono">${esc(kd)}</td><td class="small">${esc(v.description)}</td><td class="num">${v.future_records}</td><td class="num">${v.transaction_changed} / ${v.n}</td><td class="num">${v.monitoring_changed} / ${v.n}</td></tr>`).join("")}</tbody></table>` : "")) + meth(tl, "temporal");
  if (cl) html += head("Claim classifier", "synthetic", "empirical") + card(`${cl.n} labelled phrasings — the benchmark and the classifier share an author (a regression floor, not a generalisation claim)`, `<div class="grid c4"><div class="card kpi"><div class="v">${pctc(cl.coverage)}</div><div class="l">coverage</div><div class="s">legitimate paraphrases read as a claim</div></div><div class="card kpi"><div class="v">${pctc(cl.false_positive_rate)}</div><div class="l">false positives</div><div class="s">legitimate paraphrases held for a human or misread</div></div><div class="card kpi"><div class="v">${pctc(cl.adversarial_wrong_type_rate)}</div><div class="l">adversarial wrong type</div><div class="s">attack prose read as a claim it does not assert</div></div><div class="card kpi"><div class="v">${pctc(cl.abstain_rate)}</div><div class="l">abstain rate</div><div class="s">held for a human (100% of ambiguous and contradictory by design)</div></div></div><table><thead><tr><th>category</th><th class="num">n</th><th class="num">accuracy</th><th class="num">read as claim</th><th class="num">non-claim</th><th class="num">abstain</th><th class="num">misclassified</th></tr></thead><tbody>${Object.entries(cl.by_category || {}).map(([c2, v]) => `<tr><td>${esc(c2)}</td><td class="num">${v.n}</td><td class="num">${pctc(v.accuracy)}</td><td class="num">${v.claim}</td><td class="num">${v.non_claim}</td><td class="num">${v.abstain}</td><td class="num">${v.misclassified}</td></tr>`).join("")}</tbody></table><div class="subtle">an abstain reconciles to INSUFFICIENT (a human); a recognised non-claim to UNSUPPORTED (denied); a read claim only selects which trusted field is checked — the composer's guarantee does not depend on the classifier.</div>`) + meth(cl, "claims");
  // ---- performance
  if (p) html += head("Performance — own overhead, offline", "offline", "empirical") + card(`${esc(p.platform)} · Python ${esc(p.python)} · sequential single-thread, persistence excluded`, `<table><thead><tr><th>component</th><th class="num">p50 ms</th><th class="num">p95 ms</th><th class="num">p99 ms</th><th class="num">ops/s</th></tr></thead><tbody>${Object.entries(p.components).map(([n, v]) => `<tr><td class="mono">${esc(n)}</td><td class="num">${v.p50_ms}</td><td class="num">${v.p95_ms}</td><td class="num">${v.p99_ms}</td><td class="num">${v.throughput_per_sec}</td></tr>`).join("")}</tbody></table><div class="muted small">${esc(p.workloads.note)}</div>`) + meth(p, "performance");
  if (m) html += head("Model / provider evaluation", "offline", "structural") + card("The same corpus against each provider", `<table><thead><tr><th>provider</th><th>model</th><th>date</th><th>status</th><th class="num">ASR no controls</th><th class="num">ASR Sentinel</th><th class="num">FP</th><th class="num">agent latency ms</th><th class="num">tokens in / out</th></tr></thead><tbody>${m.results.map(x => `<tr><td>${esc(x.provider)}</td><td class="mono">${esc(x.model)}</td><td class="mono">${esc(x.date || (x.timestamp || "").slice(0, 10))}</td><td>${esc(x.status)}${x.reason ? ` <span class="muted small">${esc(x.reason)}</span>` : ""}</td><td class="num">${pctc(x.asr_unguarded)}</td><td class="num">${pctc(x.asr_guarded)}</td><td class="num">${pctc(x.fp_rate)}</td><td class="num">${x.mean_agent_latency_ms ?? "—"}</td><td class="num">${x.input_tokens != null ? `${x.input_tokens} / ${x.output_tokens}` : "—"}</td></tr>`).join("")}</tbody></table><div class="muted small">${esc(m.note)} A live row stays <b>not_run</b> until an operator runs it on their own key; one model on one day is one data point. No live number is quoted anywhere in this repository.</div>`) + meth(m, "models");
  return html;
};

VIEWS.system = async () => {
  const [s, c] = await Promise.all([API.get("/v1/system"), API.get("/v1/capabilities")]);
  return `<div class="grid c2">${card("System", kv({name: s.name, version: s.version, mode: s.mode, provider: s.provider, model: s.model, store: s.store, "audit chain": s.audit.ok ? `verified (${s.audit.length} events)` : "TAMPERED", "console source": API.isLive() ? "live API" : "static snapshot (read-only)"}))}${card("Policies & risk models", `<div class="pill-list">${s.policies.map(p => chip(p, "trusted")).join("")}</div><div class="pill-list" style="margin-top:8px">${s.risk_models.map(m => chip(m, "model")).join("")}</div>`)}</div>
  ${card("Capability security matrix <span class='muted'>who may make what happen — " + esc(c.invariant) + "</span>", `<table class="matrix"><thead><tr><th>capability</th><th>risk</th><th>irreversible</th><th>money</th><th>consequential</th><th>AI agent allowed</th><th>required authorization</th><th class="num">human threshold</th><th>allowed actors</th><th>policy gates</th></tr></thead><tbody>${c.capabilities.map(r => `<tr><td class="mono">${esc(r.capability)}</td><td>${chip(r.risk)}</td><td class="${r.irreversible ? "yes" : "no"}">${r.irreversible ? "yes" : "no"}</td><td class="${r.financial_effect ? "yes" : "no"}">${r.financial_effect ? "yes" : "no"}</td><td>${r.consequential ? "yes" : "no"}</td><td class="${r.ai_agent_allowed ? "yes" : "no"}">${r.ai_agent_allowed ? "YES" : "never"}</td><td class="mono small">${esc(r.required_authorization)}</td><td class="num">${r.human_review_threshold != null ? inr(r.human_review_threshold) : "—"}</td><td class="small">${esc(r.allowed_actors.join(", ") || "nobody")}</td><td class="small wrap">${esc(r.policy_gates.join(", ") || "—")}</td></tr>`).join("")}</tbody></table>`)}
  ${card("In-process metrics", `<div class="grid c2"><div>${kv(s.metrics.counters || {})}</div><div>${Object.keys(s.metrics.latency || {}).length ? `<table><thead><tr><th>key</th><th class="num">n</th><th class="num">p50</th><th class="num">p95</th><th class="num">p99</th></tr></thead><tbody>${Object.entries(s.metrics.latency).map(([k, v]) => `<tr><td class="mono small">${esc(k)}</td><td class="num">${v.n}</td><td class="num">${v.p50_ms}</td><td class="num">${v.p95_ms}</td><td class="num">${v.p99_ms}</td></tr>`).join("")}</tbody></table>` : empty("no latency samples yet")}</div></div>`)}
  ${card("Architecture", `<pre>untrusted information → AI Security Gateway (provenance · normalisation · detection)
        ↓
risk intelligence (transaction · behavioural · entity · graph · monitoring — point-in-time)
        ↓
AI recommendation (MODEL_GENERATED — recorded, never authoritative)
        ↓
trusted-evidence reconciliation (claims vs verified facts · contradictions)
        ↓
versioned, content-hashed, fail-closed policy → capability authorization → human review
        ↓
action · case · tamper-evident audit chain · replay (policy + engine drift)</pre>`)}`;
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
  if (key === "risk") $("#rk-go").onclick = async () => { try { const riskPath = "/v1/risk/" + $("#rk-type").value + "/" + encodeURIComponent($("#rk-id").value.trim()); const r = await API.get(riskPath); $("#rk-out").innerHTML = riskBlock(r); } catch (e) { $("#rk-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; } };
  if (key === "policies") $("#pol-go").onclick = async () => { try { const ctx = JSON.parse($("#pol-ctx").value); const body = {policy_id: $("#pol-id").value, context: ctx}; if ($("#pol-ver").value) body.version = parseInt($("#pol-ver").value, 10); const r = await API.post("/v1/policies/evaluate", body); $("#pol-out").innerHTML = `<div class="row">${chip(r.outcome)} <span class="muted small">${esc(r.policy_id)}@v${r.version} · hash ${esc(r.policy_hash || "")} · matched ${r.matched_rules.length}</span></div><ul class="small">${r.explanations.map(x => `<li>${esc(x)}</li>`).join("") || "<li>no rule matched — default outcome</li>"}</ul>`; } catch (e) { $("#pol-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; } };
  if (key === "replay") {
    const dec = $("#rp-dec"), pv = $("#rp-pv");
    const fillVersions = () => { const o = dec.options[dec.selectedIndex]; const pid = o ? o.dataset.policy : null; const vs = (window.__policyVersions || {})[pid] || []; pv.innerHTML = `<option value="">(keep)</option>` + vs.map(v => `<option value="${v}">v${v}</option>`).join(""); };
    dec.onchange = fillVersions; fillVersions();
    $("#rp-go").onclick = async () => { const body = {decision_id: dec.value}; if (pv.value) body.policy_version = parseInt(pv.value, 10); if ($("#rp-rm").value) body.risk_model = $("#rp-rm").value; if ($("#rp-rule").value) { const [k, v] = $("#rp-rule").value.split("="); body.rule_values = {[k.trim()]: isNaN(Number(v)) ? v : Number(v)}; } if ($("#rp-ai").value) { body.ai_recommendation = $("#rp-ai").value; const caps = {approve_refund: "APPROVE_REFUND", release_funds: "RELEASE_FUNDS", unfreeze_account: "UNFREEZE_ACCOUNT", skip_review: "SKIP_REVIEW"}; if (caps[body.ai_recommendation]) body.ai_capability = caps[body.ai_recommendation]; } if ($("#rp-ctl").value === "none") body.controls = []; try { const r = await API.post("/v1/replay", body); $("#rp-out").innerHTML = replayView(r); } catch (e) { $("#rp-out").innerHTML = `<div class="note">${esc(e.message)}</div>`; } };
  }
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
window.addEventListener("hashchange", () => { closeDrawer(); render(); });
(async () => {
  $("#nav").innerHTML = NAV.map(([k, l], i) => `<a href="#${k}" data-key="${k}"><span class="k">${String(i + 1).padStart(2, "0")}</span>${l}</a>`).join("");
  try {
    const src = await API.init();
    const sys = API.live || API.snap.system;
    $("#mode-badge").className = "badge " + (sys.mode === "live" ? "purple" : "info"); $("#mode-badge").textContent = `${sys.mode} · ${sys.model}`;
    $("#chain-badge").className = "badge " + (sys.audit.ok ? "ok" : "bad"); $("#chain-badge").textContent = sys.audit.ok ? `audit chain ✓ ${sys.audit.length}` : "audit chain broken";
    $("#source-badge").textContent = src === "live" ? "live API" : "static snapshot — run `make api` for live";
    render();
  } catch (e) { $("#view").innerHTML = `<div class="note">Could not reach the API or a snapshot: ${esc(e.message)}. Start the console with <code>make api</code>.</div>`; }
})();
})();
