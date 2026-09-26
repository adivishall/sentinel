# API

A versioned, dependency-free HTTP API (`sentinel/api/server.py`, stdlib
`http.server`) over the same application layer the CLI and console use.
There is no decision logic in the API: every route calls `SentinelApp`.

```bash
make api                     # API + console on :8000 with an in-memory demo dataset (analysed on start)
sentinel --db data/sentinel.db serve --port 8000 --analyze
```

Open http://localhost:8000/ for the console.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health`, `/version`, `/v1/system` | liveness, version/mode/model, system info + metrics |
| GET | `/v1/overview` | dashboard aggregates computed from stored decisions |
| POST | `/v1/transactions/evaluate` | `{transaction_id}` or `{transaction:{…}, untrusted:[…]}` |
| POST | `/v1/disputes/evaluate` | `{narrative, ledger, documents?}` · `{dispute_id}` · `{messages:[…], ledger}` |
| POST | `/v1/merchants/evaluate` | `{application, records, documents?}` · `{application_id}` |
| POST | `/v1/accounts/evaluate` | `{session_id}` or `{session:{…}}`, `message?`, `requested_capability?` |
| POST | `/v1/investigations/evaluate` | `{account_id, case_notes?}` |
| POST | `/v1/ai/security/evaluate` | `{text}` · `{contents:[{text,trust,source,kind}]}` · `{messages}`; `agent?`, `run_agent?` |
| GET | `/v1/ai/security/events[/{id}]` | security events |
| GET | `/v1/transactions[/{id}]`, `/v1/disputes`, `/v1/merchants[/{id}]`, `/v1/accounts[/{id}]`, `/v1/applications`, `/v1/sessions` | entity reads (the transaction view is the full investigation) |
| GET | `/v1/risk/{entity_type}/{id}` | explainable entity / transaction risk |
| GET | `/v1/graph/{entity_type}/{id}?depth=2` | relationship neighbourhood |
| GET | `/v1/decisions[/{id}]` | decisions, with evidence and audit event |
| GET, POST | `/v1/cases`, `/v1/cases/{id}`, `/v1/cases/{id}/transition`, `/v1/cases/{id}/decision` | cases; a transition can never reach RESOLVED -- only `/decision` (a recorded human verdict) resolves |
| GET | `/v1/cases/{id}/review` | the human-review packet: why the case exists, risk with components, trusted evidence vs untrusted claims, contradictions, the model's recommendation marked MODEL_GENERATED, audit history |
| GET | `/v1/audit`, `/v1/audit/verify`, `/v1/audit/{id}` | the tamper-evident audit chain (indexed lookup by event or decision id) |
| GET, POST | `/v1/policies`, `/v1/policies/{id}?version=`, `/v1/policies/catalog`, `/v1/policies/evaluate`, `/v1/policies/validate`, `/v1/policies/lint` | policy-as-code; `lint` returns the findings for a policy document or a shipped `{policy_id, version}` |
| GET | `/v1/capabilities` | the capability security matrix as data (`docs/SECURITY_MODEL.md`) |
| POST, GET | `/v1/replay`, `/v1/replays` | decision replay |
| GET, POST | `/v1/attacks`, `/v1/attacks/simulate` | the attack simulator; `{"kind", "narrative"?, "document"?, "options"?, "compare"?}` -- `compare: true` returns `without` (simulated agent, no controls) and `with` (full controls) side by side with a caveat that the victim is the offline simulator |
| GET, POST | `/v1/scenarios`, `/v1/scenarios/{key}/run` | flagship scenarios |
| GET | `/v1/evaluations` | `results/*.json` |

## Options (any evaluate route)

```jsonc
"options": {
  // user-controllable: accepted everywhere
  "hardened": false,         // hardened-prompt agent
  "skip_agent": false,       // evaluate without any model call
  // what-if: refused (403) on the evaluate routes
  "controls": ["provenance","detection","risk","adjudication","policy","authorization"],
  "unguarded": false,        // shorthand for controls: []
  "policy_version": 1,       // a historical version
  "risk_model": "txn-1.0"    // a historical model of the route's surface
}
```

A caller may request an evaluation; it may not weaken one. On the five
evaluate routes `controls`, `unguarded` (in `options` or top-level),
`policy_version`, `risk_model` and the investigation route's `as_of` are
**refused with 403**, and any option key not listed above with 400. The
authoritative path always runs every control, the **active** policy version
and the active risk model of its surface: an older version has rules the
current one added (v1 of `dispute-refund` has no double-refund block), so
selecting it by request would be a bypass. There is no switch that turns this
off. The what-if switches are accepted by `/v1/attacks/simulate`,
`/v1/scenarios/{key}/run` and `/v1/replay`; those runs are computed by the
same engine and **never recorded as decisions** (no audit event, no case, no
stored decision; `"authoritative": false` on the returned decision). A risk
model for another surface (e.g. `acct-1.0` on a transaction scenario) is a 400,
not a silent misapplication. `sentinel.decision.authority` enforces the same
rule inside the engine, whatever the surface.

## Response — the canonical Decision

```jsonc
{
  "decision_id": "DEC-…", "workflow": "dispute", "subject_type": "dispute", "subject_id": "DSP-…",
  "amount": 18000, "requested_capability": "APPROVE_REFUND",
  "risk_score": 40, "risk_level": "MEDIUM", "risk_assessment_id": "RISK-…",
  "ai_recommendation": {"agent": "Dispute Triage Agent", "recommended_action": "approve_refund",
                        "requested_capability": "APPROVE_REFUND", "trust": "MODEL_GENERATED", …},
  "evidence_verdict": "CONTRADICTED", "evidence_ids": ["EV-LEDGER-001", …], "contradiction_count": 1,
  "security_severity": "CRITICAL", "security_event_id": "SEC-…",
  "policy": {"policy_id": "dispute-refund", "version": 3, "outcome": "BLOCK", "matched_rules": [...], "explanations": [...]},
  "authorization": {"status": "DENIED", "capability": "APPROVE_REFUND", "actor": "SYSTEM", "reason": "…"},
  "human_review": {"required": true, "reason": "…", "case_id": "CASE-…"},
  "final_action": "BLOCK", "executed_capability": null,
  "blocked_by": ["trusted_evidence", "ai_security_gateway", "policy:dispute-refund@v3", "capability_authorization"],
  "reason": "…", "trail": [{"stage": "provenance", …}, …],
  "input_hash": "…", "provider": "offline", "model": "offline-simulator",
  "case_id": "CASE-…", "audit_event_id": "AUD-…", "controls": [...], "ai_agreed": false,
  "authoritative": true   // recorded by the authoritative path; false for any what-if
}
```

## Input classes: system of record vs demo / simulation

Sentinel adjudicates claims against trusted facts; it does **not** verify
those facts, and it has no real ledger integration. Every decision therefore
carries `facts_source`, which the decision's audit event also records:

| `facts_source` | Request form | Meaning |
|---|---|---|
| `system_of_record` | `{dispute_id}`, `{application_id}`, `{transaction_id}`, `{session_id}`, investigations | the facts were read by reference from the record store -- here Sentinel's synthetic SQLite store, standing in for a bank's systems of record |
| `caller_supplied` | `{ledger}`, `{records}`, `{transaction}`, `{session}` objects in the body | **demo / simulation input**: the caller supplied the facts; they are trusted by contract and Sentinel did not read them from anywhere |
| `demo_fixture` | `/v1/attacks/simulate` presets | **demo / simulation input**: a shipped synthetic preset |

The id forms are the production-shaped ones. The object forms exist so the
console and the demos can try a scenario without a dataset; they are not a
way to verify a ledger. `GET /v1/system` returns the three descriptions and
the console shows the source on every decision.

## Trust contract

Everything in `narrative`, `documents`, `messages`, `untrusted`, `message`,
`case_notes` and `text` is treated as **untrusted** with the trust class given
(or `USER_CONTROLLED` / `DOCUMENT_CONTROLLED` by field). `ledger`, `records`,
`transaction` and `session` are treated as **trusted records supplied by the
caller**. That is a contract, not a proof: in an integration the caller must
be the system of record, never a channel a customer can reach. Consequences:

- put the API behind the institution's boundary and set `SENTINEL_API_KEY`;
  the server prints a warning when it starts open on a non-loopback address;
- prefer the record-backed forms (`{dispute_id}`, `{application_id}`,
  `{transaction_id}`, `{session_id}`), which read the facts from the store;
- never build the `ledger` object from anything the disputing party sent.

`POST /v1/replay` compares the recomputed decision with the decision **as
recorded**, never merely "replay completed":

- `original` is the stored decision's summary, **anchored to its audit
  event**: the fields the event carries (action, risk score, policy version,
  authorization, executed capability, evidence verdict, risk model) are taken
  from the tamper-evident chain, and the stored input snapshot is checked
  against the SHA-256 the event recorded. Any disagreement is listed in
  `record_issues` and `record_verified` is `false`;
- `replayed` is the composer's output under the overrides; `decision_diff`
  lists every field that changed with before / after values, the risk model
  included;
- `versions` names the policy, risk model and engine on each side;
- `policy_drift`: the policy version named in the snapshot no longer has the
  content the decision was made under; `engine_drift` (alias
  `original_drift`): re-deriving the decision from its own snapshot no longer
  reproduces it.

For identical input, trusted facts, risk configuration, policy version and
engine version the result reproduces and the diff is empty
(`tests/test_replay_determinism.py`, `tests/test_replay_integrity.py`). A
replay is stored as a replay record and an audit event of kind `replay`; it
never overwrites the original decision.

`POST /v1/cases/{id}/decision` takes `reviewer`, `outcome`
(approve | deny | escalate), `note` and an optional declared `role`
(`HUMAN_REVIEWER` default, or `SENIOR_REVIEWER`). It is the only way a case
reaches RESOLVED. A reserved system / model actor name, or the name of an
agent that recommended on the case, is a 403; approving a case whose
capability needs a senior reviewer with `HUMAN_REVIEWER` is a 403; a decision
on an OPEN (untriaged) or already RESOLVED case is a 409.

## Errors

| Status | When |
|---|---|
| 400 | malformed JSON, missing/invalid field, unknown option, invalid policy document |
| 401 | `SENTINEL_API_KEY` set and no valid `Authorization: Bearer` / `X-API-Key` (compared in constant time) |
| 403 | a what-if switch (`unguarded`, `options.controls`, `options.policy_version`, `options.risk_model`, investigation `as_of`) on an evaluate route; a reviewer that is not a human actor or lacks the case's required level |
| 404 | unknown route / id |
| 409 | invalid case transition; a human decision on an OPEN or RESOLVED case |
| 413 | body over 256 KB (the body is drained first, so the client sees the 413) or a text over 20,000 chars |
| 429 | per-client rate limit (`SENTINEL_RATE_LIMIT` requests/minute, default 600, 0 = off) |
| 500 | internal error; never a stack trace |

Errors are `{"error", "code", "request_id"}`. Every response carries `X-Request-ID`; structured logs (`SENTINEL_LOG=INFO`)
carry `trace_id`, `request_id`, `decision_id`, workflow, entity, risk, policy
version, capability and action -- never raw untrusted text.

## Examples

```bash
# the flagship attack
curl -s localhost:8000/v1/attacks/simulate -H 'Content-Type: application/json' \
  -d '{"kind":"document_injection"}' | python3 -m json.tool | head -40

# a dispute with your own ledger
curl -s localhost:8000/v1/disputes/evaluate -H 'Content-Type: application/json' -d '{
  "narrative": "My order never arrived, it never came, please refund.",
  "ledger": {"amount": 18000, "delivery_status": "delivered", "policy_auto_limit": 50000}}'

# replay a decision under policy v1 with a lower threshold
curl -s localhost:8000/v1/replay -H 'Content-Type: application/json' \
  -d '{"decision_id":"DEC-…","policy_version":1,"rule_values":{"review-critical-risk":70}}'

curl -s localhost:8000/v1/audit/verify
```

## Programmatic use

```python
from sentinel.app import SentinelApp
app = SentinelApp.demo()                       # seeded synthetic world, in memory
b = app.evaluate_dispute("My order never arrived", {"amount": 18000, "delivery_status": "delivered"})
print(b.decision.final_action, b.decision.blocked_by)
```
