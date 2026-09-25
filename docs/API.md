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
| GET, POST | `/v1/cases`, `/v1/cases/{id}`, `/v1/cases/{id}/transition`, `/v1/cases/{id}/decision` | cases; human-only resolution |
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
  "controls": ["provenance","detection","risk","adjudication","policy","authorization"],  // ablation only
  "unguarded": false,        // shorthand for controls: []
  "policy_version": 1,
  "risk_model": "txn-2.0",   // txn-1.0 | txn-1.1 | txn-2.0
  "hardened": false,         // hardened-prompt agent
  "skip_agent": false        // evaluate without any model call
}
```

`controls` and `unguarded` are **refused with 403 on the evaluate routes**
unless the server runs with `SENTINEL_ALLOW_UNGUARDED=1`. The authoritative
path is always the full control set by request; the ablation switches are
accepted by `/v1/attacks/simulate` and `/v1/replay`, which record the control
set on the decision and the audit event.

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
  "case_id": "CASE-…", "audit_event_id": "AUD-…", "controls": [...], "ai_agreed": false
}
```

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

`POST /v1/replay` compares the recomputed decision with the **originally
stored** one, never merely "replay completed": `decision_diff` lists every
field that changed with its before / after values, `policy_drift` says the
policy version named in the snapshot no longer has the content the decision
was made under, and `engine_drift` (alias `original_drift`) says re-deriving
the original from its snapshot no longer reproduces the recorded outcome. For
identical input, trusted facts, risk configuration, policy version and engine
version the deterministic result reproduces and the diff is empty
(`tests/test_replay_determinism.py`).

## Errors

| Status | When |
|---|---|
| 400 | malformed JSON, missing/invalid field, unknown option, invalid policy document |
| 401 | `SENTINEL_API_KEY` set and no valid `Authorization: Bearer` / `X-API-Key` (compared in constant time) |
| 403 | `unguarded` / `options.controls` on an evaluate route without `SENTINEL_ALLOW_UNGUARDED=1` |
| 404 | unknown route / id |
| 409 | invalid case transition |
| 413 | body over 256 KB or a text over 20,000 chars |
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
