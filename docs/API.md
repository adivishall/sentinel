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
| GET | `/v1/audit`, `/v1/audit/verify`, `/v1/audit/{id}` | hash chain |
| GET, POST | `/v1/policies`, `/v1/policies/{id}?version=`, `/v1/policies/catalog`, `/v1/policies/evaluate`, `/v1/policies/validate` | policy-as-code |
| POST, GET | `/v1/replay`, `/v1/replays` | decision replay |
| GET, POST | `/v1/attacks`, `/v1/attacks/simulate` | the attack simulator |
| GET, POST | `/v1/scenarios`, `/v1/scenarios/{key}/run` | flagship scenarios |
| GET | `/v1/evaluations` | `results/*.json` |

## Options (any evaluate route)

```jsonc
"options": {
  "controls": ["provenance","detection","risk","adjudication","policy","authorization"],  // ablation only
  "unguarded": false,        // shorthand for controls: []
  "policy_version": 1,
  "risk_model": "txn-1.1",
  "hardened": false,         // hardened-prompt agent
  "skip_agent": false        // evaluate without any model call
}
```

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
  "policy": {"policy_id": "dispute-refund", "version": 2, "outcome": "BLOCK", "matched_rules": [...], "explanations": [...]},
  "authorization": {"status": "DENIED", "capability": "APPROVE_REFUND", "actor": "SYSTEM", "reason": "…"},
  "human_review": {"required": true, "reason": "…", "case_id": "CASE-…"},
  "final_action": "BLOCK", "executed_capability": null,
  "blocked_by": ["trusted_evidence", "ai_security_gateway", "policy:dispute-refund@v2", "capability_authorization"],
  "reason": "…", "trail": [{"stage": "provenance", …}, …],
  "input_hash": "…", "provider": "offline", "model": "offline-simulator",
  "case_id": "CASE-…", "audit_event_id": "AUD-…", "controls": [...], "ai_agreed": false
}
```

Everything in `narrative`, `documents`, `messages`, `untrusted`, `message`,
`case_notes` and `text` is treated as **untrusted** with the trust class given
(or `USER_CONTROLLED` / `DOCUMENT_CONTROLLED` by field). `ledger`, `records`,
`transaction` and `session` are treated as trusted records supplied by the
caller -- in an integration, the caller is the system of record, not the user.

## Errors

| Status | When |
|---|---|
| 400 | malformed JSON, missing/invalid field, unknown option, invalid policy document |
| 401 | `SENTINEL_API_KEY` set and no valid `Authorization: Bearer` / `X-API-Key` |
| 404 | unknown route / id |
| 409 | invalid case transition |
| 413 | body over 256 KB or a text over 20,000 chars |
| 429 | per-client rate limit (`SENTINEL_RATE_LIMIT` requests/minute, default 600, 0 = off) |
| 500 | internal error; never a stack trace |

Every response carries `X-Request-ID`; structured logs (`SENTINEL_LOG=INFO`)
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
