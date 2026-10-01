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

## Options (the five workflow evaluate routes)

```jsonc
"options": {
  // user-controllable: accepted everywhere
  "hardened": false,         // hardened-prompt agent
  "skip_agent": false,       // no model call -- so no model-output check either (see below)
  // what-if: refused (403) on the evaluate routes
  "controls": ["provenance","detection","risk","adjudication","policy","authorization"],
  "unguarded": false,        // shorthand for controls: []
  "policy_version": 1,       // a historical version
  "risk_model": "txn-1.0"    // a historical model of the route's surface
}
```

`skip_agent` is for callers that want the deterministic decision without a
recommendation (batch runs, latency). With no model there is no model output,
so the gateway's check of the model's tool call does not run; the text scan,
evidence, policy and authorization are unchanged, and the outcome is still
only what the records support. The caller of this API is the institution's
own system, not the customer.

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

## Decision lineage

`GET /v1/decisions/{id}/lineage` answers, for one recorded decision: **what**
(workflow, subject, amount), **when** (time, engine version), **facts** (source,
provenance, payload digest), **evidence**, **risk** (score, model version and
configuration digest), **ai** (provider, model, recommendation -- recorded,
never authoritative), **policy** (version, outcome, rules, release digest,
signer, activation), **capability** (requested, authorization, actor), **who
authorised it** (the system's grant, or the reviewers -- id, role, credential
id -- who acted on its case), the **outcome**, and its place in the **audit**
chain with anchoring status. It is assembled from the stored record and its
audit event; nothing is recomputed. Replay does that, and every replay names
its `drift` (policy content, risk-model configuration, engine, record vs audit,
policy-release artifact, audit anchor, fact signature) and a `drift_class`.

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
  "policy": {"policy_id": "dispute-refund", "version": 4, "outcome": "BLOCK", "matched_rules": [...], "explanations": [...],
             "policy_digest": "5c28…", "release_status": "VERIFIED", "release_signer": "sentinel-policy",
             "release_key_id": "ed25519:…", "activation_sequence": 4},
  "authorization": {"status": "DENIED", "capability": "APPROVE_REFUND", "actor": "SYSTEM", "reason": "…"},
  "human_review": {"required": true, "reason": "…", "case_id": "CASE-…"},
  "final_action": "BLOCK", "executed_capability": null,
  "blocked_by": ["trusted_evidence", "ai_security_gateway", "policy:dispute-refund@v3", "capability_authorization"],
  "reason": "…", "trail": [{"stage": "provenance", …}, …],
  "input_hash": "…", "provider": "offline", "model": "offline-simulator",
  "case_id": "CASE-…", "audit_event_id": "AUD-…", "controls": [...], "ai_agreed": false,
  "authoritative": true,  // recorded by the authoritative path; false for any what-if
  "facts_source": "system_of_record",
  "provenance": {"status": "VERIFIED_EXTERNAL", "kind": "dispute_ledger", "subject": "dispute:DSP-…",
                 "source": "synthetic-ledger", "key_id": "ed25519:…", "envelope_digest": "…",
                 "payload_digest": "…", "sequence": 1, "reason": "signed by …", …}
}
```

## Input classes and fact provenance

How the facts reach a decision decides what they can establish. Each
decision carries both the transport (`facts_source`) and what verified
(`provenance.status`, see `docs/SECURITY_MODEL.md`). The decision's audit
event records both, together with the payload digest.

| Request form | `facts_source` | `provenance.status` |
|---|---|---|
| `{dispute_id}`, `{application_id}`, `{transaction_id}`, `{session_id}` | `system_of_record` | `VERIFIED_EXTERNAL` when the store holds the issuer's signed statement for the record (verified again now, and checked against the stored row; a mismatch is `INVALID`), otherwise `TRUSTED_LOCAL`. With `require_signed_facts`, a record whose statement is missing is `INVALID`. |
| `{facts_envelope}`: an issuer's signed statement carried by the caller | `caller_supplied` | `VERIFIED_EXTERNAL` only if it verifies against the operator's trust store, and only for the record it names. Otherwise `INVALID`, `EXPIRED`, `REVOKED` or `SUPERSEDED`. |
| `{ledger}`, `{records}`, `{transaction}`, `{session}` objects in the body | `caller_supplied` | `UNTRUSTED`: a claim about the records. It can make an outcome stricter (a refunded ledger still denies) but never support one: what it would support is held for human review, and nothing executes. |
| `/v1/attacks/simulate` presets | `demo_fixture` | the demo issuer signs the preset's ledger, so `VERIFIED_EXTERNAL` (labelled as the ephemeral demo issuer) |

`facts_envelope` is accepted on the dispute, merchant, transaction and account
evaluate routes. Sending it together with the body facts it replaces is a 400.
A signed statement must state every field its kind requires, otherwise it is
`INVALID`: Sentinel does not fill in an issuer's silence with defaults.

A record the store holds is evaluated **by id** only. Body facts or a
statement for a stored dispute, application, transaction or session are a 400
on every route, `messages` (multi-turn) included
("held by the record store; evaluate it by id"); so is an ASCII-case variant
of a stored id. Every caller-named record id (`transaction_id`, `dispute_id`,
`application_id`, `session_id`, `merchant_id`, and the ids inside a
`transaction` or `session` object) must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
or it is a 400. Its recorded submission, its account's context and its stored
statement decide.

A consequential capability executes **once** per workflow, subject and
capability. A second evaluation of a subject whose capability already executed
(by the system, or by a human approval) is `DENY` with the reason "already
executed" and the earlier decision id; the snapshot records it as
`prior_execution` and replay restores it.

Account security: a `requested_capability` is a claim about what the session
asked for, and the session record is the evidence. A request the record does
not show is `INSUFFICIENT` and goes to human review, never execution.

| Capability | Evidenced by |
|---|---|
| `CHANGE_PAYOUT` | `payout_change` |
| `FREEZE_ACCOUNT` | `freeze_request` |
| `UNFREEZE_ACCOUNT` | `unfreeze_request` |
| `RELEASE_FUNDS` | `release_request` |

An unsigned `transaction` or `session` body is assessed as of the system's
time, not its own timestamp.

A stored dispute or application is evaluated on its **recorded** submission.
A different `narrative` or `application` sent with a record id is a 400: new
text is a new submission, not a way to re-point a stored one. Duplicate keys
anywhere in a request body are a 400.

## Trust contract

Everything in `narrative`, `documents`, `messages`, `untrusted`, `message`,
`case_notes` and `text` is treated as **untrusted**, with the trust class given
(or `USER_CONTROLLED` / `DOCUMENT_CONTROLLED` by field). Record facts are
trusted exactly as far as their provenance goes:

- A signed statement is trusted if it verifies. A caller can carry a verified
  fact but cannot forge one.
- The record store is trusted for where it is kept. Require signed facts
  (`SENTINEL_REQUIRE_SIGNED_FACTS=1`, plus a trust store naming the issuers)
  where the store itself is not a sufficient boundary.
- Body facts are never trusted.

The server binds loopback by default and refuses a network bind without an API
key (`SENTINEL_API_KEY` / `SENTINEL_API_KEY_FILE`, 16+ characters) unless it
was started with `--insecure-demo`, which is logged, audited and marked on
every response (`X-Sentinel-Insecure-Demo: 1`). POST bodies must be
`application/json`, and a cross-site POST (`Origin` of another host,
`Origin: null`, `Sec-Fetch-Site: cross-site`) is refused. See
[DEPLOYMENT](DEPLOYMENT.md#what-the-server-enforces).

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
- `facts`: the decision's recorded fact provenance, and its signed statement
  verified again against the current trust store. If the key has been revoked
  since the decision, this shows `REVOKED`.

For identical input, trusted facts, risk configuration, policy version and
engine version the result reproduces and the diff is empty
(`tests/test_replay_determinism.py`, `tests/test_replay_integrity.py`). A
replay is stored as a replay record and an audit event of kind `replay`; it
never overwrites the original decision.

Case actions (`POST /v1/cases`, `/v1/cases/{id}/transition`,
`/v1/cases/{id}/decision`) act as the reviewer whose credential is in
`X-Reviewer-Token`. The reviewer registry (`SENTINEL_REVIEWERS`) resolves the
id, role and authority limit. Responses:

- no or unknown credential → 401;
- a body naming `reviewer`, `role`, `actor` or `reviewer_id` → 400;
- a reviewer the case's capability does not allow, a senior needed on an
  escalated case, an amount above the reviewer's limit, or a second approval
  by the same reviewer where four eyes apply → 403;
- a decision on an OPEN (untriaged) or already RESOLVED case → 409.

`/decision` takes `outcome` (approve | deny | escalate) and `note`. It is the
only way a case reaches RESOLVED. A first of two required approvals leaves the
case open ("approvals 1 of 2").

## Errors

| Status | When |
|---|---|
| 400 | malformed JSON (including a duplicated key), missing/invalid field, unknown option, invalid policy document, `facts_envelope` together with the facts it replaces, new text on a stored dispute or application |
| 401 | an API key is configured and no valid `Authorization: Bearer` / `X-API-Key` (compared in constant time); a case action without an active reviewer credential (`X-Reviewer-Token`) |
| 415 | a POST whose `Content-Type` is not `application/json` |
| 421 | a loopback server addressed under another host name (DNS rebinding), unless the name is in `SENTINEL_ALLOWED_HOSTS` |
| 403 | a cross-site POST (`Origin` not this host, `Origin: null`, `Sec-Fetch-Site: cross-site`); a what-if switch (`unguarded`, `options.controls`, `options.policy_version`, `options.risk_model`, investigation `as_of`) on an evaluate route; a reviewer that is not a human actor or lacks the case's required level |
| 404 | unknown route / id |
| 409 | invalid case transition; a human decision on an OPEN or RESOLVED case |
| 413 | body over 256 KB (the body is drained first, so the client sees the 413) or a text over 20,000 chars |
| 429 | per-client rate limit (`SENTINEL_RATE_LIMIT` requests/minute, default 600, 0 = off) |
| 500 | internal error; never a stack trace |
| 503 | no trustworthy active policy (a signed activation is missing or was rolled back): the service cannot decide |

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
