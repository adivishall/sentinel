# Audit model

Rendered by `make docs` from `sentinel/audit/chain.py`.

## Terminology

This is a **tamper-evident application audit chain**. It is not a blockchain
and it is not an immutable ledger: there is no consensus, no distribution and
no guarantee that a record cannot be changed. The guarantee is narrower and
precise -- **any modification, deletion, insertion or reordering of a
recorded event is detected by verification, and the first bad record is
named** -- and the trust root is a checkpoint stored outside the store.

## The record

One `AuditEvent` per decision, case action, human decision or system event.
The hash covers every field except the two hashes: `event_id`, `sequence`, `timestamp`, `decision_id`, `actor`, `workflow`, `subject_id`, `risk_score`, `risk_level`, `policy_id`, `policy_version`, `capability`, `action`, `evidence_ids`, `security_severity`, `input_hash`, `case_id`, `kind`, `detail`.
`event_hash = SHA-256(canonical_json(body) ‖ previous_hash)`; the first
event's `previous_hash` is the genesis constant; `sequence` is contiguous
from 0. `detail` is redacted before hashing: any of `document`, `narrative`, `prompt`, `rationale`, `span`, `submission`, `text` is replaced by its
SHA-256 and length, so **no untrusted prose is ever persisted in the chain**
(detector spans are hashed too).

A decision's event also records, in `detail`, the SHA-256 of the decision's
input snapshot (`snapshot_hash`), the risk-model version and the engine
version. Replay checks the stored snapshot against that hash and takes the
recorded side of its comparison from the event, so a decision row and a
snapshot edited consistently in the database cannot replay as "no change"
(`tests/test_replay_integrity.py`).

## Verification (`sentinel audit verify [--file PATH]`, `GET /v1/audit/verify`)

Recomputes the chain from genesis and reports every problem with its
record index; `--file` verifies an exported JSONL chain (`sentinel audit
export`) without opening a store. A failure prints **AUDIT INTEGRITY ERROR**
with the problem count and the first bad record and exits with status 2 --
never a parser traceback, never a silent pass:

| Tampering | Detected by |
|---|---|
| a field of an event modified | `event_hash` mismatch on that record |
| an event deleted | `sequence` gap on the following record, and its `previous_hash` no longer matches |
| an event inserted | `sequence` collision and a broken link on the record after it |
| events reordered | `previous_hash` mismatch |
| a record unreadable (malformed JSON, truncated line, missing field) | reported as unreadable with the reason; verification continues, so later problems are reported too, and the link from the unreadable record is not assumed |
| the chain truncated at the end | the stored length / head no longer match a checkpoint |

`tests/test_audit_chain.py`, `tests/test_data_store_replay.py`,
`tests/test_rc_hardening.py` and `tests/test_audit_corruption.py` exercise each
row -- malformed JSON, a truncated line, a missing field, a wrong hash, a wrong
predecessor, deleted / inserted / reordered lines, a cut last line -- through
the library and the CLI, and edited rows in the SQLite store.

## Backends and lookups

Memory, JSONL and SQLite backends implement the same protocol: `append`,
`count`, `tail`, `at(sequence)`, `find(event_id | decision_id)` and
`read_all`. Lookups by event id or decision id are indexed (an in-memory index
for JSONL, SQL indexes for SQLite), so the console and the API do not re-read
the log to open one event. `verify()` deliberately does read everything: a
lookup path that skipped records would be a lookup path that skipped tampering
(`tests/test_audit_indexing.py`).

## Checkpoints (`sentinel audit checkpoint`, `make audit-checkpoint`)

A `Checkpoint` (`length`, `head_hash`, `created_at`, `algorithm`, `signature`) states that at `length` events the head hash
was `head_hash`. It is meant to be stored **outside** the audit store -- a
second system, a ticket, a signed release artefact. With `SENTINEL_AUDIT_KEY`
set it is signed with HMAC-SHA256 over its canonical body, so a storage
attacker who rewrites the whole chain consistently from genesis still cannot
produce the recorded head (or forge a checkpoint without the key).
`sentinel audit verify --checkpoint FILE` checks the chain against it: the
stored prefix must still hash to the checkpointed head.

## What the chain does not do

- It does not prove *what happened*, only that the record of it was not
  altered since it was written. A compromised process can write a false event
  honestly.
- Without a checkpoint stored elsewhere, a consistent rewrite of the entire
  chain from genesis is undetectable; the checkpoint is the external anchor.
- Key management for `SENTINEL_AUDIT_KEY` is the operator's (environment
  only; never committed or logged).
- Deleting the store deletes the chain; availability is a storage concern.
