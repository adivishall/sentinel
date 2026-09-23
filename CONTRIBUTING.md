# Contributing

## Workflow

1. Branch from `main` (`feat/...`, `fix/...`, `docs/...`).
2. `make test && make lint` must pass locally; CI runs the same plus the
   invariants, an evaluation smoke test, a CLI + audit-chain smoke and a
   Docker build.
3. Open a PR. Security-relevant changes (anything under `sentinel/security`,
   `sentinel/evidence`, `sentinel/policy`, `sentinel/decision`,
   `sentinel/audit`) need a second reviewer.

## Rules that keep the architecture honest

- **No decision logic outside `sentinel/decision`.** The API, CLI, console
  and evaluation call `SentinelApp` / the workflows. A test enforces this.
- **Untrusted never becomes trusted.** Do not add a code path that turns
  prose, documents or model output into VERIFIED evidence or into a policy
  context field. Extend the field catalog only with trusted fields.
- **Policies are data.** Add a new version file (`policy-id.vN.json`) rather
  than editing a shipped version in place; decisions record the version they
  used.
- **Never tune the detector to the held-out set.** If the held-out set finds
  a false positive, fix the general behaviour and add a dev-corpus case.
- **No fabricated numbers.** Every metric in the docs must come from
  `sentinel eval run` and say which corpus produced it.
- **Audit stores hashes, not prose.** Keep `redact()` in the write path.

## Layout

See `docs/ARCHITECTURE.md`. Tests are grouped by concern in `tests/`;
`tests/test_invariants.py` is the security regression suite.
