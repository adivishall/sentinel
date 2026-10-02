# Contributing

## Get it running (about 10 minutes)

Python 3.11+. One runtime dependency (`cryptography`). Offline: no API key, no network.

```bash
git clone https://github.com/adivishall/sentinel.git && cd sentinel
make install          # dev tooling + the `sentinel` command
make test             # the whole suite, offline
make lint             # ruff + black --check + mypy
make attack-compare   # the flagship attack, without and with Sentinel
make api              # API + console on http://127.0.0.1:8000 (in-memory demo data)
```

## Where to start reading

1. `README.md` -- what Sentinel decides and what it does not claim.
2. `docs/ARCHITECTURE.md` -- the packages and the one engine behind every surface.
3. `sentinel/decision/composer.py` -- the authoritative decision: a view with no
   field for untrusted text or model output.
4. `docs/INVARIANTS.md` -- what must always hold, where it is enforced, and the
   tests that fail if it breaks.
5. `docs/THREAT_MODEL.md` and `docs/FAILURE_ANALYSIS.md` -- what an attacker
   controls, and the real defects found so far.

Issues labelled `good first issue` or `help wanted` are scoped so they can be done
without reading the whole code base; each says how to test it.

## Workflow

1. Branch from `main` (`feat/...`, `fix/...`, `docs/...`).
2. For a bug, write the test first and check it fails before your fix.
3. `make test && make lint` must pass. If you change an evaluation, rerun it
   (`sentinel eval run --suite <name>`) and `make docs`; never hand-edit a number
   in `README.md` or `docs/` (they are rendered from `results/` and the code).
4. Open a pull request with the template. Security-relevant changes (anything
   under `sentinel/security`, `evidence`, `policy`, `decision`, `audit`, `trust`,
   `cases`) need a second reviewer.

## Rules that keep the architecture honest

- **No decision logic outside `sentinel/decision`.** The API, CLI, console and
  evaluation call `SentinelApp` / the workflows. A test enforces this.
- **Untrusted never becomes trusted.** Do not add a code path that turns prose,
  documents, model output or a request body into VERIFIED evidence or into a
  policy context field. Facts earn trust only from a signed statement or the
  record store.
- **Policies are data.** Add a new version file (`policy-id.vN.json`) rather than
  editing a shipped version, then `sentinel policy pin`. A version decides only
  as a signed, activated release: locally, run with
  `SENTINEL_REQUIRE_SIGNED_POLICY=0` (decisions then record `UNSIGNED`), or sign
  and activate it with your own key as in `docs/DEPLOYMENT.md` ("Policy
  releases"). Shipped releases are signed by the maintainer's key.
- **Never tune the detector or the classifier to a held-out or frozen set.** If
  one finds a miss, fix the general behaviour and add a development case.
- **No fabricated numbers.** Every metric must come from `sentinel eval run` and
  name the corpus or dataset that produced it.
- **Audit stores hashes, not prose.** Keep `redact()` in the write path.

## Reporting

- **Bugs:** open an issue with the bug template (commit, command or request
  body, expected vs actual).
- **Vulnerabilities:** do not open a public issue; see `SECURITY.md`.

## Layout

See `docs/ARCHITECTURE.md`. Tests are grouped by concern in `tests/` and listed
with what each protects in `docs/TESTING.md`; `tests/test_invariants.py` is the
security regression suite.
