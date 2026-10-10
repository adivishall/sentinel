# Security policy

Sentinel is a security project, so findings against it are welcome. It is a
study project on synthetic data; the public demo instance (`render.yaml`) is a
synthetic, ephemeral world behind an API key, not a production service, and
nothing has an SLA.

## In scope

Any way that attacker-controlled input -- prose, uploaded documents, model
output, request bodies, ids, timestamps, headers or caller-chosen fields --
can:

- make a consequential capability (refund, payment, merchant onboarding,
  account action) execute without trusted facts that support it;
- get facts treated as `TRUSTED_LOCAL` or `VERIFIED_EXTERNAL` that were not;
- let a modified or unactivated policy decide;
- let a reviewer act beyond the role or authority limit their credential holds;
- rewrite or delete audit history without detection where a checkpoint covers it;
- reach the API from the network without authentication by accident.

`docs/THREAT_MODEL.md` and `docs/INVARIANTS.md` state what is defended and
how; `docs/LIMITATIONS.md` lists what is knowingly out of scope (for example, a
valid signature proves who stated a fact, not that it is true).

## How to report

Use GitHub's private vulnerability reporting: the **Security** tab of this
repository → **Report a vulnerability**. Please include the commit, a
reproduction (request bodies, CLI commands or a failing test) and what you
expected versus what happened.

A confirmed finding is fixed with a regression test that fails before the fix,
recorded in `CHANGELOG.md` and `docs/FAILURE_ANALYSIS.md`, and credited to you
if you wish.
