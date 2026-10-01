# Deployment

Sentinel runs three ways. All run the **same** engine; only the model provider
changes. It is **secure by default**: the server binds loopback, and it refuses
to serve on a network address without an API key unless the operator says
`--insecure-demo` in so many words.

## 1. Local (one dependency, no key)

```bash
make api                          # API + console on http://127.0.0.1:8000, in-memory demo dataset
# or with a persistent store:
make data && make analyze && sentinel --db data/sentinel.db serve
make audit-verify                 # verify the tamper-evident audit chain
make audit-checkpoint             # legacy HMAC export; signed, anchored checkpoints: see "Audit checkpoints"
```

The in-memory demo prints two demo reviewer credentials (alice, sam) for the
console's case form. It does that only on a loopback bind or under
`--insecure-demo`; anything else needs a real reviewer registry.

## 2. Docker

```bash
make docker-build                 # docker build -t sentinel .
make docker-run                   # demo: published on 127.0.0.1:8000 only, SENTINEL_INSECURE_DEMO=1
curl localhost:8000/health
```

Inside the container the server binds all interfaces, so the image **refuses
to start** unless it has an API key or the insecure-demo flag:

```bash
# a deployment: the key is a mounted secret, not an environment variable that
# `docker inspect` would show
docker run --rm -p 127.0.0.1:8000:8000 \
  -v /etc/sentinel/api_key:/run/secrets/api_key:ro -e SENTINEL_API_KEY_FILE=/run/secrets/api_key \
  -v /etc/sentinel/trust.json:/etc/sentinel/trust.json:ro -e SENTINEL_TRUST_STORE=/etc/sentinel/trust.json \
  -v /etc/sentinel/reviewers.json:/etc/sentinel/reviewers.json:ro -e SENTINEL_REVIEWERS=/etc/sentinel/reviewers.json \
  -e SENTINEL_REQUIRE_SIGNED_FACTS=1 sentinel
```

- `python:3.11-slim`, non-root user, `HEALTHCHECK` on `/health`, a `/data`
  volume for the SQLite store, offline by default.
- Live mode: `docker build --build-arg LIVE=1 -t sentinel:live .` and run with
  `-e SENTINEL_FORCE_OFFLINE=0` and the Anthropic key as a mounted secret.

## 3. Live model

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make live-check                       # one call: verify key + model
SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models   # same corpus, real agent
```

## What the server enforces

| Control | Behaviour |
|---|---|
| Bind | loopback by default (`serve`, `make_server`, `sentinel serve`, `make api`). A non-loopback bind with no API key is refused before a socket opens (CLI exit 2). An API key shorter than 16 characters does not count. |
| `--insecure-demo` | the only way to serve the network without a key (`SENTINEL_INSECURE_DEMO=1` for Docker). Logged at ERROR, printed as a warning, recorded in the `SERVER_START` audit event, and marked on every response (`X-Sentinel-Insecure-Demo: 1`); the console shows a red banner. |
| Authentication | `Authorization: Bearer <key>` or `X-API-Key`; compared in constant time over SHA-256 digests (no length leak). `/health` and `/version` (name and version only) stay open. The console asks for the key once and keeps it for the tab (`sessionStorage`). |
| Browser requests | a POST must be `application/json` (415 otherwise: a page elsewhere cannot send JSON without a preflight this server never answers); an `Origin` that is not this host (or a name in `SENTINEL_ALLOWED_HOSTS`), `Origin: null`, an unparseable `Origin` or `Sec-Fetch-Site: cross-site` is a 403. |
| Host | a loopback server answers only requests addressed to a loopback name (`127.0.0.1`, `localhost`, `[::1]`) or to a name in `SENTINEL_ALLOWED_HOSTS`; anything else is a 421. This is what stops DNS rebinding: a page whose own name resolves to 127.0.0.1 is same-origin with itself, but its requests still name its host. A network bind behind a proxy should list its public name. |
| Headers | `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff` on every response; a CSP on the console (`script-src 'self'`, `connect-src 'self'`, `frame-ancestors 'none'`). |
| Limits | 256 KiB bodies (413), negative `Content-Length` (400), a 30-second socket timeout (a fully stalled client is dropped), at most `SENTINEL_MAX_CONNECTIONS` (64) connections at once, a per-client rate limit. A client that trickles a byte every few seconds is the TLS proxy's to cut off: `http.server` has no request deadline. |
| Disclosure | `/v1/system` names files (store, trust store), never paths; no stack traces; no key, key fingerprint, token or credential in any response, log line or audit event. With a key set, data files (`snapshot.json`) need it too; only the console's code is public. |
| Start | a `SERVER_START` event in the audit chain: version, bind, auth mode, where the API key came from (environment or file -- never a fingerprint of it), insecure-demo, mode, signed-facts and signed-policy settings, and fingerprints of the trust store and reviewer registry (file SHA-256, key ids, active reviewer ids, credential ids). |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_DB` | `data/sentinel.db` | SQLite store path (`:memory:` for ephemeral) |
| `SENTINEL_API_KEY` | unset | the API's bearer token (16+ characters to serve a network address) |
| `SENTINEL_API_KEY_FILE` | unset | read the API key from this file (a mounted secret) |
| `SENTINEL_INSECURE_DEMO` | unset | `1` = serve a network address without a key (throwaway demos; audited) |
| `SENTINEL_ALLOWED_HOSTS` | unset | comma-separated public names the API may be addressed as (behind a TLS proxy); requests and `Origin`s naming other hosts are refused |
| `SENTINEL_MAX_CONNECTIONS` | `64` | concurrent connections; past it a new connection is closed at once |
| `SENTINEL_FORCE_OFFLINE` | `1` in Make/Docker | force the deterministic offline agent |
| `ANTHROPIC_API_KEY` | — | enables live mode when offline is not forced; never committed or logged |
| `SENTINEL_MODEL` | `claude-opus-5-5` | live model id |
| `SENTINEL_RATE_LIMIT` | `600` | requests per minute per client (0 = off) |
| `SENTINEL_AUDIT_ANCHOR` | unset | where signed audit checkpoints are anchored: a directory (one file per checkpoint, never overwritten) or a `.jsonl` append-only file, outside the audit store writer's reach |
| `SENTINEL_AUDIT_KEY` | unset | legacy HMAC checkpoint (`audit checkpoint` without `--sign-key`); a shared secret that verifies and forges alike |
| `SENTINEL_TRUST_STORE` | unset (nothing trusted) | trust store JSON: the public keys of the issuers whose signed fact envelopes Sentinel accepts |
| `SENTINEL_REQUIRE_SIGNED_FACTS` | off (on for the in-memory demo) | every record read by id must come with its issuer's signed statement; a missing one is `INVALID` |
| `SENTINEL_POLICY_TRUST` | the shipped root (`sentinel/trust/policy_root.json`) | trust store holding the `policy-release` keys whose signed releases and activations Sentinel accepts |
| `SENTINEL_REQUIRE_SIGNED_POLICY` | on | `0` runs unsigned policies (each decision then records `UNSIGNED`) |
| `SENTINEL_REVIEWERS` | unset (nobody can act on cases) | reviewer registry JSON: who may act on cases, their role and authority limit, their credential's SHA-256 |
| `SENTINEL_REVIEWER_TOKEN` | — | the CLI's reviewer credential for `case transition` / `case decide` |
| `SENTINEL_LOG` | `WARNING` | `INFO` for structured per-decision JSON logs |
| `PORT` | `8000` | listen port |

Secrets come from the environment or mounted files only. `.env.example`
documents them.

## Production runbook

This is the recommended shape; Sentinel's own code is a lab-grade engine with
production-shaped boundaries (see "Honest scope" below).

### Topology and TLS

- Sentinel listens on loopback or a private interface. A TLS-terminating
  reverse proxy (nginx, Caddy, Envoy) sits in front: HTTP/1.1, request
  timeouts, a body limit no larger than Sentinel's 256 KiB. Bearer tokens and
  reviewer credentials never cross a network unencrypted.
- Behind a proxy every client shares one address, so Sentinel's per-client
  rate limit becomes a global one; rate-limit per client at the proxy, and give
  the proxy request deadlines (slow clients are its job).
- Set `SENTINEL_ALLOWED_HOSTS` to the public name, or have the proxy keep the
  client's `Host` (`proxy_set_header Host $http_host;`): otherwise the console's
  POSTs are refused as cross-origin.
- Start with `SENTINEL_API_KEY_FILE`, `SENTINEL_TRUST_STORE`,
  `SENTINEL_REVIEWERS`, `SENTINEL_REQUIRE_SIGNED_FACTS=1` and the policy trust
  root. Check the `SERVER_START` event (`sentinel audit list`): `auth=api_key`,
  `insecure_demo=false`, the fingerprints you expect.

### Keys: three purposes, three keys, none on the Sentinel host

A trust-store key has exactly one purpose, and the verifiers refuse a key used
for another. Keep them on independent schedules.

| Key | Held by | Sentinel holds |
|---|---|---|
| Fact issuer (`purpose: facts`) | each system of record, ideally in an HSM/KMS | public keys in `SENTINEL_TRUST_STORE` |
| Policy release (`purpose: policy-release`) | the policy release pipeline | public keys in `SENTINEL_POLICY_TRUST` |
| Audit checkpoint (`purpose: audit-checkpoint`) | the operator's checkpointing job (its own process and credentials, not the server's) | public keys in `SENTINEL_TRUST_STORE`; the anchor is read-only for the server |

**Private signing keys never live on the Sentinel application host.** The
trust stores hold public keys only; deploy them read-only and root-owned,
outside the data and policy directories.

### Issuer keys and the trust store

```bash
sentinel trust keygen --issuer core-ledger --scopes dispute_ledger \
    --key-out /secure/core-ledger.pem --trust-out /etc/sentinel/trust.json
sentinel trust sign --key /secure/core-ledger.pem --issuer core-ledger \
    --kind dispute_ledger --id DSP-000123 --payload ledger.json --out envelope.json
sentinel --trust-store /etc/sentinel/trust.json trust verify envelope.json --kind dispute_ledger
sentinel --trust-store /etc/sentinel/trust.json trust ingest envelope.json   # store it beside the record
sentinel --trust-store /etc/sentinel/trust.json trust revoke <key_id> --reason compromised
```

### Audit checkpoints

```bash
sentinel trust keygen --issuer audit-notary --purpose audit-checkpoint \
    --key-out /secure/audit-checkpoint.pem --trust-out /etc/sentinel/trust.json
# a scheduled job (its own process; the server adopts the record it appends), with the
# anchor on storage the store's writer cannot modify -- WORM, or a directory exported or
# committed elsewhere after each run
sentinel --db /data/sentinel.db --trust-store /etc/sentinel/trust.json audit checkpoint \
    --sign-key /secure/audit-checkpoint.pem --signer audit-notary --anchor /mnt/worm/sentinel-anchor
sentinel --db /data/sentinel.db --trust-store /etc/sentinel/trust.json audit verify \
    --anchor /mnt/worm/sentinel-anchor --require-anchored
```

### Policy releases

```bash
sentinel trust keygen --issuer policy-pipeline --purpose policy-release \
    --key-out /secure/policy-release.pem --trust-out /etc/sentinel/policy-trust.json
sentinel policy pin                                   # pin the new version's digest
sentinel policy sign --key /secure/policy-release.pem --signer policy-pipeline \
    --policy dispute-refund --version 5               # release exactly this document
sentinel policy activate --key /secure/policy-release.pem --signer policy-pipeline \
    --policy dispute-refund --version 5 --effective-from 2026-11-01T00:00:00Z
SENTINEL_POLICY_TRUST=/etc/sentinel/policy-trust.json sentinel policy verify
```

A changed policy is a new version: signed, then activated explicitly (a higher
number activates nothing). An in-place edit fails the release digest and the
server refuses to start. Rolling back is a *new* activation of the older
version with a higher sequence; deleting the newest activation is refused,
because the audit chain remembers the activation decisions were made under.

### Reviewer credentials

```bash
sentinel reviewers add --registry /etc/sentinel/reviewers.json \
    --id priya --name "Priya N." --role SENIOR_REVIEWER --limit 5000000
sentinel reviewers deactivate --registry /etc/sentinel/reviewers.json --id priya
```

The token is printed once (do not run `add` in a logged shell), handed over
out of band, and stored only as its SHA-256. Deactivate and reload to revoke;
a deactivated reviewer's pending four-eyes approval stops counting.

### Reloading configuration

Replace the file atomically (write a temp file, then rename), then
`kill -HUP <pid>` or restart. Both read the files the same way. The signal only
wakes a reloader thread (a burst of signals is one or more reloads, never a
deadlock), and a reload that fails for any reason keeps the server running on
its old configuration. The reload is audited (`CONFIG_RELOAD`: source, file SHA-256, keys added / removed / newly
revoked, reviewers added / deactivated, credential ids -- never key bytes or
tokens). A file that fails to load is refused, the running configuration stays
(nothing new is trusted, nothing is dropped), and `CONFIG_RELOAD_FAILED` is
audited. Policies are not reloaded: a policy change is a release and an
activation, picked up at restart.

### Rotation

- **Rotate a key:** add the new key, deploy the trust store, reload, switch the
  signer, then retire the old key with `not_after` (what it signed stays
  valid). **Revoke** only on compromise: everything the key signed becomes
  `REVOKED` (facts) or refused (policy releases) at once.
- **Fact, policy and checkpoint keys rotate independently.** None is derived
  from another.
- **Reviewer credentials:** `reviewers add` a new credential for the person,
  deactivate the old one, reload.
- **The API key:** replace the mounted `SENTINEL_API_KEY_FILE` in place; the
  server reads it again when it changes (an environment variable needs a
  restart).

### Logs and retention

Logs are JSON on stderr (`SENTINEL_LOG`); ship them. They carry ids, hashes
and outcomes, never prose, keys or credentials. Retention and PII policy are
the operator's.

## Static console (GitHub Pages)

`make snapshot` writes `ui/snapshot.json` -- a read-only copy of what the
engine computed (overview, transactions, cases, attack results, scenarios,
evaluations). `ui/index.html` uses it automatically when no API is reachable
and says so in the sidebar. Custom attacks and case actions need the live
console.

## Honest scope

This is a lab-grade control with production-shaped boundaries, not a hardened
service. `http.server` is not a production web server; real use needs the
reverse proxy above (or a real WSGI/ASGI server), SSO/OIDC for reviewers
instead of Sentinel-issued bearer tokens, a secret manager, log shipping,
retention and PII policies, integration with the real ledger, records and
authentication services in place of the SQLite context builders, an anchor
nobody can delete from (WORM storage or a transparency log; the shipped anchors
are a directory and a file), and a live-model evaluation on the operator's own
key.
