# Deployment

Sentinel runs three ways. All run the **same** engine; only the model provider
changes.

## 1. Local (no dependencies, no key)

```bash
make api                          # API + console on :8000, in-memory demo dataset
# or with a persistent store:
make data && make analyze && sentinel --db data/sentinel.db serve
make audit-verify                 # verify the tamper-evident audit chain
make audit-checkpoint             # export (and, with SENTINEL_AUDIT_KEY, sign) the chain head
```

## 2. Docker

```bash
make docker-build                 # docker build -t sentinel .
make docker-run                   # docker run --rm -p 8000:8000 sentinel
curl localhost:8000/health
```

- `python:3.11-slim`, non-root user, `HEALTHCHECK` on `/health`, a `/data`
  volume for the SQLite store, offline by default.
- Live mode: `docker build --build-arg LIVE=1 -t sentinel:live .` and run with
  `-e ANTHROPIC_API_KEY=… -e SENTINEL_FORCE_OFFLINE=0`.

## 3. Live model

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make live-check                       # one call: verify key + model
SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models   # same corpus, real agent
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_DB` | `data/sentinel.db` | SQLite store path (`:memory:` for ephemeral) |
| `SENTINEL_FORCE_OFFLINE` | `1` in Make/Docker | force the deterministic offline agent |
| `ANTHROPIC_API_KEY` | — | enables live mode when offline is not forced; never committed or logged |
| `SENTINEL_MODEL` | `claude-opus-5` | live model id |
| `SENTINEL_API_KEY` | unset | if set, the API requires this bearer token (`/health`, `/version` stay open) |
| `SENTINEL_RATE_LIMIT` | `600` | requests per minute per client (0 = off) |
| `SENTINEL_ALLOW_UNGUARDED` | unset | `1` lets the evaluate routes accept `unguarded` / `options.controls` (lab use only; the simulator and replay always accept them) |
| `SENTINEL_AUDIT_KEY` | unset | if set, `sentinel audit checkpoint` signs the exported checkpoint with HMAC-SHA256 and `audit verify --checkpoint` authenticates it; keep the key and the checkpoint outside the audit store |
| `SENTINEL_LOG` | `WARNING` | `INFO` for structured per-decision JSON logs |
| `PORT` | `8000` | listen port |

Secrets come from the environment only. `.env.example` documents them.

## Static console (GitHub Pages)

`make snapshot` writes `ui/snapshot.json` -- a read-only copy of what the
engine computed (overview, transactions, cases, attack results, scenarios,
evaluations). `ui/index.html` uses it automatically when no API is reachable
and says so in the sidebar. Custom attacks and case actions need the live
console.

## Production notes (honest scope)

This is a lab-grade control with production-shaped boundaries, not a
hardened service. Before real use: a reverse proxy with TLS and a real
WSGI/ASGI server, per-tenant keys and roles, secret management, log shipping,
retention and PII policies, integration with the real ledger / records /
authentication services in place of the SQLite context builders, and a
live-model evaluation on the operator's own key.
