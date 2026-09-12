# Deployment

Sentinel runs three ways. All of them run the **same** firewall code; only the
agent's cognition (offline simulator vs real Claude) changes.

## 1. Local (no dependencies, no key)

```bash
python3 sentinel_api.py          # or: make api   (port 8000, offline)
curl localhost:8000/health
```

The offline core has **zero runtime dependencies**. It is the default and needs
neither network nor credentials.

## 2. Docker

```bash
make docker-build                # docker build -t sentinel-api .
make docker-run                  # docker run --rm -p 8000:8000 sentinel-api
curl localhost:8000/health
```

- Base image `python:3.11-slim`; runs as a non-root user; container `HEALTHCHECK`
  hits `/health`.
- Offline by default (`SENTINEL_FORCE_OFFLINE=1`). No secrets are baked in.
- For live Claude mode, build with the SDK and pass the key at **runtime**:

```bash
docker build --build-arg LIVE=1 -t sentinel-api:live .
docker run --rm -p 8000:8000 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e SENTINEL_FORCE_OFFLINE=0 \
  sentinel-api:live
```

## 3. Live Claude mode

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make live-check                  # 1 call: verify key + model
make live                        # cheap sample run vs offline
make live-full                   # whole corpus (costlier)
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables live Claude mode. Never commit it. |
| `SENTINEL_FORCE_OFFLINE` | unset | `1` forces the deterministic offline agent. |
| `SENTINEL_MODEL` | `claude-opus-5` | Model id for live mode (e.g. `claude-haiku-4-5`). |
| `SENTINEL_API_KEY` | unset | If set, the HTTP API requires this bearer token. |
| `SENTINEL_LOG` | `WARNING` | `INFO`/`DEBUG` emit structured per-layer JSON logs. |
| `SENTINEL_AUDIT_LOG` | `eval/results/audit.jsonl` | Path for persisted audit events. |
| `PORT` | `8000` | API listen port. |

`.env.example` documents the secret-bearing ones. Secrets come from the
environment only — nothing is written to tracked files or baked into the image.

## Static demo (GitHub Pages)

`console/index.html` is a self-contained browser mirror of the firewall, served
at **https://adivishall.github.io/sentinel/**. It needs no backend. `index.html`
at the repo root redirects there.

## Production notes (honest scope)

This is a lab prototype of a control, not a hardened production service. Before
real use you would add: a real WSGI/ASGI server behind a reverse proxy, request
rate limiting, per-tenant keys/roles, log shipping, and integration with the
real ledger/records systems. The API ships a minimal API-key mechanism, input
size caps, JSON validation, request IDs and no-stack-trace error handling as a
sensible baseline.
