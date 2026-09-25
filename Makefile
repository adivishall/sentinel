.PHONY: help install test lint typecheck cov eval bench docs demo api ui snapshot data analyze attack audit-verify audit-checkpoint replay docker-build docker-run clean live-check

PY ?= python3
DB ?= data/sentinel.db
export SENTINEL_FORCE_OFFLINE ?= 1

help:             ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:          ## install dev tooling (the core has no runtime deps)
	$(PY) -m pip install -r requirements-dev.txt

test:             ## run the test suite (offline, no key)
	$(PY) -m pytest tests/ -q

cov:              ## tests with coverage gate
	$(PY) -m pytest tests/ -q --cov=sentinel --cov-report=term --cov-fail-under=80

lint:             ## ruff + black --check + mypy
	$(PY) -m ruff check .
	$(PY) -m black --check .
	$(PY) -m mypy

data:             ## generate the deterministic synthetic dataset into $(DB)
	$(PY) -m sentinel --db $(DB) data generate --seed 42 --customers 500 --merchants 60 --transactions 20000

analyze:          ## run the engine over a slice of the dataset (populates the console)
	$(PY) -m sentinel --db $(DB) analyze

demo: attack      ## the flagship demo

attack:           ## "Attack the financial AI" -- the flagship demonstration
	$(PY) -m sentinel --db :memory: security attack --scenario document_injection

attack-compare:   ## the same attack WITHOUT (simulated agent, no controls) and WITH Sentinel, side by side
	$(PY) -m sentinel --db :memory: security attack --scenario document_injection --compare

api:              ## API + console on :8000 (in-memory demo dataset, analysed on start)
	$(PY) -m sentinel --db :memory: serve --host 0.0.0.0 --port 8000 --analyze

ui: api           ## alias: the console is served by the API

snapshot:         ## static console snapshot (GitHub Pages) computed by the real engine
	$(PY) -m sentinel --db :memory: ui snapshot --out ui/snapshot.json

eval:             ## full evaluation: security · held-out · surfaces · KYB · baselines · ablation · financial · integrity · temporal · performance · models · charts
	$(PY) -m sentinel eval run --suite full

eval-quick:       ## the CI subset
	$(PY) -m sentinel eval run --suite security
	$(PY) -m sentinel eval run --suite heldout
	$(PY) -m sentinel eval run --suite surfaces
	$(PY) -m sentinel eval run --suite kyb
	$(PY) -m sentinel eval run --suite ablation
	$(PY) -m sentinel eval run --suite integrity
	$(PY) -m sentinel eval run --suite temporal

bench:            ## component + end-to-end latency benchmark
	$(PY) -m sentinel bench

docs:             ## re-render docs/EVALUATION.md, docs/PERFORMANCE.md and the README / résumé numbers from results/
	$(PY) scripts/render_docs.py

audit-verify:     ## verify the tamper-evident audit chain in $(DB)
	$(PY) -m sentinel --db $(DB) audit verify

audit-checkpoint: ## export a (signed, if SENTINEL_AUDIT_KEY is set) checkpoint of the chain head
	$(PY) -m sentinel --db $(DB) audit checkpoint --out audit-checkpoint.json

live-check:       ## one Claude call to verify the key + model (needs ANTHROPIC_API_KEY)
	SENTINEL_FORCE_OFFLINE=0 $(PY) scripts/live_check.py

docker-build:     ## build the container image
	docker build -t sentinel .

docker-run:       ## run the API + console container on :8000
	docker run --rm -p 8000:8000 sentinel

clean:
	rm -rf data/*.db results/*.png .coverage .pytest_cache .mypy_cache .ruff_cache
