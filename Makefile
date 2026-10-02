.PHONY: help install test cov lint data analyze demo attack attack-compare api ui screenshots snapshot eval eval-quick bench docs audit-verify audit-checkpoint live-check docker-build docker-run clean

PY ?= python3
DB ?= data/sentinel.db
export SENTINEL_FORCE_OFFLINE ?= 1

help:             ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:          ## install dev tooling and the `sentinel` command (one runtime dependency: cryptography)
	$(PY) -m pip install -r requirements-dev.txt
	$(PY) -m pip install -e .

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

demo: attack-compare  ## the flagship demo (alias of attack-compare)

attack:           ## the flagship attack, WITH Sentinel only (stage by stage)
	$(PY) -m sentinel --db :memory: security attack --scenario document_injection

attack-compare:   ## the same attack WITHOUT (simulated agent, no controls) and WITH Sentinel, side by side
	$(PY) -m sentinel --db :memory: security attack --scenario document_injection --compare

api:              ## API + console on 127.0.0.1:8000 (in-memory demo dataset, analysed on start)
	$(PY) -m sentinel --db :memory: serve --host 127.0.0.1 --port 8000 --analyze

ui: api           ## alias: the console is served by the API

screenshots:      ## capture docs/img/*.png from a running console (make api) with local headless Chrome
	scripts/screenshots.sh

snapshot:         ## static console snapshot (GitHub Pages) computed by the real engine
	$(PY) -m sentinel --db :memory: ui snapshot --out ui/snapshot.json

eval:             ## full evaluation: security · held-out · surfaces · KYB · baselines · ablation · financial · integrity · temporal · claims · performance · models · charts
	$(PY) -m sentinel eval run --suite full

eval-quick:       ## the CI subset
	$(PY) -m sentinel eval run --suite security
	$(PY) -m sentinel eval run --suite heldout
	$(PY) -m sentinel eval run --suite surfaces
	$(PY) -m sentinel eval run --suite kyb
	$(PY) -m sentinel eval run --suite ablation
	$(PY) -m sentinel eval run --suite integrity
	$(PY) -m sentinel eval run --suite temporal
	$(PY) -m sentinel eval run --suite claims

bench:            ## component + end-to-end latency benchmark
	$(PY) -m sentinel bench

docs:             ## re-render every generated doc section and number from results/ and the code (README, docs/*)
	$(PY) scripts/render_docs.py

audit-verify:     ## verify the tamper-evident audit chain in $(DB)
	$(PY) -m sentinel --db $(DB) audit verify

audit-checkpoint: ## export a (signed, if SENTINEL_AUDIT_KEY is set) checkpoint of the chain head
	$(PY) -m sentinel --db $(DB) audit checkpoint --out audit-checkpoint.json

live-check:       ## one Claude call to verify the key + model (needs ANTHROPIC_API_KEY)
	SENTINEL_FORCE_OFFLINE=0 $(PY) scripts/live_check.py

docker-build:     ## build the container image
	docker build -t sentinel .

docker-run:       ## run the demo container, published on 127.0.0.1:8000 only (an insecure demo: no API key)
	docker run --rm -p 127.0.0.1:8000:8000 -e SENTINEL_INSECURE_DEMO=1 -e SENTINEL_DEMO_DATA=1 sentinel

clean:
	rm -rf data/*.db results/*.png .coverage .pytest_cache .mypy_cache .ruff_cache
