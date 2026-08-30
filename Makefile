.PHONY: setup corpus eval charts all demo offline clean

setup:            ## install deps (only needed for live mode + charts)
	pip install -r requirements.txt

corpus:           ## build the attack + control corpus
	python3 red/corpus.py

eval:             ## run all cases: unguarded vs firewall -> results/
	python3 eval/harness.py

ablation:         ## real layer ablation -> results/ablation.json
	python3 eval/ablation.py

baselines:        ## beat-the-obvious-defence comparison -> results/baselines.json
	python3 eval/baselines.py

kyb:              ## KYB second-surface benchmark -> results/kyb.json
	SENTINEL_FORCE_OFFLINE=1 python3 eval/kyb_harness.py

charts:           ## render the three submission charts
	python3 eval/charts.py

all: corpus eval ablation baselines kyb charts   ## full pipeline

offline:          ## force offline mode end-to-end
	SENTINEL_FORCE_OFFLINE=1 $(MAKE) all

demo:             ## open the standalone demo console
	python3 -c "import webbrowser,os;webbrowser.open('file://'+os.path.abspath('console/index.html'))"

test:             ## run the pytest suite (offline)
	SENTINEL_FORCE_OFFLINE=1 python3 -m pytest tests/ -q

lint:             ## ruff + black --check + mypy
	python3 -m ruff check .
	python3 -m black --check .
	python3 -m mypy

bench:            ## firewall latency / throughput benchmark
	SENTINEL_FORCE_OFFLINE=1 python3 eval/bench.py

live-check:       ## preflight: one Claude call to verify key + model
	python3 scripts/live_check.py

live:             ## live sample run (cheap) vs offline
	python3 scripts/live_run.py

live-full:        ## live run over the whole corpus (costlier)
	python3 scripts/live_run.py --full

clean:
	rm -f eval/results/*.png eval/results/*.json red/attacks/corpus.json
