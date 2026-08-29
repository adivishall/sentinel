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

charts:           ## render the three submission charts
	python3 eval/charts.py

all: corpus eval ablation baselines charts   ## full pipeline

offline:          ## force offline mode end-to-end
	SENTINEL_FORCE_OFFLINE=1 $(MAKE) all

demo:             ## open the standalone demo console
	python3 -c "import webbrowser,os;webbrowser.open('file://'+os.path.abspath('console/index.html'))"

clean:
	rm -f eval/results/*.png eval/results/*.json red/attacks/corpus.json
