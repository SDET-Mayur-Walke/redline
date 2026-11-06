.PHONY: setup data index search serve sink demo demo-stub test test-ollama lint fmt check gate ablation

setup:            ## create the venv and install everything for development
	uv venv --python 3.12
	uv pip install -e ".[dev,ui]"

data:             ## regenerate the synthetic store and reviews (deterministic)
	.venv/bin/python -m redline.store.generate
	.venv/bin/python -m redline.kb.generate_reviews

index:            ## build the Qdrant index from data/kb (needs Ollama)
	.venv/bin/python -m redline.kb.ingest

search:           ## make search q="how long do UPI refunds take"
	.venv/bin/python -m redline.kb.search "$(q)"

serve:            ## the support agent API on 127.0.0.1:8000 (needs Ollama; rebuilds the index at startup)
	.venv/bin/uvicorn redline.api:app --host 127.0.0.1 --port 8000

sink:             ## the exfil sink, an attacker's request logger, on 127.0.0.1:8765
	.venv/bin/python -m redline.sink

DEMO = .venv/bin/streamlit run src/redline/demo/app.py --server.address 127.0.0.1 --server.port 8501 \
	--browser.gatherUsageStats false

demo:             ## the Streamlit demo on 127.0.0.1:8501, vulnerable vs hardened (needs Ollama; run make sink too)
	REDLINE_DEMO_MODEL=ollama $(DEMO)

demo-stub:        ## the demo offline: the CI gate's stub model and configs, no Ollama
	REDLINE_DEMO_MODEL=stub $(DEMO)

test:
	.venv/bin/pytest -q

test-ollama:      ## tests that need a running Ollama
	.venv/bin/pytest -q -m ollama

lint:
	.venv/bin/ruff check src tests scripts

fmt:
	.venv/bin/ruff check --fix src tests scripts
	.venv/bin/ruff format src tests scripts

check: lint test  ## what CI runs

gate:             ## CI gate: stub-model probes vs gate/baseline.json (offline, no Ollama)
	.venv/bin/python -m redline.gate

ablation:         ## step 11, the full measurement: hours, needs Ollama, resumable; logs to runs/ablation/run.log
	.venv/bin/python -m redline.ablation
