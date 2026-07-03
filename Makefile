.PHONY: train-classifier download-ner up down logs test redteam agent-scan-safe agent-scan-risky clean

train-classifier:
	cd app/train && python3 train_classifier.py

download-ner: 
	python3 -m spacy download en_core_web_sm

up: train-classifier 
	docker compose up --build

down: 
	docker compose down -v

logs: 
	docker compose logs -f

test: train-classifier 
	python3 -m pytest tests/ -v

redteam: 
	python3 redteam/fuzz.py

agent-scan-safe: 
	cd agent_scanner && python3 cli.py examples/safe_agent.json

agent-scan-risky: 
	cd agent_scanner && python3 cli.py examples/risky_agent.json

fleet-benchmark: 
	cd agent_scanner && python3 benchmark.py

clean: 
	rm -rf app/models .pytest_cache tests/__pycache__ agent_scanner/fleet/after_fleet.json
