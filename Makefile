PYTHON ?= python3
COMPOSE = docker compose -f network-anomaly-detection/lab/integration/compose.yml

.PHONY: test lab-up lab-stop demo
test:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m pytest network-anomaly-detection/tests -q -p no:cacheprovider

lab-up:
	BUILDX_BUILDER=default $(COMPOSE) --profile serving up -d --build

lab-stop:
	$(COMPOSE) --profile serving down

demo:
	$(PYTHON) network-anomaly-detection/tools/demo_integration.py
