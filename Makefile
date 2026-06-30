UV_CACHE_DIR ?= /tmp/uv-cache
PYTHON ?= python
UV ?= uv

.PHONY: test test-uv compile compile-uv check check-uv clean help smoke-browser

test:
	$(PYTHON) -m unittest discover -s tests

test-uv:
	UV_CACHE_DIR=$(UV_CACHE_DIR) $(UV) run python -m unittest discover -s tests

compile:
	$(PYTHON) -m compileall tech_scan tests

compile-uv:
	UV_CACHE_DIR=$(UV_CACHE_DIR) $(UV) run python -m compileall tech_scan tests

check: test compile

check-uv: test-uv compile-uv

clean:
	rm -rf \
		build \
		dist \
		.pytest_cache \
		.mypy_cache \
		.ruff_cache \
		tech_scan.egg-info \
		tech_scan/__pycache__ \
		tech_scan/fetchers/__pycache__ \
		tech_scan/fetchers/data/__pycache__ \
		tech_scan/fetchers/data/adblock/__pycache__ \
		tech_scan/fetchers/data/ubol/__pycache__ \
		tech_scan/providers/__pycache__ \
		tech_scan/providers/data/__pycache__ \
		tech_scan/providers/data/wappalyzergo/__pycache__ \
		tests/__pycache__

help:
	UV_CACHE_DIR=$(UV_CACHE_DIR) $(UV) run -m tech_scan --help

smoke-browser:
	UV_CACHE_DIR=$(UV_CACHE_DIR) CHROMIUM_PATH=/usr/bin/chromium \
		$(UV) run -m tech_scan --mode browser --output jsonl --refresh
