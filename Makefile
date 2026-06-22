PYTHON ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
LINT_FILES := \
	soundcore_d3200_downloader.py \
	tests/test_crypto.py \
	tests/test_framing.py \
	tests/test_packaging.py \
	tools/d3200_decrypt_ble.py \
	tools/d3200_sdk_crypto.py \
	tools/known_plaintext.py

.PHONY: help test lint scan pair download clean

help:
	@echo "Soundcore D3200 BLE note downloader — make targets"
	@echo ""
	@echo "  test       Run the test suite"
	@echo "  lint       Run the ruff linter"
	@echo "  scan       BLE scan for the D3200"
	@echo "  pair       BLE QC/session handshake only (no download)"
	@echo "  download   Download + decrypt the most recent recording"
	@echo "  clean      Remove generated caches"

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	$(PYTHON) -m ruff check $(LINT_FILES)

scan:
	$(PYTHON) soundcore_d3200_downloader.py --scan-only

pair:
	$(PYTHON) soundcore_d3200_downloader.py --pair-only

download:
	$(PYTHON) soundcore_d3200_downloader.py --output downloads

clean:
	rm -rf __pycache__ .pytest_cache tools/__pycache__ tests/__pycache__
	find . -name "*.pyc" -delete
