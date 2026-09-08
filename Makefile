ifeq ($(OS),Windows_NT)
    VENV_BIN := .venv/Scripts
    PYTHON   := python
else
    VENV_BIN := .venv/bin
    PYTHON   := python3
endif

VENV_PYTHON := $(VENV_BIN)/python
PIP         := $(VENV_BIN)/pip

IMAGE   := ccm
VERSION := latest

.PHONY: setup run clean help release

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "  setup    create venv, install dependencies"
	@echo "  run      start the Flask development server on port 5050 (runs setup if needed)"
	@echo "  clean    remove the venv, database, and Python caches"
	@echo "  release  build a Docker image and export it as a portable, compressed tarball"
	@echo "           (override the tag with: make release VERSION=1.0.0)"

setup: .venv/pyvenv.cfg

.venv/pyvenv.cfg: requirements.txt
	$(PYTHON) -m venv .venv
	$(PIP) install --upgrade pip --quiet
	$(PIP) install -r requirements.txt --quiet
	@echo "Setup complete. Run 'make run' to start the server."

run: .venv/pyvenv.cfg
	$(VENV_PYTHON) src/app.py

clean:
	rm -rf .venv
	@echo "Virtual environment removed."
	rm -rf src/instance
	@echo "instance (database) removed."
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Python caches removed."

release:
	docker build -f docker/Dockerfile -t $(IMAGE):$(VERSION) .
	@echo "Built $(IMAGE):$(VERSION)"
	docker save $(IMAGE):$(VERSION) | gzip > $(IMAGE)-$(VERSION).tar.gz
	@echo "Exported $(IMAGE)-$(VERSION).tar.gz — copy this file to the offline machine and run:"
	@echo "  docker load -i $(IMAGE)-$(VERSION).tar.gz"
