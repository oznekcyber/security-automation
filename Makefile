# ==============================================================================
# Security Automation Portfolio — Makefile
#
# Usage:
#   make help            List all available targets
#   make install         Install all phase dependencies
#   make lint            Run linters across all phases
#   make test            Run all test suites
#   make security        Run security scans (bandit + safety)
#   make docker-build    Build all Docker images
#   make up              Start the full stack with docker compose
#   make down            Stop the full stack
#   make clean           Remove build artifacts and caches
# ==============================================================================

.DEFAULT_GOAL := help
.PHONY: help install lint format type-check test security \
        docker-build docker-push up down clean pre-commit-install \
        phase1-lint phase1-test phase1-docker \
        phase2-lint phase2-test phase2-docker \
        phase3-lint phase3-test phase3-docker \
        phase4-lint phase4-test phase4-docker

PHASES := phase1-normalizer phase2-splunk-pipeline phase3-soar-playbook phase4-integration-hub
PYTHON := python3
PIP    := pip3
REGISTRY ?= ghcr.io
IMAGE_PREFIX ?= $(shell git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/' | tr '[:upper:]' '[:lower:]')

# ── Help ──────────────────────────────────────────────────────────────────────

help: ## Show this help message
	@echo ""
	@echo "Security Automation Portfolio — Available Targets"
	@echo "═══════════════════════════════════════════════════"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────

install: ## Install dependencies for all phases
	@for phase in $(PHASES); do \
		echo "Installing $$phase dependencies..."; \
		if [ -f $$phase/requirements.txt ]; then \
			$(PIP) install -r $$phase/requirements.txt; \
		fi; \
	done
	$(PIP) install flake8 black isort mypy bandit safety pytest pytest-cov

pre-commit-install: ## Install pre-commit hooks into the local repository
	$(PIP) install pre-commit
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed."

# ── Linting ───────────────────────────────────────────────────────────────────

lint: ## Run flake8 and black check across all phases
	@for phase in $(PHASES); do \
		echo ""; \
		echo "── Linting $$phase ──────────────────────"; \
		if find $$phase -name "*.py" | grep -q .; then \
			flake8 $$phase --max-line-length=100 --exclude=.venv,__pycache__,dist,build; \
			black --check --diff --line-length=100 $$phase; \
		else \
			echo "  No Python files found — skipping"; \
		fi; \
	done

format: ## Auto-format all Python code with black and isort
	@for phase in $(PHASES); do \
		echo "Formatting $$phase..."; \
		if find $$phase -name "*.py" | grep -q .; then \
			black --line-length=100 $$phase; \
			isort --profile=black --line-length=100 $$phase; \
		fi; \
	done

phase1-lint: ## Lint Phase 1 only
	flake8 phase1-normalizer --max-line-length=100
	black --check --line-length=100 phase1-normalizer

phase2-lint: ## Lint Phase 2 only
	@if find phase2-splunk-pipeline -name "*.py" | grep -q .; then \
		flake8 phase2-splunk-pipeline --max-line-length=100; \
		black --check --line-length=100 phase2-splunk-pipeline; \
	fi

phase3-lint: ## Lint Phase 3 only
	@if find phase3-soar-playbook -name "*.py" | grep -q .; then \
		flake8 phase3-soar-playbook --max-line-length=100; \
		black --check --line-length=100 phase3-soar-playbook; \
	fi

phase4-lint: ## Lint Phase 4 only
	@if find phase4-integration-hub -name "*.py" | grep -q .; then \
		flake8 phase4-integration-hub --max-line-length=100; \
		black --check --line-length=100 phase4-integration-hub; \
	fi

# ── Type Checking ─────────────────────────────────────────────────────────────

type-check: ## Run mypy type checking across all phases
	@for phase in $(PHASES); do \
		echo ""; \
		echo "── Type-checking $$phase ────────────────"; \
		if find $$phase -name "*.py" | grep -q .; then \
			mypy $$phase --ignore-missing-imports --no-strict-optional \
				--exclude '.*/(\.venv|venv|dist|build)/.*'; \
		else \
			echo "  No Python files found — skipping"; \
		fi; \
	done

# ── Testing ───────────────────────────────────────────────────────────────────

test: ## Run all test suites with coverage
	@for phase in $(PHASES); do \
		echo ""; \
		echo "── Testing $$phase ──────────────────────"; \
		if find $$phase -name "test_*.py" -o -name "*_test.py" | grep -q .; then \
			cd $$phase && pytest tests/ -v \
				--cov=src \
				--cov-report=term-missing \
				--cov-fail-under=70 && cd ..; \
		else \
			echo "  No test files found — skipping"; \
		fi; \
	done

phase1-test: ## Run Phase 1 tests
	cd phase1-normalizer && pytest tests/ -v \
		--cov=src --cov-report=term-missing --cov-fail-under=70

phase2-test: ## Run Phase 2 tests
	@if find phase2-splunk-pipeline -name "test_*.py" | grep -q .; then \
		cd phase2-splunk-pipeline && pytest -v; \
	fi

phase3-test: ## Run Phase 3 tests
	@if find phase3-soar-playbook -name "test_*.py" | grep -q .; then \
		cd phase3-soar-playbook && pytest -v; \
	fi

phase4-test: ## Run Phase 4 tests
	@if find phase4-integration-hub -name "test_*.py" | grep -q .; then \
		cd phase4-integration-hub && pytest -v; \
	fi

# ── Security Scanning ─────────────────────────────────────────────────────────

security: ## Run bandit (SAST) and safety (CVE audit) across all phases
	@for phase in $(PHASES); do \
		echo ""; \
		echo "── Security scan: $$phase ───────────────"; \
		if find $$phase -name "*.py" | grep -q .; then \
			echo "  Running bandit..."; \
			bandit -r $$phase -ll -ii --exclude $$phase/.venv; \
		fi; \
		if [ -f $$phase/requirements.txt ]; then \
			echo "  Running safety..."; \
			safety check --file $$phase/requirements.txt || true; \
		fi; \
	done

secrets-scan: ## Scan the entire repository for hardcoded secrets
	@$(PIP) install detect-secrets -q
	detect-secrets scan \
		--exclude-files '\.env\.example$$' \
		--exclude-files '\.git/.*' \
		> /tmp/secrets-baseline.json
	@python3 -c " \
	import json, sys; \
	data = json.load(open('/tmp/secrets-baseline.json')); \
	results = data.get('results', {}); \
	print(f'Scanned repository — {len(results)} file(s) with potential findings'); \
	[print(f'  {k}: {len(v)} finding(s)') for k,v in results.items()]; \
	sys.exit(1) if results else print('Clean — no secrets detected')"

# ── Docker ────────────────────────────────────────────────────────────────────

docker-build: ## Build Docker images for all phases that have a Dockerfile
	@for phase in $(PHASES); do \
		echo ""; \
		echo "── Building $$phase ─────────────────────"; \
		if [ -f $$phase/Dockerfile ]; then \
			docker build -t $$phase:dev $$phase/; \
		else \
			echo "  No Dockerfile found — skipping"; \
		fi; \
	done

phase1-docker: ## Build Phase 1 Docker image
	docker build -t phase1-normalizer:dev phase1-normalizer/

phase2-docker: ## Build Phase 2 Docker image
	@[ -f phase2-splunk-pipeline/Dockerfile ] && \
		docker build -t phase2-splunk-pipeline:dev phase2-splunk-pipeline/ || \
		echo "No Dockerfile for phase2"

phase3-docker: ## Build Phase 3 Docker image
	@[ -f phase3-soar-playbook/Dockerfile ] && \
		docker build -t phase3-soar-playbook:dev phase3-soar-playbook/ || \
		echo "No Dockerfile for phase3"

phase4-docker: ## Build Phase 4 Docker image
	@[ -f phase4-integration-hub/Dockerfile ] && \
		docker build -t phase4-integration-hub:dev phase4-integration-hub/ || \
		echo "No Dockerfile for phase4"

up: ## Start the full security automation stack with docker compose
	docker compose -f docker-compose.full-stack.yml up -d
	@echo ""
	@echo "Full stack is running:"
	@echo "  Phase 4 API Hub  → http://localhost:8000"
	@echo "  Phase 4 Docs     → http://localhost:8000/docs"
	@echo ""
	@echo "Run 'make logs' to tail logs, 'make down' to stop."

down: ## Stop and remove all containers
	docker compose -f docker-compose.full-stack.yml down --remove-orphans

logs: ## Tail logs from the full stack
	docker compose -f docker-compose.full-stack.yml logs -f

ps: ## Show running containers in the full stack
	docker compose -f docker-compose.full-stack.yml ps

# ── CI shortcut — run everything that CI runs ─────────────────────────────────

ci: lint type-check security test docker-build ## Run the complete CI pipeline locally
	@echo ""
	@echo "All CI checks passed locally."

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean: ## Remove Python build artifacts, caches, and coverage reports
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "coverage.xml" -delete 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	@echo "Clean complete."
