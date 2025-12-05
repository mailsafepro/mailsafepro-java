# Makefile for MailSafePro API
# Simplifies common development tasks

.PHONY: help install test lint format security docker-build docker-run clean

# Default target
.DEFAULT_GOAL := help

# Colors for output
YELLOW := \033[1;33m
GREEN := \033[1;32m
RED := \033[1;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)MailSafePro API - Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

# =============================================================================
# Installation & Setup
# =============================================================================

install: ## Install all dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	pip install --upgrade pip setuptools wheel
	pip install -r requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev: install ## Install dev dependencies and pre-commit hooks
	@echo "$(GREEN)Installing dev tools...$(NC)"
	pip install pre-commit
	pre-commit install
	@echo "$(GREEN)✓ Dev environment ready$(NC)"

# =============================================================================
# Code Quality
# =============================================================================

lint: ## Run all linters
	@echo "$(GREEN)Running linters...$(NC)"
	@echo "$(YELLOW)→ Black$(NC)"
	black --check app/ tests/
	@echo "$(YELLOW)→ isort$(NC)"
	isort --check-only app/ tests/
	@echo "$(YELLOW)→ Flake8$(NC)"
	flake8 app/ tests/ --max-line-length=120
	@echo "$(YELLOW)→ mypy$(NC)"
	mypy app/ --ignore-missing-imports || true
	@echo "$(GREEN)✓ Linting complete$(NC)"

format: ## Auto-format code with black and isort
	@echo "$(GREEN)Formatting code...$(NC)"
	black app/ tests/
	isort app/ tests/
	@echo "$(GREEN)✓ Code formatted$(NC)"

security: ## Run security checks
	@echo "$(GREEN)Running security checks...$(NC)"
	@echo "$(YELLOW)→ Bandit$(NC)"
	bandit -r app/ -ll
	@echo "$(YELLOW)→ Safety$(NC)"
	safety check
	@echo "$(GREEN)✓ Security checks complete$(NC)"

# =============================================================================
# Testing
# =============================================================================

test: ## Run all tests
	@echo "$(GREEN)Running tests...$(NC)"
	pytest tests/ -v
	@echo "$(GREEN)✓ Tests passed$(NC)"

test-cov: ## Run tests with coverage
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

test-watch: ## Run tests in watch mode
	@echo "$(GREEN)Running tests in watch mode...$(NC)"
	pytest-watch tests/ -v

# =============================================================================
# Docker
# =============================================================================

docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	docker build -t mailsafepro-api:local .
	@echo "$(GREEN)✓ Image built: mailsafepro-api:local$(NC)"

docker-run: docker-build ## Run Docker container locally
	@echo "$(GREEN)Starting Docker container...$(NC)"
	docker run -p 8000:8000 \
		--env-file .env \
		--name mailsafepro-api \
		mailsafepro-api:local

docker-compose-up: ## Start all services with docker-compose
	@echo "$(GREEN)Starting services...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Services running$(NC)"
	@echo "$(YELLOW)API: http://localhost:8000$(NC)"
	@echo "$(YELLOW)Docs: http://localhost:8000/docs$(NC)"

docker-compose-down: ## Stop all services
	@echo "$(GREEN)Stopping services...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Services stopped$(NC)"

docker-compose-logs: ## Show docker-compose logs
	docker-compose logs -f

# =============================================================================
# Development Server
# =============================================================================

dev: ## Run development server
	@echo "$(GREEN)Starting development server...$(NC)"
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

debug: ## Run development server with debug logging
	@echo "$(GREEN)Starting debug server...$(NC)"
	LOG_LEVEL=DEBUG uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# =============================================================================
# Database & Cache
# =============================================================================

redis-cli: ## Connect to Redis CLI
	docker exec -it toni-redis-1 redis-cli

redis-flush: ## Flush Redis cache
	docker exec -it toni-redis-1 redis-cli FLUSHALL
	@echo "$(GREEN)✓ Redis cache flushed$(NC)"

# =============================================================================
# CI/CD Locally
# =============================================================================

ci-local: lint security test ## Run full CI pipeline locally
	@echo "$(GREEN)✓ All CI checks passed$(NC)"

pre-commit-all: ## Run pre-commit on all files
	@echo "$(GREEN)Running pre-commit hooks...$(NC)"
	pre-commit run --all-files
	@echo "$(GREEN)✓ Pre-commit checks complete$(NC)"

# =============================================================================
# Utilities
# =============================================================================

clean: ## Clean up generated files
	@echo "$(GREEN)Cleaning up...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .mypy_cache
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

requirements: ## Update requirements.txt from current environment
	@echo "$(GREEN)Generating requirements.txt...$(NC)"
	pip freeze > requirements.txt
	@echo "$(GREEN)✓ requirements.txt updated$(NC)"

check-env: ## Check if .env file exists
	@if [ ! -f .env ]; then \
		echo "$(RED)✗ .env file not found!$(NC)"; \
		echo "$(YELLOW)→ Copy .env.example to .env and configure it$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ .env file exists$(NC)"

# =============================================================================
# Kubernetes
# =============================================================================

k8s-apply: ## Apply Kubernetes manifests
	@echo "$(GREEN)Applying Kubernetes manifests...$(NC)"
	kubectl apply -f k8s/
	@echo "$(GREEN)✓ Manifests applied$(NC)"

k8s-status: ## Check Kubernetes deployment status
	@echo "$(GREEN)Checking deployment status...$(NC)"
	kubectl get pods -n mailsafepro
	kubectl get deployments -n mailsafepro
	kubectl get services -n mailsafepro

k8s-logs: ## Show Kubernetes pod logs
	kubectl logs -f -n mailsafepro -l app=mailsafepro-api

k8s-delete: ## Delete Kubernetes resources
	kubectl delete -f k8s/

# =============================================================================
# Release
# =============================================================================

version: ## Show current version
	@grep "version" pyproject.toml | head -1

tag: ## Create a new git tag (usage: make tag VERSION=v2.2.0)
ifndef VERSION
	@echo "$(RED)✗ VERSION not specified$(NC)"
	@echo "$(YELLOW)Usage: make tag VERSION=v2.2.0$(NC)"
	@exit 1
endif
	@echo "$(GREEN)Creating tag $(VERSION)...$(NC)"
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@echo "$(GREEN)✓ Tag $(VERSION) created and pushed$(NC)"
