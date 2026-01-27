.PHONY: format lint check test clean install-hooks help

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

format:  ## Format code with black and isort
	@echo "Running black..."
	@uv run black zkhydra/
	@echo "Running isort..."
	@uv run isort zkhydra/ --profile black
	@echo "✅ Formatting complete!"

lint:  ## Run ruff linter and fix issues
	@echo "Running ruff..."
	@uv run ruff check zkhydra/ --fix
	@echo "✅ Linting complete!"

check:  ## Check code without making changes
	@echo "Checking with ruff..."
	@uv run ruff check zkhydra/
	@echo "Checking format with black..."
	@uv run black zkhydra/ --check
	@echo "Checking imports with isort..."
	@uv run isort zkhydra/ --check-only --profile black
	@echo "✅ All checks passed!"

all: format lint  ## Format and lint code (recommended)
	@echo "✅ Code is formatted and linted!"

install-hooks:  ## Install pre-commit git hooks
	@echo "Installing pre-commit hooks..."
	@uv pip install pre-commit
	@pre-commit install
	@echo "✅ Pre-commit hooks installed! Checks will run automatically on git commit."

clean:  ## Remove generated files and caches
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@echo "✅ Cleaned up!"
