.PHONY: help install install-dev up down logs clean test lint type-check format

help:
	@echo "DDF Development Commands"
	@echo "======================="
	@echo "make install       - Install production dependencies"
	@echo "make install-dev   - Install development dependencies"
	@echo "make up            - Start Docker services (PostgreSQL, OpenFGA)"
	@echo "make down          - Stop Docker services"
	@echo "make logs          - View Docker service logs"
	@echo "make clean         - Clean up temporary files and caches"
	@echo "make test          - Run test suite"
	@echo "make test-coverage - Run tests with coverage report"
	@echo "make lint          - Run linting (ruff)"
	@echo "make type-check    - Run type checking (mypy)"
	@echo "make format        - Format code with ruff"
	@echo "make migrate       - Run database migrations"
	@echo "make serve         - Run development server"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,openfga]"

up:
	docker-compose up -d
	@echo "Waiting for services to be healthy..."
	sleep 5

down:
	docker-compose down

logs:
	docker-compose logs -f

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + || true
	find . -type d -name ".coverage" -exec rm -rf {} + || true
	find . -type d -name "htmlcov" -exec rm -rf {} + || true

test:
	pytest tests/ -v

test-coverage:
	pytest tests/ -v --cov=src/ddf --cov-report=html --cov-report=term-missing
	@echo "Coverage report generated in htmlcov/index.html"

lint:
	ruff check src tests

format:
	ruff format src tests
	ruff check --fix src tests

type-check:
	mypy src/ddf

migrate:
	alembic upgrade head

serve:
	uvicorn ddf.main:create_app --factory --reload --host 0.0.0.0 --port 8000

.PHONY: psql

psql:
	docker-compose exec postgres psql -U ddf -d ddf_db
