# open-easm

Self-hosted passive External Attack Surface Management (EASM) monitoring platform.

## Quick Start

1. Copy `.env.example` to `.env` and set database credentials
2. Copy `config.yaml.example` to `config.yaml` and configure your targets
3. Run `docker compose up`

The API will be available at http://localhost:8000 with OpenAPI docs at http://localhost:8000/docs.

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Lint
uv run ruff check src/

# Type check
uv run mypy src/
```

## Architecture

- **API**: FastAPI with async routes
- **Data**: PostgreSQL 18 with asyncpg
- **Runners**: certstream (websocket), subfinder, asnmap
- **Scheduler**: APScheduler.AsyncIOScheduler
- **Config**: YAML with Pydantic validation
