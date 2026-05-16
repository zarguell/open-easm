# Open EASM

Self-hosted passive External Attack Surface Management platform. Continuously discovers and maps your external attack surface through passive reconnaissance — ASN enumeration, certificate transparency monitoring, DNS resolution, and subdomain discovery — with automated pivot chaining that expands from a single ASN into a full graph of IPs, hostnames, domains, and certificates.

![Dashboard](docs/screenshots/dashboard.png)

## Features

- **Automated Discovery Cascade** — Start from an ASN, IP range, or domain. Open EASM chains pivots automatically: ASN → IP ranges → reverse DNS → hostnames → domain extraction → certificate search → new domains → repeat up to configurable depth.
- **Real-time Certificate Transparency** — Watches the Certificate Transparency log feed via certstream and matches against your configured domains and keywords in real time.
- **D3-force Graph Explorer** — Interactive force-directed graph visualization of your entire attack surface, with entity-type coloring, zoom/pan, and depth controls.
- **Inventory with Filters** — Browse all discovered entities with type-based filtering (ASN, IP Range, IP, Hostname, Domain, Certificate, Org), full-text search, and cursor-based pagination.
- **Run Tracking** — Monitor scheduled and on-demand runner executions with status, timing, and auto-refresh.
- **Pivot Queue** — See the pending pivot jobs that will expand your surface further, with entity value, pivot type, and depth tracking.
- **Single Binary Deploy** — Multi-stage Dockerfile builds the React SPA and Python backend into one container. No separate frontend hosting needed.
- **Configurable Schedules** — Cron-based scheduling for each runner per target, with on-demand trigger from the UI.

## Screenshots

| Dashboard | Inventory |
|-----------|-----------|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Inventory](docs/screenshots/inventory.png) |

| Graph Explorer | Runs |
|---------------|------|
| ![Graph Explorer](docs/screenshots/graph-explorer.png) | ![Runs](docs/screenshots/runs.png) |

| Targets & Pivots |
|------------------|
| ![Targets](docs/screenshots/targets.png) |

## Quick Start

### Requirements

- Docker & Docker Compose
- (Optional) [PDCP API key](https://cloud.projectdiscovery.io) for asnmap — free tier available

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/zarguell/open-easm.git
cd open-easm

# 2. Configure environment
cp .env.example .env
# Edit .env if you want to change the default DB credentials

# 3. Configure your targets
cp config.yaml.example config.yaml
# Edit config.yaml with your organization's ASNs, domains, and keywords

# 4. Start
docker compose up -d

# 5. Open the UI
open http://localhost:8000/ui
```

The API is available at `http://localhost:8000/api` with interactive docs at `http://localhost:8000/docs`.

### Configuration

Targets are defined in `config.yaml`. Each target specifies what to discover and how:

```yaml
targets:
  - id: my-org
    name: My Organization
    type: organization
    enabled: true
    match_rules:
      domains:
        - example.com
      keywords:
        - Example Corp
      asns:
        - AS15169
    runners:
      certstream:
        enabled: true
        mode: realtime          # Watch CT logs in real time
      subfinder:
        enabled: true
        schedule: "0 */6 * * *" # Every 6 hours
      asnmap:
        enabled: true
        schedule: "0 2 * * *"   # Daily at 2am
    pivot:
      enabled: true
      max_depth: 4              # How many hops from the seed entity
      max_concurrent: 3
      allowed_pivots:
        - from: ip_range
          to: ip
          via: reverse_dns
        - from: hostname
          to: ip
          via: dns_resolve
        - from: hostname
          to: domain
          via: domain_extract
        - from: domain
          to: certificate
          via: crtsh_search
```

See `config.yaml.example` for the full reference.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    UI (React)                    │
│  Dashboard · Inventory · Graph · Runs · Targets  │
└──────────────────────┬──────────────────────────┘
                       │ /api/*
┌──────────────────────┴──────────────────────────┐
│              FastAPI (Python 3.14)               │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │ Scheduler │ │  Runners  │ │  Pivot Workers   │ │
│  │(APScheduler)│ │          │ │  (async queue)   │ │
│  └────┬─────┘ └────┬─────┘ └───────┬──────────┘ │
│       │            │               │             │
│  ┌────┴────────────┴───────────────┴──────────┐  │
│  │              Store (asyncpg)                │  │
│  └───────────────────┬────────────────────────┘  │
└──────────────────────┼──────────────────────────┘
                       │
              ┌────────┴────────┐
              │   PostgreSQL    │
              └─────────────────┘
```

### Discovery Pipeline

| Runner | Source | What it finds |
|--------|--------|---------------|
| **asnmap** | ASN | IP ranges belonging to the ASN |
| **certstream** | CT logs | Domains and certificates matching your keywords |
| **subfinder** | Domain | Subdomains via passive DNS sources |
| **crtsh_search** | Domain | Certificates from crt.sh |
| **reverse_dns** | IP range | Hostnames via reverse DNS |
| **dns_resolve** | Hostname | IPs via forward DNS |
| **domain_extract** | Hostname | Registered domain from FQDN |

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14, FastAPI, asyncpg, APScheduler |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS 4 |
| Graph | D3-force |
| Database | PostgreSQL 18 |
| Discovery | subfinder, asnmap, certstream, crt.sh |
| Deploy | Docker multi-stage build |

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

# Run the backend locally
uv run python -m easm.main

# Run the frontend dev server (proxies API to :8000)
cd ui && npm install && npm run dev
```

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/targets` | List configured targets with runner status |
| `GET /api/entities` | Paginated entity inventory with type filters |
| `GET /api/entities/{id}` | Single entity with relationships |
| `GET /api/graph/{target_id}` | Full graph (nodes + edges) for a target |
| `GET /api/runs` | List runner executions |
| `POST /api/runs/trigger` | Trigger a runner on demand |
| `GET /api/pivot-queue` | Pending pivot jobs |
| `GET /api/healthz` | Health check |

Interactive docs available at `http://localhost:8000/docs`.

## License

MIT
