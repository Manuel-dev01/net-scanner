# net-scanner

A network-security toolkit written in Go that combines **active subnet scanning**, **host-change diffing**, and **passive traffic analytics** on a shared PostgreSQL backend, with real-time metrics in Prometheus and dashboards in Grafana.

It covers both halves of network reconnaissance:

- **Active** (`scan`, `diff`) — *outward-probing.* Sends ICMP pings and TCP probes across a subnet you specify to discover live hosts, open ports, and hostnames, then tracks how that inventory changes over time.
- **Passive** (`dashboard`) — *self-observing.* Reads this host's own live network connections (no probing, no target), enriches each with protocol/DNS/GeoIP, stores them, and visualizes where your machine is talking to in real time.

---

## Documentation

Three documents, deliberately non-overlapping:

| Document | Question it answers |
|---|---|
| **README.md** (this file) | *How do I run it?* — setup, commands, configuration |
| [ARCHITECTURE.md](ARCHITECTURE.md) | *How does it work?* — pipeline internals, metrics catalog, database schema, design decisions |
| [docs/THEORY.md](docs/THEORY.md) | *Why is it built this way?* — the networking, statistical, and systems theory behind each component, and where its claims stop being valid |

---

## Table of contents

- [Features](#features)
- [The stack at a glance](#the-stack-at-a-glance)
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [Commands](#commands)
- [Configuration](#configuration)
- [Grafana dashboard](#grafana-dashboard)
- [Project layout](#project-layout)
- [Technology stack](#technology-stack)
- [Known limitations](#known-limitations)

---

## Features

| Capability | Command | What it does |
|---|---|---|
| Active subnet scan | `scan --cidr` | Concurrent ping + TCP port probe + reverse-DNS across a CIDR; records live hosts |
| Inventory listing | `list` | Shows tracked subnets and the hosts found in the latest scan |
| Host-change diffing | `diff --cidr` | Compares the last two scans of a subnet → reports `NEW` / `REMOVED` hosts |
| Passive traffic analytics | `dashboard` | Captures this host's live connections, enriches (protocol/DNS/GeoIP), stores, and exposes Prometheus metrics |
| Anomaly detection | (within `dashboard`) | Flags traffic spikes and first-seen destinations |
| Visualization | Grafana | World map, time-series, tables, and stat panels over Prometheus + Postgres |

## The stack at a glance

```
                  ┌──────────────────────────────────────────────┐
                  │  net-scanner (Go, runs natively on the host)  │
                  │  scan │ list │ diff │ dashboard               │
                  └───────────────┬──────────────────────────────┘
                                  │ writes / reads
                                  ▼
   ┌───────────┐  scrapes :9090  ┌───────────┐   reads   ┌───────────┐
   │ Prometheus│◄────────────────│ /metrics  │           │  Grafana  │
   │  :9091    │                 │  exporter │           │  :3000    │
   │ (Docker)  │◄────────────────────────────────────────│ (Docker)  │
   └───────────┘     PromQL                               └─────┬─────┘
                                                                │ SQL
                                              ┌─────────────────▼──────┐
                                              │  PostgreSQL :5433       │
                                              │  scanner_db (Docker)    │
                                              └────────────────────────┘
```

| Service | Port | Runs as | Purpose |
|---|---|---|---|
| net-scanner | `9090` (metrics) | **native process** | Capture + scan + metrics exporter |
| PostgreSQL | `5433` | Docker (`pg-scanner`) | Stores flows, scans, hosts, anomalies |
| Prometheus | `9091` | Docker (`prometheus`) | Scrapes `/metrics`, stores time-series |
| Grafana | `3000` | Docker (`grafana`) | Dashboards |

> **Why is the scanner native and not containerized?** It must observe the host's *real* network stack — the live socket table for the poller, and the host's network position for active scanning. Inside a container it would only see the container's isolated network namespace. The stateful infrastructure (Postgres/Prometheus/Grafana) is containerized for reproducibility and clean teardown.

---

## Prerequisites

- **Go 1.25+**
- **Docker** (for Postgres, Prometheus, Grafana)
- **Windows** — the passive poller uses PowerShell's `Get-NetTCPConnection` (see [poller.go](internal/capture/poller.go))
- **MaxMind GeoLite2-City** database (`GeoLite2-City.mmdb`) for geolocation — place it in the project root ([free download](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data))

---

## Quickstart

Start the components **in this order** (each depends on the previous):

### 1. PostgreSQL

```bash
# First time — create the container
docker run -d --name pg-scanner -p 5433:5432 \
  -e POSTGRES_PASSWORD=devpw \
  -e POSTGRES_DB=scanner_db \
  postgres

# Apply the schema migrations
docker exec -i pg-scanner psql -U postgres -d scanner_db < db/migrations/000001_init_schema.up.sql
docker exec -i pg-scanner psql -U postgres -d scanner_db < db/migrations/000002_traffic_analytics.up.sql

# (subsequent runs)
docker start pg-scanner
```

### 2. The scanner (passive analytics mode)

```bash
go run cmd/scanner/main.go dashboard --mode poller --geoip GeoLite2-City.mmdb
```

This exposes metrics at `http://localhost:9090/metrics` and a health check at `http://localhost:9090/health`.

### 3. Prometheus

```bash
docker run -d --name prometheus -p 9091:9090 \
  -v "$(pwd)/grafana/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml" \
  prom/prometheus

# (subsequent runs)
docker start prometheus
```

> Prometheus runs on **9091** because the scanner's exporter already occupies **9090**.

### 4. Grafana

```bash
docker run -d --name grafana -p 3000:3000 \
  -v "$(pwd)/grafana/provisioning:/etc/grafana/provisioning" \
  grafana/grafana

# (subsequent runs)
docker start grafana
```

Open **http://localhost:3000** (default login `admin` / `admin`). Datasources and the dashboard are **auto-provisioned** — no manual setup. Find it under the **Network Scanner** folder → **Network Traffic Analytics**.

---

## Commands

The single binary ([cmd/scanner/main.go](cmd/scanner/main.go)) is a multi-tool with four subcommands.

### `dashboard` — passive traffic analytics
```bash
go run cmd/scanner/main.go dashboard --mode poller --geoip GeoLite2-City.mmdb
```
| Flag | Default | Description |
|---|---|---|
| `--mode` | `poller` | Capture mode (`poller`; `pcap` not yet implemented) |
| `--geoip` | _(none)_ | Path to `GeoLite2-City.mmdb` (geolocation disabled if omitted) |
| `--port` | `9090` | Prometheus metrics port |

Reads this host's established TCP connections every 5s, enriches and stores them, and serves metrics. **No CIDR needed** — it observes your own connections, it does not scan a network.

### `scan` — active subnet scan
```bash
go run cmd/scanner/main.go scan --cidr 192.168.1.0/24
```
Expands the CIDR to individual hosts and probes each concurrently (ping + TCP 22/80/443/8080 + reverse DNS). Persists results to `subnets` / `scans` / `hosts`.

### `list` — show discovered inventory
```bash
go run cmd/scanner/main.go list
```
Prints tracked subnets and the hosts from each subnet's most recent scan.

### `diff` — host-change detection
```bash
go run cmd/scanner/main.go diff --cidr 192.168.1.0/24
```
Compares the last two scans of the subnet and emits JSON of `NEW` / `REMOVED` hosts. Requires at least two prior scans.

---

## Configuration

Most behavior is configurable via environment variables ([internal/config/config.go](internal/config/config.go)):

| Variable | Default | Affects |
|---|---|---|
| `NS_DB_URL` | `postgres://postgres:devpw@localhost:5433/scanner_db?sslmode=disable` | Database connection¹ |
| `NS_CAPTURE_MODE` | `poller` | Capture mode |
| `NS_POLL_INTERVAL` | `5s` | How often the poller snapshots connections |
| `NS_GEOIP_DB_PATH` | _(none)_ | GeoIP database path (or use `--geoip`) |
| `NS_DNS_TTL` | `10m` | Reverse-DNS cache lifetime |
| `NS_METRICS_PORT` | `9090` | Metrics port² |
| `NS_AGG_INTERVAL` | `1m` | Materialized-view refresh interval |
| `NS_EXCLUDE_LOCAL` | `true` | Skip loopback / private / link-local destinations |
| `NS_PCAP_INTERFACE`, `NS_PCAP_BPF`, `NS_PCAP_FLUSH_INTERVAL` | — | Reserved for the unimplemented pcap mode |

**Precedence:** an explicit command-line flag beats the environment variable, which beats the built-in default. Flag defaults are seeded from the loaded config, so `NS_METRICS_PORT=9099` takes effect unless you actually pass `--port`. The same holds for `--mode` (`NS_CAPTURE_MODE`) and `--geoip` (`NS_GEOIP_DB_PATH`).

```bash
NS_METRICS_PORT=9099 go run cmd/scanner/main.go dashboard              # serves on 9099
NS_METRICS_PORT=9099 go run cmd/scanner/main.go dashboard --port 9090  # serves on 9090
```

---

## Tests

```bash
go test ./...          # all packages
go test ./... -v       # per-case detail
```

18 test functions / 148 cases across six packages, covering the deterministic logic: CIDR enumeration and address increment, port→protocol identification, the anomaly baseline, PowerShell BOM stripping, local-address classification, flow-key identity, and configuration parsing.

There are **no integration tests** — nothing exercises the database, PowerShell, the HTTP handlers, or the goroutine topology end-to-end. See [docs/THEORY.md §6.6](docs/THEORY.md#66-verification-status) for what verification does and does not establish.

---

## Grafana dashboard

The dashboard draws from **two datasources**:

- **Prometheus** → real-time aggregate stats and time-series (connection counts, rates, unique destinations/countries, anomaly counts).
- **PostgreSQL** → detailed historical breakdowns (top IPs, countries, ports, the anomaly log, and the world map).

Provisioning files under [grafana/provisioning/](grafana/provisioning/) wire both datasources and import the dashboard automatically on Grafana startup.

The dashboard exists as **two copies with identical panels and queries**, differing only in how they reference datasources:

| File | Role |
|---|---|
| [grafana/provisioning/dashboards/json/traffic-overview.json](grafana/provisioning/dashboards/json/traffic-overview.json) | **Authoritative.** This is what Grafana loads at startup. Datasource UIDs are hardcoded to match [datasources.yml](grafana/provisioning/datasources/datasources.yml). **Edit this one.** |
| [grafana/dashboards/traffic-overview.json](grafana/dashboards/traffic-overview.json) | Portable export. Uses `${DS_PROMETHEUS}` / `${DS_POSTGRES}` template variables so it can be imported into any Grafana that prompts for datasources. |

If you change one, mirror the change into the other.

> Why the split between datasources isn't arbitrary: Prometheus stores one time series per label-value combination, so per-destination detail would create unbounded cardinality. Low-cardinality velocity metrics live in Prometheus, high-cardinality detail lives in Postgres. See [docs/THEORY.md §2.11](docs/THEORY.md#211-time-series-semantics).

---

## Project layout

```
cmd/scanner/main.go          Entry point — CLI subcommand router + DB connection
internal/
  capture/                   Connection capture (poller via Get-NetTCPConnection)
  enrichment/                Protocol (port→name), DNS, and GeoIP enrichment
  storage/                   PostgreSQL writes (batch COPY) + materialized views
  metrics/                   Prometheus registry (counters/gauges) + DB-driven collector
  anomaly/                   Spike + new-destination detection
  scanner/                   Active CIDR scanner (ping + TCP probe + DNS)
  dashboard/                 Wires the passive pipeline together (the `dashboard` cmd)
  config/                    Environment-variable configuration
db/migrations/               PostgreSQL schema
grafana/                     Prometheus config, datasource + dashboard provisioning
```

## Technology stack

| Layer | Technology | Role |
|---|---|---|
| Language | **Go 1.25** | Concurrent pipeline, static binary |
| DB driver | **jackc/pgx v5** (+ pgxpool) | PostgreSQL access + connection pool, batch `COPY` inserts |
| Database | **PostgreSQL** | Flows, scans, hosts, anomalies, geo cache |
| Metrics | **prometheus/client_golang** | Instrumentation + `/metrics` endpoint |
| Metrics store | **Prometheus** | Scrapes and stores time-series |
| Dashboards | **Grafana** | Visualization (Prometheus + Postgres) |
| GeoIP | **oschwald/maxminddb-golang** + MaxMind GeoLite2 | IP → country / continent / lat-long |
| Active scan | **prometheus-community/pro-bing** | ICMP ping for host liveness |
| Concurrency | **golang.org/x/sync** | Bounded worker pools (errgroup + semaphore) |
| Logging | **log/slog** (stdlib) | Structured JSON logs |
| Infra | **Docker** | Runs Postgres, Prometheus, Grafana |

## Known limitations

- **Byte/bandwidth metrics read 0 in poller mode.** The OS connection table reports *who* and *which port*, but not byte volume. Panels for Total Bytes, Bandwidth, and byte-based breakdowns are wired and will populate once `pcap` (packet capture) mode is implemented. The world map is sized by *unique IPs* instead of bytes for this reason.
- **`pcap` mode is not implemented** — only `poller` mode works today.
- **Windows-specific capture** — the poller depends on PowerShell's `Get-NetTCPConnection`.
- **TCP only, ESTABLISHED only** — UDP (including DNS) and failed connection attempts are never captured.
- **Connections shorter than the poll interval are invisible** — a 5-second sample cannot see a 200 ms HTTP request. This biases the capture toward long-lived sessions; see [docs/THEORY.md §2.6](docs/THEORY.md#26-sampling-theory--the-most-important-limitation).
- **Anomaly detection is conservative** — spike detection needs byte data (unavailable in poller mode), and "new destination" only fires for genuinely first-seen IPs.
- **No integration tests** — unit tests cover pure logic only.
</content>
