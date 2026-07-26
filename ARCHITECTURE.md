# Architecture

This document explains how net-scanner works internally — the data pipeline, every metric, the database schema, and the design decisions behind them. It's the reference for understanding and defending the build.

- [Mental model: active vs. passive](#mental-model-active-vs-passive)
- [Entry point and process model](#entry-point-and-process-model)
- [The passive pipeline (dashboard mode)](#the-passive-pipeline-dashboard-mode)
- [The active scanner (scan / diff)](#the-active-scanner-scan--diff)
- [Metrics catalog](#metrics-catalog)
- [Database schema](#database-schema)
- [Anomaly detection](#anomaly-detection)
- [Why three Docker containers](#why-three-docker-containers)
- [Design decisions](#design-decisions)
- [Known limitations](#known-limitations)

---

## Mental model: active vs. passive

The toolkit covers the two complementary halves of network reconnaissance. Understanding this split explains every design choice.

| | **Active** (`scan`, `diff`) | **Passive** (`dashboard`) |
|---|---|---|
| Question answered | "What exists on my network?" | "What is my machine talking to?" |
| Direction | Outbound — *we reach out and probe* | Inward observation — *we watch ourselves* |
| Generates traffic? | **Yes** — pings and TCP connects | **No** — only reads the OS socket table |
| Needs a target? | **Yes** — a `--cidr` you specify | **No** — scope is your own connections |
| Data source | Network responses to our probes | `Get-NetTCPConnection` (live sockets) |
| Analogy | "Knock on every door on the street" | "Look at the calls I'm currently on" |

> ⚠️ **The word "active" is overloaded** — be precise:
> - **"Active scanning"** = active because *we send probe traffic*. (needs a CIDR)
> - **"Active connections"** (a dashboard stat) = active meaning *currently-established sockets*. This is **passive** monitoring. (no CIDR)
>
> Same word, opposite meaning.

---

## Entry point and process model

Everything starts at [`cmd/scanner/main.go` → `func main()`](cmd/scanner/main.go). On every invocation it:

1. Sets up structured JSON logging (`log/slog`).
2. Loads configuration via `config.Load()` and opens a PostgreSQL connection pool to `cfg.DatabaseURL` (`NS_DB_URL`, defaulting to `localhost:5433/scanner_db`). `pgx` connects lazily, so a down database surfaces as an error on first query, not at startup.
3. Routes to one of four subcommands: `scan`, `list`, `diff`, `dashboard`.

**What `go run ... dashboard` does and doesn't start:** it launches *only* the Go process. PostgreSQL, Prometheus, and Grafana are independent Docker containers that must already be running. Correct order:

```
1. docker start pg-scanner     # DB up first (everything writes here)
2. go run ... dashboard ...    # exposes /metrics on :9090
3. docker start prometheus     # scrapes :9090
4. docker start grafana        # reads prometheus + postgres
```

The scanner runs **natively on the host** (not containerized) because it must see the host's real network stack — see [Why three Docker containers](#why-three-docker-containers).

---

## The passive pipeline (dashboard mode)

`dashboard.Run()` ([internal/dashboard/dashboard.go](internal/dashboard/dashboard.go)) wires a set of concurrent goroutines connected by channels. Data flows left to right:

```
┌─────────┐  FlowRecord  ┌────────────┐  EnrichedFlow  ┌──────────┐
│ CAPTURE │ ───channel──►│ ENRICHMENT │ ────channel───►│ STORAGE  │
│ poller  │              │ proto/DNS/ │  (+counters++) │ Postgres │
│  (5s)   │              │   GeoIP    │                │ (COPY)   │
└─────────┘              └────────────┘                └────┬─────┘
                                                            │
   ┌──────────────────┐   reads recent flows (1m)           │
   │ ANOMALY DETECTOR │◄────────────────────────────────────┤
   └──────────────────┘                                     │
   ┌──────────────────┐   sets gauges from DB (30s)         │
   │    COLLECTOR     │◄────────────────────────────────────┘
   └────────┬─────────┘
            ▼
      Prometheus gauges + counters  ──►  /metrics (:9090)
```

### 1. Capture — [internal/capture/poller.go](internal/capture/poller.go)

Every **5 seconds**, the poller runs this PowerShell command:

```powershell
Get-NetTCPConnection | Where-Object State -eq 5 | ForEach-Object { ... }
```

`State -eq 5` means **Established**. This returns the host's own live outbound connections (remote IP, remote port, owning process). Two filters narrow the output ([poller.go:152](internal/capture/poller.go#L152)):

- Drop empty / wildcard remote addresses (listening sockets).
- Drop loopback / private (RFC1918) / link-local addresses when `ExcludeLocal=true` (the default).

Each surviving connection becomes a `FlowRecord`. A `seen` map deduplicates identical `src:dst:port:proto` tuples across snapshots so a long-lived connection is emitted once, not every 5s.

> This is why dashboard mode needs **no CIDR**: the scope is automatically "every public IP this host currently has an established connection to."

### 2. Enrichment — [`enrichLoop`](internal/dashboard/dashboard.go) + [internal/enrichment/](internal/enrichment/)

Each `FlowRecord` is enriched into an `EnrichedFlow`:

| Step | Adds | Source |
|---|---|---|
| **Protocol** | `HTTPS`, `DNS`, `SSH`… instead of just `TCP` | port→name map ([protocol.go](internal/enrichment/protocol.go)) |
| **Reverse DNS** | destination hostname | `net` resolver, cached with a TTL ([dns.go](internal/enrichment/dns.go)) |
| **GeoIP** | country, continent, latitude, longitude | MaxMind GeoLite2 lookup ([geoip.go](internal/enrichment/geoip.go)) |

This is also where the per-flow **Prometheus counters** are incremented (flows, packets, bytes by protocol/direction).

### 3. Storage — [internal/storage/store.go](internal/storage/store.go)

`storeLoop` batches enriched flows and flushes them on a **5-second ticker** or when the batch hits **500 rows**, using PostgreSQL's high-throughput `COPY` protocol ([store.go:70](internal/storage/store.go#L70)) rather than row-by-row `INSERT`.

A separate loop refreshes two materialized views (`mv_protocol_breakdown`, `mv_geo_breakdown`) on the `NS_AGG_INTERVAL` cadence.

### 4. Metrics collector — [internal/metrics/collector.go](internal/metrics/collector.go)

Every **30 seconds** the collector queries Postgres to set the **gauges** (current-value metrics) that can't be derived from the stream alone — active connections, unique destinations, unique countries.

---

## The active scanner (scan / diff)

[internal/scanner/scanner.go](internal/scanner/scanner.go). Completely independent of the passive pipeline.

1. **`enumerateCIDR`** ([scanner.go:133](internal/scanner/scanner.go#L133)) parses e.g. `192.168.1.0/24` and expands it to every host address, dropping network and broadcast addresses.
2. **Bounded concurrency** — up to **64** workers run at once, gated by a `semaphore` inside an `errgroup` ([scanner.go:37](internal/scanner/scanner.go#L37)), so a `/16` doesn't exhaust host resources.
3. **`probeHost`** ([scanner.go:70](internal/scanner/scanner.go#L70)) runs three checks per IP:
   - **ICMP ping** (`pro-bing`, 1 packet, 500ms timeout) → up/down + RTT.
   - **TCP connect** to ports 22, 80, 443, 8080 → open ports.
   - **Reverse DNS** → hostname.
4. Results are persisted to `subnets` / `scans` / `hosts`.

**`diff`** ([main.go:235](cmd/scanner/main.go#L235)) loads the two most recent scans of a subnet and runs a SQL `FULL OUTER JOIN` between them ([main.go:263](cmd/scanner/main.go#L263)), classifying each host as `NEW` (appeared / came up) or `REMOVED` (went down). This is network drift detection — useful for spotting rogue or departed devices.

---

## Metrics catalog

Defined in [internal/metrics/registry.go](internal/metrics/registry.go). Two categories matter:

- **Counters** — cumulative, only increase. Use `rate()` in PromQL to get per-second velocity. Incremented inline in the enrichment loop.
- **Gauges** — current value, go up *and* down. Set every 30s by the collector from Postgres.

### The key insight for defending the dashboard

Every stat is **a count of something distinct over a time window**, and the windows differ. That's why the numbers differ — they are *the same traffic* measured over different horizons, not contradictory data:

| Metric | Counts | Window | Type |
|---|---|---|---|
| `net_scanner_traffic_active_connections` | flow records | last **30s** | gauge |
| `net_scanner_traffic_unique_destinations` | distinct dst IPs | last **5m** | gauge |
| `net_scanner_geo_unique_countries` | distinct countries | last **5m** | gauge |
| World map "Unique IPs" | distinct dst IPs | last **1h** | SQL |

So Active Connections ≈ 0–2 while the map shows 100+ is **expected**: 30 seconds of *new* connections vs. an hour of *distinct* destinations.

### Full metric reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `net_scanner_traffic_active_connections` | gauge | — | Flow records captured in the last 30s — a liveness pulse |
| `net_scanner_traffic_unique_destinations` | gauge | — | Distinct destination IPs in the last 5 min |
| `net_scanner_geo_unique_countries` | gauge | — | Distinct destination countries in the last 5 min |
| `net_scanner_traffic_flows_total` | counter | `protocol`, `capture_mode` | Cumulative captured flows; `rate()` → flows/sec |
| `net_scanner_traffic_packets_total` | counter | `protocol` | Cumulative packets |
| `net_scanner_traffic_bytes_total` | counter | `protocol`, `direction` | Cumulative bytes (⚠️ 0 in poller mode) |
| `net_scanner_anomaly_events_total` | counter | `event_type`, `severity` | Anomalies detected (pre-seeded to 0) |
| `net_scanner_traffic_flow_duration_seconds` | histogram | — | Flow duration distribution (unused by current panels) |

> **"active_connections" naming caveat:** the metric counts flow records in a 30s window, so it's really *recent capture throughput*, not concurrent live sockets. Defensible phrasing: *"the count of external connections recorded in the trailing 30-second window."*

### Dashboard panels by datasource

**Prometheus-backed** (real-time): Active Connections, Unique Destinations, Unique Countries, Total Flows, Connection Rate Over Time, Anomalies Detected, Bandwidth Over Time.

**Postgres-backed** (historical detail): Top 10 Destination IPs, Top 10 Countries, Traffic by Continent, Port Breakdown, Anomaly Events table, Traffic World Map.

---

## Database schema

Two migrations under [db/migrations/](db/migrations/).

### Active-scan tables ([000001_init_schema.up.sql](db/migrations/000001_init_schema.up.sql))

- **`subnets`** — tracked CIDR blocks (unique).
- **`scans`** — one row per scan run, linked to a subnet, with start/end times.
- **`hosts`** — per-scan host results: IP, hostname, RTT, up/down, open ports.

### Passive-analytics tables ([000002_traffic_analytics.up.sql](db/migrations/000002_traffic_analytics.up.sql))

- **`traffic_flows`** — the core table: one row per observed connection, fully enriched (protocol, hostname, country, lat/long, process). Indexed on `captured_at`, `dst_ip`, `country_code`, `protocol`, `dst_port`.
- **`traffic_aggregates`** — pre-rolled per-minute stats.
- **`geo_cache`** — table for caching IP→geo results. Currently *read* by the anomaly detector to attach country info; the GeoIP enrichment path queries the in-memory MaxMind database directly rather than this table.
- **`anomaly_events`** — the anomaly log (type, severity, description, JSONB metadata).
- **`mv_protocol_breakdown`, `mv_geo_breakdown`** — materialized views, refreshed periodically and read by dashboard panels.

> Both halves of the toolkit share one database — active scans populate `subnets`/`scans`/`hosts`; passive analytics populate `traffic_flows`/`anomaly_events`. One schema, three lenses.

---

## Anomaly detection

[internal/anomaly/detector.go](internal/anomaly/detector.go). Runs every **1 minute**, pulling recent flows from the DB and applying two detectors:

1. **Spike detection** — maintains a rolling average of bytes-per-window; flags a `warning` when the current window exceeds the average by ≥2× ([`DefaultThresholds`](internal/anomaly/detector.go)).
2. **New-destination detection** — for each destination, checks whether it's been seen in the last 24h; first contact emits an `info` event.

Events are persisted to `anomaly_events` **and** increment the Prometheus counter. The counter is **pre-seeded to 0** at startup so the dashboard reads a truthful `0` rather than "No data" before anything fires.

**Why it usually shows 0:** spike detection needs byte data (0 in poller mode), and new-destination only fires for genuinely first-seen IPs — your destinations already have history. The detection is wired and waiting, not broken.

---

## Why three Docker containers

PostgreSQL, Prometheus, and Grafana are **off-the-shelf infrastructure**, not project code. Containerizing them gives:

- **Reproducibility** — version-pinned services; identical on any machine.
- **No host pollution** — no native installs; `docker rm` removes everything cleanly.
- **Isolation** — separate filesystems/configs; no conflicts.
- **Portability** — clone the repo, run the containers, done.

**The scanner itself is deliberately *not* containerized** because it must observe the host's real network stack: the poller reads the host's live socket table, and the active scanner needs the host's network position to reach a target subnet. In a container it would only see the container's isolated network namespace. The pattern — *containers for stateful infra, native execution for the thing that needs raw host access* — is intentional.

---

## Design decisions

| Decision | Rationale |
|---|---|
| **pgx + `COPY` for inserts** | Batch `COPY` is far faster than per-row `INSERT` for high-volume flow data. |
| **Channels between pipeline stages** | Decouples capture / enrich / store so each runs at its own pace with backpressure via buffered channels. |
| **Gauges from DB, counters inline** | Counters are naturally per-event (increment as flows arrive); gauges are point-in-time aggregates best computed by querying the DB. |
| **In-memory DNS cache with TTL** | Reverse-DNS results are cached per IP ([dns.go](internal/enrichment/dns.go)) so repeat destinations skip lookups; failures never stall the pipeline. |
| **Materialized views** | Pre-aggregate expensive groupings so dashboard panels stay fast. |
| **Bounded scan concurrency (64)** | Parallel enough to scan large subnets quickly without exhausting sockets/FDs. |
| **Prometheus on 9091** | The exporter already owns 9090; the server needs a separate port. |
| **World map sized by unique IPs** | Bytes are 0 in poller mode; unique-IP count is real, meaningful data. |
| **Auto-provisioned Grafana** | Datasources + dashboard load from files, so the visualization layer is reproducible and version-controlled. |

---

## Known limitations

- **Byte/bandwidth metrics are 0 in poller mode.** The OS connection table exposes endpoints and ports, not byte volume. Byte-based panels are wired and will populate once `pcap` mode lands. *Defense:* *"Byte accounting requires packet capture — a deliberate next phase. The current build proves the full pipeline using connection-level data."*
- **`pcap` mode unimplemented** — `--mode pcap` returns an error; only `poller` works.
- **Windows-only capture** — the poller relies on PowerShell `Get-NetTCPConnection`.
- **Process tied to its terminal** — the scanner is a foreground process; closing the terminal stops it. A `docker-compose` setup (with `network_mode: host` for the scanner) or a service wrapper would make the whole stack start and stay up together.
- **Unbounded dedup state** — the poller's `seen` map is never pruned; it grows one entry per distinct 4-tuple for the process lifetime.

For the full set of validity threats — sampling blind spots, construct-validity issues, and unexercised code paths — see [docs/THEORY.md §6](docs/THEORY.md#6-validity-and-limitations).
</content>
