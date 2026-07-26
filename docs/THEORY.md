# Theory and Design Rationale

This document explains **why** net-scanner is built the way it is. It is the theoretical companion to the other two documents, and the three are deliberately non-overlapping:

| Document | Question it answers |
|---|---|
| [README.md](../README.md) | *How do I run it?* — setup, commands, configuration |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | *How does it work?* — pipeline internals, metrics catalog, schema |
| **THEORY.md** (this file) | *Why is it built this way?* — the principles each component instantiates, and what they assume |

It is written top-down: the problem, the theory, the architecture that follows from the theory, the technologies chosen to implement it, how the layers connect, and — critically — where the design's claims stop being valid.

**Scope: Month 1.** This describes the system as it stands at the first milestone. Sections marked *Not yet implemented* are stated as such rather than glossed over.

---

## Table of contents

1. [Problem framing](#1-problem-framing)
2. [Theoretical foundations](#2-theoretical-foundations)
3. [Architecture](#3-architecture)
4. [Technology stack, justified](#4-technology-stack-justified)
5. [How the layers connect](#5-how-the-layers-connect)
6. [Validity and limitations](#6-validity-and-limitations)
7. [Appendix: anticipated defence questions](#appendix-anticipated-defence-questions)

---

## 1. Problem framing

### 1.1 The problem

Network security begins with **situational awareness**: you cannot defend what you cannot see. Two distinct questions must be answered, and they require opposite methods:

- **"What exists on my network?"** — an inventory problem. Answered by *reaching out* and probing an address space.
- **"What is my machine talking to?"** — a behaviour problem. Answered by *observing* traffic that is already happening.

Neither question subsumes the other. A perfect asset inventory tells you nothing about a compromised host beaconing to a command-and-control server. A perfect traffic log tells you nothing about a rogue device that has not yet communicated with you.

net-scanner implements both, sharing one database so the two views can eventually be correlated.

### 1.2 The reconnaissance duality

|  | **Active** (`scan`, `diff`) | **Passive** (`dashboard`) |
|---|---|---|
| Question | "What exists?" | "What am I talking to?" |
| Method | Emit probes, interpret responses | Read local state, emit nothing |
| Observable? | **Yes** — appears in target logs/IDS | **No** — no traffic generated |
| Needs a target | Yes (`--cidr`) | No (scope is self) |
| Failure mode | Silence is ambiguous | Cannot see what it does not sample |
| Epistemics | Interventional — we perturb the system | Observational — we watch it |

The last row is the deepest distinction. Active scanning is an **experiment**: we apply a stimulus and record the response, which gives clean causal attribution (a SYN-ACK *means* a listening service) at the cost of being detectable and intrusive. Passive monitoring is an **observational study**: unobtrusive, but it can only report on traffic that happened to occur, with all the sampling bias that implies.

> ⚠️ **Terminology trap.** "Active" is overloaded in this project, as [ARCHITECTURE.md](../ARCHITECTURE.md#mental-model-active-vs-passive) also warns:
> - **Active scanning** — active because *we transmit probes*.
> - **Active connections** — a dashboard statistic meaning *currently-established sockets*. This is **passive** monitoring.
>
> Same adjective, opposite methodology. Be precise about which you mean.

---

## 2. Theoretical foundations

Each subsection states the principle, its formal basis, where the codebase instantiates it, and — most importantly — **what it assumes**. The assumptions are where a defence is won or lost.

### 2.1 Address-space arithmetic (CIDR)

**Principle.** Classless Inter-Domain Routing (RFC 4632) replaced fixed class A/B/C boundaries with an explicit prefix length. An address block `A/p` partitions the 32-bit IPv4 space by treating the high `p` bits as a network identifier and the low `32−p` bits as a host identifier. Prefix matching is a pure bitwise operation, which is what makes longest-prefix-match routing tractable in hardware.

**Instantiation.** [`enumerateCIDR`](../internal/scanner/scanner.go#L133) masks off the host bits to find the network address, then walks the block by incrementing the address in place ([`incIP`](../internal/scanner/scanner.go#L150) — a big-endian byte-wise increment with carry) until the block no longer contains the result. It then drops the first and last addresses:

```
usable hosts = 2^(32−p) − 2
```

The network address (all host bits 0) identifies the block itself; the broadcast address (all host bits 1) addresses every host on it. Neither is assignable to an interface, so probing them wastes time and can produce misleading responses.

**Assumptions and edges.**
- **Memory is O(2^(32−p)).** A `/24` is 254 strings; a `/8` is ~16.7 million, materialised eagerly in a slice. This is the practical ceiling on scan size and a genuine scalability limitation — a streaming iterator would remove it.
- **The `−2` rule does not hold universally.** RFC 3021 defines `/31` as a valid point-to-point link where *both* addresses are usable, and a `/32` is a single host route. The implementation handles this with a `len(ips) > 2` guard that skips the stripping — verified in `TestEnumerateCIDR`.
- **IPv4 only.** The enumeration logic would work bytewise on IPv6, but a `/64` contains 2^64 addresses, so exhaustive enumeration is not merely slow — it is infeasible. IPv6 host discovery is a genuinely different problem requiring DNS enumeration or neighbour-discovery techniques.

### 2.2 Reachability as an unreliable oracle

**Principle.** "Is this host up?" cannot be answered directly; it can only be inferred from responses to stimuli. ICMP Echo (RFC 792) is the classical probe, but its answer is **asymmetric in information content**:

- A reply is **positive proof** of liveness.
- Silence proves nothing. The host may be down, or up-but-firewalled, or the probe or reply may have been dropped in transit.

This is a one-sided oracle: it can confirm but not refute.

**Instantiation.** [`probeHost`](../internal/scanner/scanner.go#L70) compensates by consulting a **second, independent oracle**. After the ICMP probe it attempts TCP connections to ports 22, 80, 443 and 8080, and a successful handshake *also* sets `IsUp = true` ([scanner.go:84](../internal/scanner/scanner.go#L84)):

```
IsUp = ICMP_reply ∨ (∃ port ∈ P : TCP_connect(port) succeeds)
```

This is **multi-oracle consensus** — specifically a disjunction, which is the correct combinator for one-sided positive oracles. Because each oracle can only produce false negatives, never false positives, their disjunction strictly reduces the false-negative rate without introducing false positives. A host that drops ICMP but serves HTTPS — extremely common, since blocking ICMP is a default hardening step — is correctly classified as up.

**Assumptions.**
- The four probed ports are a *convenience sample*, not a representative one. A host running only a database on 5432 is invisible to both oracles and reported as down. The classification is therefore **"up" or "not observed"**, not "up" or "down". This is the honest reading of the `is_up` column.
- Reverse DNS is only attempted for hosts believed up, saving lookups but meaning a hostname is never recorded for an unobserved host.

### 2.3 Scanning technique taxonomy

**Principle.** Port scanning techniques differ in which stage of the TCP three-way handshake they complete, trading stealth against privilege:

| Technique | Mechanism | Requires raw sockets | Logged by target |
|---|---|---|---|
| **TCP connect** | Full handshake via the OS socket API | No | Yes — a completed connection |
| **SYN / half-open** | Send SYN, read SYN-ACK, send RST | **Yes** | Often not — no connection completes |
| **FIN / NULL / Xmas** | Malformed flag combinations; infer from RST | **Yes** | Varies by stack |
| **UDP** | Send datagram; infer from ICMP port-unreachable | Usually | Unreliable — silence is ambiguous |

**Instantiation.** [`checkTCPPort`](../internal/scanner/scanner.go#L123) uses `net.DialTimeout`, i.e. a full connect scan through the ordinary socket API.

**Rationale.** This is a deliberate **portability-and-privilege trade against stealth**. Raw sockets require `CAP_NET_RAW` on Linux or Administrator on Windows; demanding elevation for a monitoring tool is a meaningful security cost and an operational barrier. Connect-scanning needs no privilege and behaves identically across platforms. Since this tool is designed for scanning networks you own — where being logged is unremarkable — stealth has little value. The same reasoning drives `SetPrivileged(false)` in [`pingHost`](../internal/scanner/scanner.go#L102), which uses unprivileged datagram-based ICMP rather than raw sockets.

### 2.4 The TCP finite state machine as a data source

**Principle.** TCP (RFC 793) specifies a connection as a finite state machine: CLOSED → LISTEN / SYN-SENT → SYN-RECEIVED → **ESTABLISHED** → FIN-WAIT-1/2 → CLOSING → TIME-WAIT → CLOSED. The operating system maintains this FSM per socket and exposes the table for inspection.

**Instantiation.** The poller shells out to PowerShell and filters on state 5:

```powershell
Get-NetTCPConnection | Where-Object State -eq 5 | ForEach-Object { ... }
```

State 5 is ESTABLISHED — connections that completed the handshake and have not begun teardown.

**Why endpoint observation rather than packet capture.** This is not a compromise; it is a different vantage point with a genuine advantage. The socket table yields **process attribution** — socket → owning PID → process name — which is *structurally invisible on the wire*. A packet sniffer sees that this machine contacted `142.250.185.78:443`; it cannot see that the responsible process was `chrome.exe` rather than `svchost.exe`. That distinction is exactly what matters when triaging whether a connection is legitimate.

This is host-based telemetry (the EDR model) rather than network-based telemetry (the IDS model), and the two are complementary rather than competing.

**Assumptions.**
- **Only ESTABLISHED is captured.** Connections that fail to establish — refused, timed out, blocked — never appear. Failed connection attempts are a strong signal of scanning or misconfiguration, and this build is blind to them.
- **TCP only.** UDP has no connection state to enumerate. `Get-NetUDPEndpoint` would list bound endpoints but not peers, so UDP traffic — including all plain DNS — is entirely absent. The `Protocol` column can hold `'UDP'`, but nothing ever writes it.

### 2.5 Flow abstraction

**Principle.** The flow abstraction (NetFlow, standardised as IPFIX in RFC 7011) aggregates packets sharing a key into a single record. The canonical key is the **5-tuple**:

```
(source IP, source port, destination IP, destination port, protocol)
```

Flows trade per-packet fidelity for a large reduction in data volume — the essential move that makes long-horizon traffic retention affordable.

**Instantiation.** [`flowKey`](../internal/capture/poller.go#L174) constructs:

```go
SrcIP + ":" + DstIP + ":" + itoa(DstPort) + ":" + Protocol
```

This is a **4-tuple** — source port is absent from `FlowRecord` entirely. A `seen` map keyed on it deduplicates across polling cycles, so a long-lived connection is emitted once rather than once per 5-second tick.

**Consequence, stated plainly.** Two concurrent connections from different ephemeral source ports to the same destination service **collapse into one flow**. A browser opening six parallel connections to one server is recorded as one. This is a deliberate cardinality reduction — and it is defensible, because for the question this tool asks ("which external services is this host communicating with, and via what process?") the ephemeral source port is noise. But it means flow *counts* are counts of distinct host-service relationships, not of TCP connections. `TestFlowKey` pins this behaviour down explicitly.

**A known leak.** The `seen` map is never pruned. Over a long-running session it grows without bound — one entry per distinct 4-tuple ever observed. On a workstation this is slow enough not to matter within a session, but it is unbounded state and would need a TTL or LRU eviction for continuous operation.

### 2.6 Sampling theory — the most important limitation

**Principle.** The poller samples a continuous process at discrete 5-second intervals. Any sampled measurement of a continuous signal is subject to **aliasing**: phenomena whose characteristic timescale is shorter than the sampling interval are not merely under-measured, they are *systematically and invisibly* lost. This is the same principle underlying the Nyquist–Shannon sampling theorem — to observe a phenomenon you must sample faster than it changes.

**Consequence.** A connection that opens and closes entirely between two polls **never existed** as far as this system is concerned. This is not a rare edge case:

| Traffic type | Typical lifetime | Captured at 5 s polling? |
|---|---|---|
| DNS query over UDP | milliseconds | Never (also not TCP) |
| Short HTTP request/response | 10–500 ms | Only if it straddles a poll |
| TLS handshake to a new host | ~100 ms–1 s | Usually not |
| Streaming video, SSH session | minutes–hours | Reliably |
| Idle keep-alive connection | hours | Reliably |

The capture is therefore **biased toward long-lived connections**. It is close to a census of persistent sessions and close to blind to transactional traffic. Bursty, short-lived traffic — precisely the profile of much malicious beaconing — is exactly what it is worst at seeing.

**Why this is the right thing to foreground.** It is the honest answer to "how complete is your data?", and it is a *property of the measurement method*, not a bug. Lowering `NS_POLL_INTERVAL` narrows the blind spot but never closes it, because the limit as the interval approaches zero is packet capture — which is a different capture mode, not a smaller number.

### 2.7 Protocol identification by convention

**Principle.** IANA maintains a registry assigning well-known ports (0–1023) and registered ports (1024–49151) to services. Identifying a protocol from its port number treats this registry as an oracle. It is a **convention-based heuristic**: it works because operators mostly follow convention, not because the mapping is enforced by anything.

**Instantiation.** [`IdentifyProtocol`](../internal/enrichment/protocol.go#L34) looks the destination port up in a 25-entry table and falls back to the transport name when absent.

**Assumptions and failure modes.**
- **Non-standard ports defeat it.** A web server on 8081 is reported as `TCP`.
- **Tunnelling defeats it.** SSH over 443, or any protocol inside an HTTPS tunnel, is reported as `HTTPS`.
- **It is directional.** Only the destination port is consulted, which is correct for outbound client connections — the source port is ephemeral — but would misclassify inbound server traffic.
- **A deliberate deception is trivial.** Malware choosing port 443 is labelled `HTTPS` with no further scrutiny.

**The alternative not taken.** Deep packet inspection identifies protocols from payload structure rather than port number, and for encrypted traffic, TLS SNI extraction or JA3/JA4 fingerprinting identifies the destination and client stack from the handshake — which is unencrypted. None of this is implemented, and none of it is possible without packet capture. Port-based identification is what the socket table makes available, and its accuracy is bounded accordingly.

### 2.8 Set theory for drift detection

**Principle.** Two scans of the same subnet produce two sets of live hosts, `H_prev` and `H_curr`. The interesting quantity is their **symmetric difference**:

```
NEW      = H_curr \ H_prev     (appeared)
REMOVED  = H_prev \ H_curr     (disappeared)
H_prev △ H_curr = NEW ∪ REMOVED
```

This is the formal basis of asset-inventory drift detection: a device in `NEW` that nobody provisioned is a rogue device; a device in `REMOVED` that should be running is an outage.

**Instantiation.** In relational algebra, symmetric difference over a common key is a `FULL OUTER JOIN` with a predicate selecting rows where the two sides disagree — which is exactly the query in [`executeDiff`](../cmd/scanner/main.go).

**A worked example of three-valued logic.** The original implementation used:

```sql
WHERE prev.is_up != curr.is_up
```

This is subtly and silently wrong. In a `FULL OUTER JOIN`, a host present in only one snapshot yields `NULL` on the other side. SQL uses **three-valued logic**: `NULL != true` evaluates not to `true` or `false` but to `NULL`, and `WHERE` admits only rows evaluating to `true`. So every genuinely new or genuinely vanished host — the entire point of the query — was silently discarded. The `CASE` branch written to handle `prev.ip IS NULL` was unreachable.

The corrected predicate is:

```sql
WHERE prev.is_up IS DISTINCT FROM curr.is_up
```

`IS DISTINCT FROM` is the NULL-safe comparison: it treats `NULL` as a value that differs from any non-`NULL` value, and returns `true`/`false` but never `NULL`. It is the correct relational expression of set difference.

This is worth stating explicitly because it illustrates a general principle: **`NULL` in SQL means "unknown", not "absent"**, and comparison operators propagate that unknowing. Any outer join followed by a comparison predicate is a place to check for this bug.

### 2.9 Statistical anomaly detection

**Principle.** Threshold-based anomaly detection models normal behaviour as a statistic over recent history and flags observations exceeding a multiple of it. The simplest form is a **moving average with a fixed multiplier**:

```
baseline_t = mean(x_{t−n} … x_{t−1})
anomaly    ⟺ x_t > k · baseline_t
```

**Instantiation.** [`rollingAverage`](../internal/anomaly/detector.go#L187) over a 10-slot window with `k = 2.0`.

**The estimator-bias guard.** The function deliberately excludes the final element — the observation under test — from its own baseline:

```go
for _, v := range values[:len(values)-1] { sum += v }
return sum / float64(len(values)-1)
```

This is not incidental. Including `x_t` in `baseline_t` **contaminates the baseline with the observation being tested**, and does so proportionally: the larger the spike, the more it inflates its own reference value, and the harder it becomes to detect. With a window of `n`, including the current sample pulls the baseline up by `x_t/n`, biasing the detector toward silence exactly when it should fire. Excluding it keeps the baseline an estimate of *prior* normality. `TestRollingAverage` asserts this directly.

**Fixed multiplier vs. z-score.** The alternative is a standardised score:

```
z = (x_t − μ) / σ,   anomaly ⟺ z > threshold
```

| | Fixed multiplier (`x > k·μ`) | z-score (`(x−μ)/σ > k`) |
|---|---|---|
| Distributional assumption | None | Roughly normal, for the threshold to mean anything |
| Adapts to variance | No | Yes |
| On stable traffic | Fine | Fine |
| On bursty traffic | Constant false positives | Adapts — high σ raises the bar |
| Robust to outliers | Somewhat | No — outliers inflate σ. MAD is the robust alternative |

The fixed multiplier is the right starting point precisely *because* it assumes nothing about the distribution — network traffic is famously non-Gaussian, heavy-tailed and self-similar, so a z-score's normality assumption is not obviously safer. Its weakness is not adapting to variance.

**Why it currently never fires.** The baseline is computed over byte counts, and the poller reports zero bytes (§6.2). `0 > 0 × 2.0` is false, always. The detector is correctly wired and structurally silent — a fact `TestSpikeRuleAgainstZeroBaseline` encodes as an executable assertion rather than a claim in prose.

### 2.10 Novelty detection

**Principle.** [`checkNewDestinations`](../internal/anomaly/detector.go#L111) asks whether a destination has been contacted in the last 24 hours; first contact emits an event. Formally this is **one-class classification**: model only the normal class and flag everything outside it. Unlike supervised classification it needs no labelled attack data — which matters enormously, because labelled malicious traffic for *your* network does not exist.

**Security rationale.** First-contact detection is the classical heuristic for command-and-control discovery. Compromised hosts must eventually reach infrastructure they have never contacted before, and that first connection is the earliest network-visible moment of compromise.

**Assumptions and failure modes.**
- **Cold start.** On day one every destination is novel, so the detector is pure noise until a baseline accumulates. The 24-hour window means it takes a day to become useful and never fully stabilises for a host with genuinely varied browsing.
- **Base-rate fallacy.** Ordinary web browsing contacts new CDN endpoints constantly. Even a very low per-destination false-positive rate produces overwhelming absolute volume, because the denominator is huge. This is why the events are `info` severity — they are a feed to be correlated, not alerts to be actioned.
- **Trivially evaded.** An attacker using an already-contacted host — a compromised popular service, or a CDN-fronted channel — never triggers it.
- **The window is a memory, not a model.** There is no notion of *how often* a destination is normally contacted, only whether it appeared at all. Periodicity analysis — detecting the regular heartbeat that distinguishes beaconing from human browsing — would be substantially stronger and is not implemented.

### 2.11 Time-series semantics

**Principle.** Prometheus distinguishes two fundamental metric types, and the distinction is semantic rather than cosmetic:

- **Counter** — monotonically non-decreasing, resets only on process restart. The *value* is meaningless (it depends on uptime); the *derivative* is the signal.
- **Gauge** — an instantaneous measurement that moves in both directions. The value is meaningful; the derivative usually is not.

**Why `rate()` matters.** `rate(counter[1m])` computes per-second change over a window and is **reset-aware**: on detecting a decrease it infers a counter reset and compensates, rather than reporting a large negative rate. This is why counters must never be reset manually — the reset is a signal the query layer interprets.

**Instantiation.** Counters (`flows_total`, `bytes_total`, `packets_total`, `anomaly_events_total`) are incremented inline as each flow passes through enrichment. Gauges (`active_connections`, `unique_destinations`, `geo_unique_countries`) are set every 30 seconds by [`metrics.Collector`](../internal/metrics/collector.go) from SQL aggregates.

**Why gauges come from SQL rather than the stream.** A gauge like "distinct destination IPs in the last 5 minutes" is a **windowed set-cardinality** query. Maintaining it in-process would require a sliding-window structure with expiry — real state, real bugs. Postgres already holds the data and `COUNT(DISTINCT …)` over an indexed timestamp is cheap. The rule that falls out: *stream what is naturally incremental, query what is naturally aggregate.*

**Pre-seeding.** [`NewDetector`](../internal/anomaly/detector.go) initialises the anomaly counter series to zero at startup. Prometheus has no concept of "a series that exists but has no events" — an unseeded counter is simply absent, and Grafana renders absence as "No data", which reads as *broken* rather than as *nothing has happened*. Pre-seeding makes the zero explicit. This is a small thing that materially changes how the dashboard is interpreted.

**Label cardinality.** Every distinct label-value combination is a separate stored time series. `flows_total{protocol, capture_mode}` is bounded (~25 protocols × 2 modes). Adding `dst_ip` as a label would create one series per destination — thousands, unbounded, growing forever. This is the standard Prometheus failure mode, and it is why per-destination detail lives in Postgres and only low-cardinality aggregates live in Prometheus. **The two-datasource dashboard design follows directly from this constraint**, not from convenience.

### 2.12 Concurrency: Communicating Sequential Processes

**Principle.** Go's concurrency model derives from Hoare's CSP (1978): independent processes communicating over channels rather than sharing memory. *"Do not communicate by sharing memory; instead, share memory by communicating."* The pipeline stages need no mutexes because ownership of each record transfers along the channel.

**Three distinct patterns are used, each solving a different problem:**

**1. Bounded worker pool — admission control.** [`scanner.Run`](../internal/scanner/scanner.go#L37) pairs a weighted semaphore (limit 64) with an `errgroup`. Without the bound, a `/16` would spawn 65,534 goroutines each holding a socket — exhausting file descriptors and ephemeral ports long before the network saturated. The semaphore is classical Dijkstra admission control; 64 is chosen to keep the scan network-bound rather than resource-bound.

Note the lock-free result collection: results are written to a pre-sized slice at index `i`, so each goroutine owns a distinct memory location and no synchronisation is needed. This is *disjoint ownership*, not shared state.

**2. Buffered channels — backpressure.** Pipeline stages run at different speeds; enrichment does DNS lookups and is slower than capture. A buffered channel absorbs transient mismatch; when the buffer fills, the producer blocks, and that blocking *is* the flow-control signal propagating upstream. No explicit rate limiting is needed.

**3. Non-blocking send with drop — availability over completeness.** [`Detector.emit`](../internal/anomaly/detector.go#L153) uses `select` with a `default` branch, discarding the event (with a warning) if the 64-slot buffer is full:

```go
select {
case d.events <- evt:
    // recorded
default:
    // channel full — drop
}
```

This is a deliberate **CAP-style availability choice**: under overload the detector loses events rather than stalling. The alternative — blocking — would apply backpressure from the anomaly path all the way back into capture, so a slow database writer could halt traffic observation entirely. Losing some anomaly events is strictly better than going blind. The trade is explicit and the log records when it happens.

### 2.13 Caching

**Principle.** Reverse DNS is a network round-trip on the critical path of every flow. Caching converts repeated lookups into memory reads, exploiting the strong temporal and spatial locality of network traffic — a host contacts the same small set of destinations repeatedly.

**Instantiation.** [`DNSResolver`](../internal/enrichment/dns.go) holds a TTL-bounded map behind a `sync.RWMutex`. `RWMutex` rather than `Mutex` matters: the workload is read-dominated, and readers do not exclude each other.

**Negative caching.** Failures are cached too. Without this, every flow to a destination with no PTR record — very common — pays the full DNS timeout, and the enrichment stage becomes latency-bound on records that will never resolve. Negative caching is standard DNS practice (RFC 2308) for exactly this reason.

**Assumption.** The TTL is a fixed 10 minutes rather than the record's actual DNS TTL, trading correctness for simplicity. A stale mapping persists at most 10 minutes.

### 2.14 Data engineering

**Batch amortisation.** `storeLoop` accumulates flows and flushes at 500 rows or 5 seconds, whichever comes first. Per-row `INSERT` pays network round-trip, parse, plan and transaction overhead *per row*; batching amortises all of it. The dual trigger bounds both throughput cost and latency — a busy system flushes on size, an idle one on time, so records never sit indefinitely.

**COPY vs INSERT.** [`InsertFlows`](../internal/storage/store.go) uses PostgreSQL's `COPY` protocol via `pgx.CopyFrom`. `COPY` streams rows in a binary format, bypassing per-statement SQL parsing and planning entirely. For bulk loading it is typically an order of magnitude faster than individual `INSERT`s.

**Materialised views.** `mv_protocol_breakdown` and `mv_geo_breakdown` store the *results* of aggregate queries, refreshed periodically. This trades **staleness for read latency** — the classic precomputation trade. `REFRESH MATERIALIZED VIEW CONCURRENTLY` is used specifically because the non-concurrent form takes an `ACCESS EXCLUSIVE` lock, which would block dashboard reads during every refresh. `CONCURRENTLY` requires a unique index and does more work, but keeps the view readable throughout.

**Index design.** `traffic_flows` is indexed on `captured_at`, `dst_ip`, `country_code`, `protocol` and `dst_port` — precisely the columns the dashboard filters and groups by. Indexes trade write throughput and storage for read speed, which is the correct direction here: flows are written in batches by one process and read repeatedly by every dashboard refresh across every viewer.

---

## 3. Architecture

The theory above determines the structure. This section is a bridge — see [ARCHITECTURE.md](../ARCHITECTURE.md) for the full internal walkthrough.

**Layered view:**

```
┌──────────────────────────────────────────────────────────┐
│ PRESENTATION   Grafana — 15 panels, 2 datasources        │
├──────────────────────────────────────────────────────────┤
│ AGGREGATION    Prometheus (time-series) │ Postgres MVs   │
├──────────────────────────────────────────────────────────┤
│ PERSISTENCE    PostgreSQL — flows, scans, hosts, events  │
├──────────────────────────────────────────────────────────┤
│ ANALYSIS       Anomaly detection (spike, novelty)        │
├──────────────────────────────────────────────────────────┤
│ ENRICHMENT     Protocol · Reverse DNS · GeoIP            │
├──────────────────────────────────────────────────────────┤
│ ACQUISITION    Socket-table poller  │  Active CIDR scan  │
└──────────────────────────────────────────────────────────┘
```

Each layer depends only on the one below and communicates through a narrow interface. `capture.Capturer` is the clearest example — an interface with `Start`/`Stop`/`Name` that the unimplemented `pcap` mode is designed to satisfy without any change above the acquisition layer. That the byte-oriented metrics and panels already exist and read zero is evidence the seam is real: only the bottom layer needs replacing to populate them.

**Process topology.** `dashboard.Run` launches seven concurrent activities — capture, enrichment, batched storage, anomaly analysis, anomaly persistence, gauge collection, materialised-view refresh — plus an HTTP server, all coordinated by channels and a single cancellable context. One `Ctrl+C` propagates cancellation to every goroutine, each of which flushes and exits.

**Deployment asymmetry.** Postgres, Prometheus and Grafana run in Docker; the scanner runs natively. This is not inconsistency — it is the layer boundary made physical. Off-the-shelf stateful infrastructure benefits from containerisation (reproducibility, version pinning, clean teardown). The scanner cannot be containerised, because a container has its own network namespace: it would observe the *container's* socket table, which is empty, rather than the host's. The rule is *containers for infrastructure, native execution for anything requiring genuine host visibility*.

---

## 4. Technology stack, justified

| Layer | Technology | Theory it implements | Why over the alternative |
|---|---|---|---|
| Language | **Go 1.25** | CSP concurrency | Channels and goroutines are language primitives, not a library. Python's GIL prevents true CPU parallelism and its async model would require rewriting the pipeline around an event loop. Go also compiles to a single static binary — no runtime to install on a monitored host. |
| Scan concurrency | **golang.org/x/sync** (`errgroup`, `semaphore`) | Admission control; structured concurrency | `errgroup` propagates the first error and cancels siblings, giving structured lifetimes. Hand-rolling with `WaitGroup` + channels reimplements this, badly. |
| ICMP | **pro-bing** (unprivileged) | One-sided liveness oracle | Uses datagram-based ICMP, so no `CAP_NET_RAW`/Administrator. Raw sockets would enable SYN scanning but impose elevation on every run (§2.3). |
| DB driver | **pgx v5** + `pgxpool` | Batch amortisation | Native `COPY` support, which `database/sql` does not expose. Connection pooling amortises TCP+TLS+auth setup. Chosen over an ORM because the queries are analytical (CTEs, `FULL OUTER JOIN`, window functions) — exactly what ORMs express worst. |
| Database | **PostgreSQL** | Relational algebra; precomputation | First-class network types (`INET`, `CIDR`) with native containment operators, plus materialised views and `JSONB`. SQLite has no concurrent-writer story; a time-series DB alone could not express the `FULL OUTER JOIN` drift query. |
| Metrics | **prometheus/client_golang** | Counter/gauge semantics | Enforces the type distinction at the API level, so `rate()` is always valid on a counter. |
| Metrics store | **Prometheus** | Pull-based collection | Pulling means the scrape target is also a health check — an unreachable exporter is visibly `up == 0` rather than silently quiet, which is how push models (StatsD/Graphite) fail. Prometheus also owns the retention/downsampling policy centrally. |
| Geolocation | **maxminddb-golang** + GeoLite2 | Locality-of-reference | A memory-mapped binary trie giving microsecond lookups with no network dependency. A geolocation *API* would add a network round-trip to the hot path, impose rate limits, and leak every destination IP to a third party. |
| Dashboards | **Grafana** (dual datasource) | Cardinality separation (§2.11) | Queries Prometheus and Postgres in one dashboard, which is what makes the split viable: low-cardinality velocity from Prometheus, high-cardinality detail from SQL. |
| Provisioning | **Grafana file provisioning** | Infrastructure as code | Datasources and dashboards are version-controlled JSON, so the visualisation layer is reproducible and reviewable rather than click-configured. |
| Logging | **log/slog** (stdlib) | Structured logging | Machine-parseable JSON with typed key-value pairs. Stdlib since Go 1.21 — no dependency. |
| Infrastructure | **Docker** | Reproducibility, isolation | Version-pinned stateful services, clean teardown, no host pollution (§3). |

---

## 5. How the layers connect

The clearest way to see the whole system is to follow **one connection** from the operating system to a pixel on the map.

**The scenario.** Your browser opens an HTTPS connection to `142.250.185.78:443` (a Google server in Mountain View).

| # | Where | What happens |
|---|---|---|
| 1 | **Windows kernel** | The TCP handshake completes. The socket enters state 5 (ESTABLISHED) in the kernel's connection table, tagged with the owning PID. |
| 2 | [`poller.go`](../internal/capture/poller.go) → PowerShell | Within 5 s the ticker fires. `Get-NetTCPConnection \| Where-Object State -eq 5` joined against `Get-Process` returns the connection *with its process name* — telemetry a packet sniffer cannot produce (§2.4). |
| 3 | [`trimBOM`](../internal/capture/poller.go#L198) → `json.Unmarshal` | PowerShell's UTF-8/UTF-16 byte-order mark is stripped; without this the payload is invalid JSON and the whole snapshot is discarded. |
| 4 | [`isLocalIP`](../internal/capture/poller.go#L190) | `142.250.185.78` is public, so it survives the loopback/RFC1918/link-local filter. A connection to `192.168.1.1` would be dropped here. |
| 5 | [`flowKey`](../internal/capture/poller.go#L174) | Key `192.168.1.10:142.250.185.78:443:TCP`. First sighting, so it is emitted; on the next tick the same key is suppressed (§2.5). |
| 6 | **channel** | A `FlowRecord` crosses into `enrichLoop` — ownership transfers, no lock (§2.12). |
| 7 | [`IdentifyProtocol`](../internal/enrichment/protocol.go#L34) | Port 443 → `HTTPS`. A convention-based inference, not an observation (§2.7). |
| 8 | [`DNSResolver.Resolve`](../internal/enrichment/dns.go) | PTR lookup → hostname, cached with a TTL. Subsequent flows to this IP skip the network entirely (§2.13). |
| 9 | [`GeoEnricher.Lookup`](../internal/enrichment/geoip.go) | MaxMind trie → `US`, `North America`, `37.42, −122.08`. Microseconds, no network call. |
| 10 | [`metrics/registry.go`](../internal/metrics/registry.go) | `flows_total{protocol="HTTPS", capture_mode="poller"}` increments. `bytes_total` increments by **zero** — the socket table carries no volume (§6.2). |
| 11 | **channel** → `storeLoop` | Buffered into a batch. Flushed at 500 rows or 5 s (§2.14). |
| 12 | [`InsertFlows`](../internal/storage/store.go) | The batch streams into `traffic_flows` via `COPY` — one operation for the whole batch. |
| 13 | [`anomaly/detector.go`](../internal/anomaly/detector.go) | Once a minute, recent flows are re-read from the DB. Is `142.250.185.78` new in 24 h? Almost certainly not, so no event. Byte spike? Baseline is 0, so never (§2.9). |
| 14 | [`metrics/collector.go`](../internal/metrics/collector.go) | Every 30 s, `COUNT(DISTINCT dst_ip)` over the last 5 minutes sets `unique_destinations`. This connection is now part of that set. |
| 15 | **Prometheus** | Every 15 s it scrapes `:9090/metrics`, appending each sample to its time-series store. |
| 16 | **Grafana / Prometheus panels** | `sum by (protocol) (rate(net_scanner_traffic_flows_total[1m]))` renders the HTTPS connection rate — the counter's derivative, not its value (§2.11). |
| 17 | **Grafana / Postgres panels** | `SELECT country_name, latitude, longitude, COUNT(DISTINCT dst_ip) … GROUP BY …` places a marker on the United States. High-cardinality detail, deliberately kept out of Prometheus (§2.11). |

**Two independent paths from one event.** Note that steps 15–16 and step 17 read from different stores with different retention, different query languages, and different windows. That is the cardinality separation of §2.11 made concrete: the same connection contributes to a *velocity* signal in Prometheus and a *detail* record in Postgres, and neither store could serve both roles well.

**Where the active scanner joins.** `scan`/`diff` bypass steps 1–12 entirely, writing to `subnets`/`scans`/`hosts` instead. The two halves share only the database — which is what would eventually allow correlating "this host appeared on my network yesterday" with "and it is now talking to an address nobody has ever contacted."

---

## 6. Validity and limitations

Framed as *threats to validity* rather than apologies. Each is a bounded, stated claim about what the system does and does not establish.

### 6.1 Construct validity — does the metric measure what its name says?

**`net_scanner_traffic_active_connections` does not measure active connections.** It is set to `COUNT(*)` of flow records captured in the trailing 30 seconds. Because deduplication suppresses repeat sightings (§2.5), a connection open for an hour contributes to exactly one 30-second window — the one in which it was first seen. The metric therefore measures **recent capture throughput**, not concurrent established sockets.

The defensible phrasing is: *"the number of newly observed external connections in the trailing 30-second window."* The name overstates the construct and should be corrected.

A related point, already made in [ARCHITECTURE.md](../ARCHITECTURE.md#the-key-insight-for-defending-the-dashboard): every headline statistic counts over a *different* window (30 s, 5 m, 5 m, 1 h). Apparently contradictory readings — "Active Connections: 2" beside a map showing 100+ countries — are consistent, because they measure different horizons of the same traffic.

### 6.2 Measurement validity — byte accounting is structurally zero

`Get-NetTCPConnection` reports *who* and *which port*. It does not report bytes transferred. The poller therefore hardcodes `BytesSent = 0`, `BytesRecv = 0`, `Packets = 1`.

The consequences, stated plainly:

- Every byte-based Prometheus counter is permanently 0.
- Six Grafana panels (Total Bytes, Bandwidth Over Time, Protocol Breakdown by bytes, Top Countries by bytes, Traffic by Continent, and the byte columns of Top Destinations / Port Breakdown) render as zero or empty.
- **Spike detection can never fire**, since the baseline and the observation are both 0.
- The world map is sized by *unique IP count* rather than bytes specifically to work around this — a real number substituted for an unavailable one.

This is a property of the data source, not a defect in the code that consumes it. Volume accounting requires observing packets, which requires packet capture. `TestSpikeRuleAgainstZeroBaseline` encodes the consequence as an executable assertion so the limitation cannot silently drift.

### 6.3 Coverage — what is systematically invisible

| Blind spot | Cause | Section |
|---|---|---|
| Connections shorter than the poll interval | Discrete sampling | §2.6 |
| All UDP traffic, including DNS | Only `Get-NetTCPConnection` is called | §2.4 |
| ICMP traffic | Same | §2.4 |
| Failed / refused connection attempts | Only ESTABLISHED (state 5) is read | §2.4 |
| Multiple connections to the same service | 4-tuple deduplication | §2.5 |
| Services on non-standard ports | Port-based protocol inference | §2.7 |
| Non-Windows hosts | PowerShell dependency | — |
| Hosts running only unprobed ports | Four-port convenience sample | §2.2 |

### 6.4 Unexercised surface

Declared but not reached by any code path. Named here so they are not mistaken for working features:

- `traffic_aggregates` — table created by migration, never written or read.
- `geo_cache` — read by the anomaly detector for country annotation, but never populated, so that lookup always misses. GeoIP enrichment queries the MaxMind database directly instead.
- `flow_duration_seconds` — histogram registered but never observed. The poller has no connection-teardown detection, so duration is unmeasurable in this mode.
- `new_country` — an anomaly type named in the `Event` documentation and the SQL column comment, never implemented.
- `Store.InsertAnomalyEvent`, `Detector.Events()`, `Capturer.Stop()` — defined but never called; shutdown relies on context cancellation alone.
- `NS_PCAP_INTERFACE`, `NS_PCAP_BPF`, `NS_PCAP_FLUSH_INTERVAL` — configuration for the unimplemented capture mode.

### 6.5 Security posture

- **Plaintext credentials.** `grafana/provisioning/datasources/datasources.yml` commits the Postgres password `devpw`. Acceptable for a local development database with no real data; unacceptable for any deployment. Environment-variable interpolation is the standard fix.
- **Legal and ethical scope of active scanning.** `scan` transmits unsolicited probes to every address in the target range. Doing so against networks you do not own or have written authorisation to test is unlawful in most jurisdictions. The tool has no built-in restriction to private ranges — restraint is the operator's responsibility.
- **Passive mode is non-intrusive** and observes only the host it runs on, but the resulting database is a detailed log of that host's external communications, which is sensitive by nature.

### 6.6 Verification status

At this milestone the project has **18 test functions covering 148 cases across six packages**, all passing. They cover the pure, deterministic logic: CIDR enumeration and address increment, protocol identification, the rolling-average baseline and its zero-baseline consequence, BOM stripping, local-address classification, flow-key identity, and configuration parsing with its fail-soft fallbacks.

What is **not** covered, and should be stated rather than implied:

- No integration tests — nothing exercises the database, the PowerShell invocation, the HTTP handlers, or the goroutine topology end-to-end.
- No test asserts the correctness of the `diff` SQL against a live database; the fix in §2.8 is reasoned from SQL semantics, not empirically confirmed here.
- No property-based or fuzz testing.
- No continuous integration — tests run only when invoked manually.

---

## Appendix: anticipated defence questions

**"Why not just use Wireshark, Zeek, or ntopng?"**
Those are packet-capture tools and would give richer data — real byte counts, protocol dissection, TLS metadata. Three things justify building this instead. First, **process attribution**: none of them can tell you which local process owns a connection, because that information does not exist on the wire (§2.4). Second, **integration**: the objective is a single system spanning active discovery and passive monitoring over a shared schema, which is an integration problem those tools do not solve. Third, **pedagogy**: implementing flow deduplication, threshold detection, and metric semantics from primitives demonstrates understanding that configuring a tool does not.

**"Why is there no machine learning?"**
Deliberate, for three reasons. There is **no labelled data** — supervised learning needs known-malicious traffic for this network, which does not exist. The **feature space is currently degenerate** — with byte counts structurally zero (§6.2), the available features are destination, port, process and time; a model over those would be learning very little. And ML would be **premature**: the correct sequence is establish reliable measurement, understand the baseline, then model. Unsupervised approaches (clustering for peer-group anomalies, autoencoder reconstruction error) become appropriate once volume data exists. Note also that the current detectors are not unprincipled — §2.9 and §2.10 identify them as a moving-average threshold detector and a one-class novelty detector respectively, both standard techniques with known trade-offs.

**"How do you know the data is correct?"**
Layered, and honestly bounded. Unit tests cover the deterministic logic (§6.6). The capture source is the operating system's own connection table, which is authoritative for what it reports. Cross-validation is possible: `netstat -ano` should agree with what the poller sees, and destinations can be spot-checked against `nslookup` and an independent geolocation service. But the honest answer is that **correctness of individual records is well-supported while completeness is not** — §2.6 and §6.3 bound exactly what the system cannot see, and no test can establish the absence of data that was never sampled.

**"Why isn't the scanner containerised when everything else is?"**
Because a container has its own network namespace. Inside one, `Get-NetTCPConnection` would enumerate the container's socket table — effectively empty — rather than the host's, and the active scanner would probe from the container's network position rather than the host's. The rule applied is *containers for stateful infrastructure, native execution for anything requiring genuine host visibility* (§3, and [ARCHITECTURE.md](../ARCHITECTURE.md#why-three-docker-containers)).

**"Your dashboard shows 2 active connections but the map shows 100+ destinations. Isn't that contradictory?"**
No — they measure different windows. `active_connections` counts flow records in the trailing 30 seconds; the map counts distinct destination IPs over the last hour. Thirty seconds of newly-observed connections against an hour of accumulated distinct destinations. That said, the metric is misnamed and does not measure concurrent sockets at all — see §6.1, where I state the problem rather than defend the name.

**"Why poll every 5 seconds rather than 1, or 30?"**
It is a bias-cost trade with no optimum, only a position on a curve. Each poll spawns a PowerShell process — expensive on Windows — so 1-second polling multiplies overhead fivefold to shrink but not close the blind spot. Thirty seconds would make the tool blind to nearly everything but persistent sessions. Five seconds captures sustained connections reliably while keeping overhead negligible, and the value is configurable via `NS_POLL_INTERVAL`. The principled point is that no interval eliminates the aliasing (§2.6) — only a different capture method does.

**"What is the single biggest weakness?"**
The absence of byte-volume data (§6.2). It is not merely a missing column: it disables spike detection entirely, empties six dashboard panels, and removes the most informative feature any future analysis would use. Everything downstream of it is built and tested, which is why replacing the acquisition layer — the seam described in §3 — is the change with by far the highest leverage.
