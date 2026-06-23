package dashboard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Manuel-dev01/net-scanner/internal/anomaly"
	"github.com/Manuel-dev01/net-scanner/internal/capture"
	"github.com/Manuel-dev01/net-scanner/internal/config"
	"github.com/Manuel-dev01/net-scanner/internal/enrichment"
	"github.com/Manuel-dev01/net-scanner/internal/metrics"
	"github.com/Manuel-dev01/net-scanner/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Run starts the traffic analytics dashboard pipeline.
func Run(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) error {
	// Print startup banner
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║       Network Traffic Analytics Dashboard        ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Printf("  Capture mode : %s\n", cfg.CaptureMode)
	fmt.Printf("  Metrics port : %d\n", cfg.MetricsPort)
	fmt.Printf("  GeoIP DB     : %s\n", geoipStatus(cfg.GeoIPDBPath))
	fmt.Printf("  Poll interval: %s\n", cfg.PollInterval)
	fmt.Println()

	// Initialize capture
	var capturer capture.Capturer
	switch cfg.CaptureMode {
	case "poller":
		capturer = capture.NewPoller(capture.PollerConfig{
			Interval:     cfg.PollInterval,
			ExcludeLocal: cfg.ExcludeLocal,
		})
	case "pcap":
		return fmt.Errorf("pcap mode not yet implemented — use --mode poller")
	default:
		return fmt.Errorf("unknown capture mode: %s", cfg.CaptureMode)
	}

	// Initialize enrichment
	var geoEnricher *enrichment.GeoEnricher
	if cfg.GeoIPDBPath != "" {
		var err error
		geoEnricher, err = enrichment.NewGeoEnricher(cfg.GeoIPDBPath)
		if err != nil {
			slog.Warn("GeoIP enrichment disabled — failed to load database", "error", err)
		} else {
			defer geoEnricher.Close()
			slog.Info("GeoIP enrichment enabled", "path", cfg.GeoIPDBPath)
		}
	}

	dnsResolver := enrichment.NewDNSResolver(cfg.DNSTTL)
	store := storage.NewStore(pool)
	detector := anomaly.NewDetector(pool, anomaly.DefaultThresholds())

	// Start capture
	flowCh, err := capturer.Start(ctx)
	if err != nil {
		return fmt.Errorf("start capture: %w", err)
	}
	slog.Info("Traffic capture started", "mode", capturer.Name())

	// Start enrichment pipeline
	enrichedCh := enrichLoop(ctx, flowCh, geoEnricher, dnsResolver)

	// Start storage writer (batch insert)
	go storeLoop(ctx, enrichedCh, store, capturer.Name())

	// Start anomaly event persister
	go detector.PersistEvents(ctx)

	// Start anomaly analyzer (polls recent flows from the DB)
	go anomalyLoop(ctx, pool, detector)

	// Start metrics collector
	collector := metrics.NewCollector(pool, 30*time.Second)
	go collector.Run(ctx)

	// Start materialized view refresher
	go mvRefreshLoop(ctx, store, cfg.AggInterval)

	// Setup Prometheus
	reg := prometheus.NewRegistry()
	metrics.Register(reg)
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","mode":"%s"}`, capturer.Name())
	})

	addr := fmt.Sprintf(":%d", cfg.MetricsPort)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		slog.Info("HTTP metrics server starting", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Metrics server error", "error", err)
		}
	}()

	fmt.Printf("  ✓ Dashboard running — metrics at http://localhost%s/metrics\n", addr)
	fmt.Println("  ✓ Press Ctrl+C to stop\n")

	// Wait for shutdown
	<-ctx.Done()
	slog.Info("Shutting down dashboard...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)

	return nil
}

// enrichLoop reads raw flows and enriches them with GeoIP, DNS, and protocol data.
func enrichLoop(ctx context.Context, rawFlows <-chan capture.FlowRecord, geo *enrichment.GeoEnricher, dns *enrichment.DNSResolver) <-chan storage.EnrichedFlow {
	out := make(chan storage.EnrichedFlow, 256)

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case flow, ok := <-rawFlows:
				if !ok {
					return
				}

				ef := storage.EnrichedFlow{
					Timestamp:   flow.Timestamp,
					SrcIP:       flow.SrcIP,
					DstIP:       flow.DstIP,
					DstPort:     flow.DstPort,
					Protocol:    flow.Protocol,
					BytesSent:   flow.BytesSent,
					BytesRecv:   flow.BytesRecv,
					Packets:     flow.Packets,
					ProcessName: flow.ProcessName,
					CaptureMode: "poller",
				}

				// Protocol enrichment
				ef.Protocol = enrichment.IdentifyProtocol(flow.DstPort, flow.Protocol)

				// Update Prometheus counters for this flow
				metrics.FlowsTotal.WithLabelValues(ef.Protocol, ef.CaptureMode).Inc()
				metrics.PacketsTotal.WithLabelValues(ef.Protocol).Add(float64(ef.Packets))
				metrics.BytesTotal.WithLabelValues(ef.Protocol, "sent").Add(float64(ef.BytesSent))
				metrics.BytesTotal.WithLabelValues(ef.Protocol, "recv").Add(float64(ef.BytesRecv))

				// DNS enrichment (non-blocking)
				ef.Hostname = dns.Resolve(ctx, flow.DstIP)

				// GeoIP enrichment
				if geo != nil {
					ip := net.ParseIP(flow.DstIP)
					if ip != nil {
						result, err := geo.Lookup(ip)
						if err == nil && result != nil {
							ef.CountryCode = result.CountryCode
							ef.CountryName = result.CountryName
							ef.Continent = result.Continent
							ef.Latitude = result.Latitude
							ef.Longitude = result.Longitude
						}
					}
				}

				select {
				case out <- ef:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return out
}

// storeLoop batches enriched flows and inserts them into the database.
func storeLoop(ctx context.Context, enrichedCh <-chan storage.EnrichedFlow, store *storage.Store, captureMode string) {
	batch := make([]storage.EnrichedFlow, 0, 500)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining
			if len(batch) > 0 {
				store.InsertFlows(ctx, batch)
			}
			return
		case ef, ok := <-enrichedCh:
			if !ok {
				if len(batch) > 0 {
					store.InsertFlows(ctx, batch)
				}
				return
			}
			batch = append(batch, ef)
			if len(batch) >= 500 {
				store.InsertFlows(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				store.InsertFlows(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// anomalyLoop periodically pulls recent flows from the DB and runs anomaly
// detection on them. A DB-based approach is used (rather than tapping flowCh)
// because the raw flow channel is already fully consumed by enrichLoop.
func anomalyLoop(ctx context.Context, pool *pgxpool.Pool, detector *anomaly.Detector) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flows, err := recentFlows(ctx, pool, time.Minute)
			if err != nil {
				slog.Warn("Anomaly detection: failed to load recent flows", "error", err)
				continue
			}
			detector.Analyze(ctx, flows)
		}
	}
}

// recentFlows loads flows captured within the given look-back window for analysis.
func recentFlows(ctx context.Context, pool *pgxpool.Pool, window time.Duration) ([]capture.FlowRecord, error) {
	rows, err := pool.Query(ctx, `
		SELECT src_ip, dst_ip, dst_port, protocol, bytes_sent, bytes_recv, packets
		FROM traffic_flows
		WHERE captured_at > now() - $1::interval;`, window.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var flows []capture.FlowRecord
	for rows.Next() {
		var f capture.FlowRecord
		if err := rows.Scan(&f.SrcIP, &f.DstIP, &f.DstPort, &f.Protocol, &f.BytesSent, &f.BytesRecv, &f.Packets); err != nil {
			return nil, err
		}
		flows = append(flows, f)
	}
	return flows, rows.Err()
}

// mvRefreshLoop periodically refreshes materialized views.
func mvRefreshLoop(ctx context.Context, store *storage.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial refresh
	store.RefreshMaterializedViews(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			store.RefreshMaterializedViews(ctx)
		}
	}
}

func geoipStatus(path string) string {
	if path == "" {
		return "disabled (set NS_GEOIP_DB_PATH to enable)"
	}
	return path
}
