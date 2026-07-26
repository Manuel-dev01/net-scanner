package anomaly

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/Manuel-dev01/net-scanner/internal/capture"
	"github.com/Manuel-dev01/net-scanner/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event represents an anomaly detection event.
type Event struct {
	Type        string // "spike", "new_destination", "new_country"
	Severity    string // "info", "warning", "critical"
	Description string
	Metadata    map[string]interface{}
}

// Thresholds configures anomaly detection sensitivity.
type Thresholds struct {
	BytesPerMinuteSpike float64       // multiplier over rolling average to trigger spike
	NewDestWindow       time.Duration // look-back window for "new" destination detection
}

// DefaultThresholds returns sensible defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		BytesPerMinuteSpike: 2.0,
		NewDestWindow:       24 * time.Hour,
	}
}

// Detector watches flow records and emits anomaly events.
type Detector struct {
	pool       *pgxpool.Pool
	events     chan Event
	thresholds Thresholds

	// Rolling window for spike detection
	windowMu    sync.Mutex
	byteWindows []float64 // bytes per window, last N entries
	windowSize  int
}

// NewDetector creates a new anomaly detector.
func NewDetector(pool *pgxpool.Pool, thresholds Thresholds) *Detector {
	if thresholds.BytesPerMinuteSpike == 0 {
		thresholds = DefaultThresholds()
	}
	// Pre-initialize the known anomaly series to 0 so the metric is exported
	// (and the dashboard reads 0) before the first event fires, rather than
	// being absent and showing "No data".
	for _, c := range [][2]string{{"spike", "warning"}, {"new_destination", "info"}} {
		metrics.AnomaliesDetected.WithLabelValues(c[0], c[1]).Add(0)
	}
	return &Detector{
		pool:        pool,
		events:      make(chan Event, 64),
		thresholds:  thresholds,
		byteWindows: make([]float64, 0, 10),
		windowSize:  10,
	}
}

// Events returns the channel of anomaly events.
func (d *Detector) Events() <-chan Event {
	return d.events
}

// Analyze checks a batch of flows for anomalies. Call this periodically.
func (d *Detector) Analyze(ctx context.Context, flows []capture.FlowRecord) {
	if len(flows) == 0 {
		return
	}

	// Spike detection: sum bytes in this batch
	var totalBytes float64
	for _, f := range flows {
		totalBytes += float64(f.BytesSent + f.BytesRecv)
	}

	d.windowMu.Lock()
	d.byteWindows = append(d.byteWindows, totalBytes)
	if len(d.byteWindows) > d.windowSize {
		d.byteWindows = d.byteWindows[1:]
	}
	avg := rollingAverage(d.byteWindows)
	d.windowMu.Unlock()

	if avg > 0 && totalBytes > avg*d.thresholds.BytesPerMinuteSpike {
		d.emit(Event{
			Type:     "spike",
			Severity: "warning",
			Description: "Traffic spike detected",
			Metadata: map[string]interface{}{
				"bytes_this_window": totalBytes,
				"rolling_average":   avg,
				"multiplier":        totalBytes / avg,
			},
		})
	}

	// New destination detection
	d.checkNewDestinations(ctx, flows)
}

func (d *Detector) checkNewDestinations(ctx context.Context, flows []capture.FlowRecord) {
	// Collect unique destination IPs from this batch
	dests := make(map[string]bool)
	for _, f := range flows {
		dests[f.DstIP] = true
	}

	for dstIP := range dests {
		var count int
		err := d.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM traffic_flows
			WHERE dst_ip = $1 AND captured_at > now() - $2::interval;`,
			dstIP, d.thresholds.NewDestWindow.String(),
		).Scan(&count)
		if err != nil {
			continue
		}

		// If this is the first time we've seen this destination (count will be 0 or 1
		// because the current batch may not be inserted yet)
		if count <= 1 {
			// Check if it's in geo_cache for country info
			var countryCode *string
			d.pool.QueryRow(ctx, `SELECT country_code FROM geo_cache WHERE ip = $1;`, dstIP).Scan(&countryCode)

			desc := "New destination detected: " + dstIP
			meta := map[string]interface{}{"dst_ip": dstIP}
			if countryCode != nil {
				meta["country_code"] = *countryCode
				desc += " (" + *countryCode + ")"
			}

			d.emit(Event{
				Type:        "new_destination",
				Severity:    "info",
				Description: desc,
				Metadata:    meta,
			})
		}
	}
}

func (d *Detector) emit(evt Event) {
	select {
	case d.events <- evt:
		metrics.AnomaliesDetected.WithLabelValues(evt.Type, evt.Severity).Inc()
		slog.Info("Anomaly detected", "type", evt.Type, "severity", evt.Severity, "description", evt.Description)
	default:
		// Channel full, drop event
		slog.Warn("Anomaly event channel full, dropping event", "type", evt.Type)
	}
}

// PersistEvents reads from the events channel and writes to the database.
func (d *Detector) PersistEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-d.events:
			if !ok {
				return
			}
			metaBytes, _ := json.Marshal(evt.Metadata)
			_, err := d.pool.Exec(ctx, `
				INSERT INTO anomaly_events (event_type, severity, description, metadata)
				VALUES ($1, $2, $3, $4);`,
				evt.Type, evt.Severity, evt.Description, metaBytes,
			)
			if err != nil {
				slog.Error("Failed to persist anomaly event", "error", err)
			}
		}
	}
}

func rollingAverage(values []float64) float64 {
	if len(values) <= 1 {
		return 0
	}
	// Exclude the last value (current) from the average
	sum := 0.0
	for _, v := range values[:len(values)-1] {
		sum += v
	}
	return sum / float64(len(values)-1)
}
