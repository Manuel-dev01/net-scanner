package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// Counters
	FlowsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "net_scanner",
			Subsystem: "traffic",
			Name:      "flows_total",
			Help:      "Total number of captured flow records",
		},
		[]string{"protocol", "capture_mode"},
	)

	BytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "net_scanner",
			Subsystem: "traffic",
			Name:      "bytes_total",
			Help:      "Total bytes captured",
		},
		[]string{"protocol", "direction"},
	)

	PacketsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "net_scanner",
			Subsystem: "traffic",
			Name:      "packets_total",
			Help:      "Total packets captured",
		},
		[]string{"protocol"},
	)

	AnomaliesDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "net_scanner",
			Subsystem: "anomaly",
			Name:      "events_total",
			Help:      "Total anomaly events detected",
		},
		[]string{"event_type", "severity"},
	)

	// Gauges
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "net_scanner",
			Subsystem: "traffic",
			Name:      "active_connections",
			Help:      "Current number of active tracked connections",
		},
	)

	UniqueDestinations = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "net_scanner",
			Subsystem: "traffic",
			Name:      "unique_destinations",
			Help:      "Number of unique destination IPs in the last window",
		},
	)

	UniqueCountries = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "net_scanner",
			Subsystem: "geo",
			Name:      "unique_countries",
			Help:      "Number of unique destination countries in the last window",
		},
	)

	// Histograms
	FlowDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "net_scanner",
			Subsystem: "traffic",
			Name:      "flow_duration_seconds",
			Help:      "Duration of captured flows in seconds",
			Buckets:   []float64{0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 600},
		},
	)
)

// Register registers all metrics with the given registerer.
func Register(reg prometheus.Registerer) {
	reg.MustRegister(
		FlowsTotal,
		BytesTotal,
		PacketsTotal,
		AnomaliesDetected,
		ActiveConnections,
		UniqueDestinations,
		UniqueCountries,
		FlowDuration,
	)
}
