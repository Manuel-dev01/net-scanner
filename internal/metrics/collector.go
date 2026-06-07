package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Collector periodically queries the database to update gauge metrics
// that can't be derived from the streaming pipeline alone.
type Collector struct {
	pool     *pgxpool.Pool
	interval time.Duration
}

// NewCollector creates a new metrics collector.
func NewCollector(pool *pgxpool.Pool, interval time.Duration) *Collector {
	if interval == 0 {
		interval = 30 * time.Second
	}
	return &Collector{pool: pool, interval: interval}
}

// Run blocks and periodically updates gauges. Cancel ctx to stop.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

func (c *Collector) collect(ctx context.Context) {
	// Unique destinations in last 5 minutes
	var uniqueDests int
	err := c.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT dst_ip) FROM traffic_flows
		WHERE captured_at > now() - INTERVAL '5 minutes';`).Scan(&uniqueDests)
	if err != nil {
		slog.Warn("Failed to query unique destinations", "error", err)
	} else {
		UniqueDestinations.Set(float64(uniqueDests))
	}

	// Unique countries in last 5 minutes
	var uniqueCountries int
	err = c.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT country_code) FROM traffic_flows
		WHERE captured_at > now() - INTERVAL '5 minutes'
		AND country_code IS NOT NULL;`).Scan(&uniqueCountries)
	if err != nil {
		slog.Warn("Failed to query unique countries", "error", err)
	} else {
		UniqueCountries.Set(float64(uniqueCountries))
	}

	// Active connections (flows in last interval)
	var activeConns int
	err = c.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM traffic_flows
		WHERE captured_at > now() - $1::interval;`, c.interval.String()).Scan(&activeConns)
	if err != nil {
		slog.Warn("Failed to query active connections", "error", err)
	} else {
		ActiveConnections.Set(float64(activeConns))
	}
}
