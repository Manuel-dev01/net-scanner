package storage

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnrichedFlow is a flow record with all enrichment data attached.
type EnrichedFlow struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	DstPort     int
	Protocol    string
	BytesSent   int64
	BytesRecv   int64
	Packets     int
	ProcessName string
	Hostname    string
	CountryCode string
	CountryName string
	Continent   string
	Latitude    float64
	Longitude   float64
	CaptureMode string
}

// Store handles database operations for traffic data.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// InsertFlows batch-inserts enriched flows using COPY for efficiency.
func (s *Store) InsertFlows(ctx context.Context, flows []EnrichedFlow) error {
	if len(flows) == 0 {
		return nil
	}

	rows := make([][]interface{}, 0, len(flows))
	for _, f := range flows {
		rows = append(rows, []interface{}{
			f.Timestamp,
			f.SrcIP,
			f.DstIP,
			zeroIfNeg(f.DstPort),
			f.Protocol,
			f.BytesSent,
			f.BytesRecv,
			f.Packets,
			nullIfEmpty(f.ProcessName),
			nullIfEmpty(f.Hostname),
			nullIfEmpty(f.CountryCode),
			nullIfEmpty(f.CountryName),
			nullIfEmpty(f.Continent),
			f.Latitude,
			f.Longitude,
			f.CaptureMode,
		})
	}

	_, err := s.pool.CopyFrom(
		ctx,
		pgx.Identifier{"traffic_flows"},
		[]string{
			"captured_at", "src_ip", "dst_ip", "dst_port", "protocol",
			"bytes_sent", "bytes_recv", "packets", "process_name",
			"dst_hostname", "country_code", "country_name", "continent",
			"latitude", "longitude", "capture_mode",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		slog.Error("Failed to batch insert flows", "count", len(flows), "error", err)
		return err
	}
	return nil
}

// InsertAnomalyEvent writes an anomaly event to the database.
func (s *Store) InsertAnomalyEvent(ctx context.Context, eventType, severity, description string, metadata []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO anomaly_events (event_type, severity, description, metadata)
		VALUES ($1, $2, $3, $4);`,
		eventType, severity, description, metadata,
	)
	return err
}

// RefreshMaterializedViews refreshes the protocol and geo breakdown views.
func (s *Store) RefreshMaterializedViews(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_protocol_breakdown;")
	if err != nil {
		slog.Warn("Failed to refresh mv_protocol_breakdown", "error", err)
	}
	_, err = s.pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_geo_breakdown;")
	if err != nil {
		slog.Warn("Failed to refresh mv_geo_breakdown", "error", err)
	}
	return nil
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func zeroIfNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
