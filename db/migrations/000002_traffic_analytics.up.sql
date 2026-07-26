-- Core flow records (one row per observed connection or packet summary)
CREATE TABLE IF NOT EXISTS traffic_flows (
    id              BIGSERIAL PRIMARY KEY,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    dst_port        INT,
    protocol        TEXT NOT NULL,           -- 'TCP', 'UDP', 'ICMP', 'OTHER'
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    bytes_recv      BIGINT NOT NULL DEFAULT 0,
    packets         INT NOT NULL DEFAULT 0,
    process_name    TEXT,                    -- from poller mode, nullable in pcap mode
    dst_hostname    TEXT,                    -- reverse DNS result
    country_code    CHAR(2),                -- ISO 3166-1 alpha-2
    country_name    TEXT,
    continent       TEXT,
    latitude        DOUBLE PRECISION,
    longitude       DOUBLE PRECISION,
    capture_mode    TEXT NOT NULL DEFAULT 'poller'  -- 'poller' or 'pcap'
);

CREATE INDEX IF NOT EXISTS idx_traffic_flows_captured_at ON traffic_flows (captured_at);
CREATE INDEX IF NOT EXISTS idx_traffic_flows_dst_ip ON traffic_flows (dst_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_flows_country_code ON traffic_flows (country_code);
CREATE INDEX IF NOT EXISTS idx_traffic_flows_protocol ON traffic_flows (protocol);
CREATE INDEX IF NOT EXISTS idx_traffic_flows_dst_port ON traffic_flows (dst_port);

-- Aggregated stats per 1-minute window (populated by periodic job)
CREATE TABLE IF NOT EXISTS traffic_aggregates (
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    dst_ip          INET NOT NULL,
    dst_port        INT,
    protocol        TEXT NOT NULL,
    country_code    CHAR(2),
    continent       TEXT,
    total_bytes     BIGINT NOT NULL DEFAULT 0,
    total_packets   INT NOT NULL DEFAULT 0,
    connection_count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (window_start, dst_ip, dst_port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_traffic_aggregates_window ON traffic_aggregates (window_start);

-- Known destinations cache (avoids repeated GeoIP lookups)
CREATE TABLE IF NOT EXISTS geo_cache (
    ip              INET PRIMARY KEY,
    country_code    CHAR(2),
    country_name    TEXT,
    continent       TEXT,
    latitude        DOUBLE PRECISION,
    longitude       DOUBLE PRECISION,
    resolved_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Anomaly events log
CREATE TABLE IF NOT EXISTS anomaly_events (
    id              BIGSERIAL PRIMARY KEY,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      TEXT NOT NULL,           -- 'spike', 'new_destination', 'new_country'
    severity        TEXT NOT NULL DEFAULT 'info',  -- 'info', 'warning', 'critical'
    description     TEXT NOT NULL,
    metadata        JSONB,
    acknowledged    BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_detected_at ON anomaly_events (detected_at);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_type ON anomaly_events (event_type);

-- Materialized view for protocol breakdown (refreshed periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_protocol_breakdown AS
SELECT
    date_trunc('minute', captured_at) AS window,
    protocol,
    dst_port,
    COUNT(*) AS connection_count,
    SUM(bytes_sent + bytes_recv) AS total_bytes
FROM traffic_flows
WHERE captured_at > now() - INTERVAL '24 hours'
GROUP BY 1, 2, 3
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_protocol_breakdown ON mv_protocol_breakdown ("window", protocol, dst_port);

-- Materialized view for geo breakdown (refreshed periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_geo_breakdown AS
SELECT
    date_trunc('minute', captured_at) AS window,
    country_code,
    country_name,
    continent,
    latitude,
    longitude,
    COUNT(DISTINCT dst_ip) AS unique_ips,
    SUM(bytes_sent + bytes_recv) AS total_bytes,
    COUNT(*) AS connection_count
FROM traffic_flows
WHERE captured_at > now() - INTERVAL '24 hours'
    AND country_code IS NOT NULL
GROUP BY 1, 2, 3, 4, 5, 6
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_geo_breakdown ON mv_geo_breakdown ("window", country_code);
