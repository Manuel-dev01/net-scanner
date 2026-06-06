CREATE TABLE subnets (
    id          SERIAL PRIMARY KEY,
    cidr        CIDR NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE scans (
    id         BIGSERIAL PRIMARY KEY,
    subnet_id  INT REFERENCES subnets(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at   TIMESTAMPTZ
);

CREATE TABLE hosts (
    id            BIGSERIAL PRIMARY KEY,
    scan_id       BIGINT REFERENCES scans(id) ON DELETE CASCADE,
    ip            INET NOT NULL,
    hostname      TEXT,
    rtt_ms        DOUBLE PRECISION,
    is_up         BOOLEAN NOT NULL,
    open_ports    INT[],
    first_seen_at TIMESTAMPTZ DEFAULT now(),
    last_seen_at  TIMESTAMPTZ DEFAULT now()
);

-- Optimize queries for specific asset discovery and historical lookups
CREATE INDEX ON hosts (ip);
CREATE INDEX ON hosts (scan_id);