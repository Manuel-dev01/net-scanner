package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL       string
	CaptureMode       string // "poller" or "pcap"
	PollInterval      time.Duration
	PcapInterface     string
	PcapBPF           string
	PcapFlushInterval time.Duration
	GeoIPDBPath       string
	DNSTTL            time.Duration
	MetricsPort       int
	AggInterval       time.Duration
	ExcludeLocal      bool
}

func Load() *Config {
	cfg := &Config{
		DatabaseURL:       envOrDefault("NS_DB_URL", "postgres://postgres:devpw@localhost:5433/scanner_db?sslmode=disable"),
		CaptureMode:       envOrDefault("NS_CAPTURE_MODE", "poller"),
		PollInterval:      envDuration("NS_POLL_INTERVAL", 5*time.Second),
		PcapInterface:     os.Getenv("NS_PCAP_INTERFACE"),
		PcapBPF:           os.Getenv("NS_PCAP_BPF"),
		PcapFlushInterval: envDuration("NS_PCAP_FLUSH_INTERVAL", 10*time.Second),
		GeoIPDBPath:       os.Getenv("NS_GEOIP_DB_PATH"),
		DNSTTL:            envDuration("NS_DNS_TTL", 10*time.Minute),
		MetricsPort:       envInt("NS_METRICS_PORT", 9090),
		AggInterval:       envDuration("NS_AGG_INTERVAL", 1*time.Minute),
		ExcludeLocal:      envBool("NS_EXCLUDE_LOCAL", true),
	}
	return cfg
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
