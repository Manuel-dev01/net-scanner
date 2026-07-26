package config

import (
	"testing"
	"time"
)

// The NS_* variables the loader reads. Setting each to the empty string is
// equivalent to leaving it unset, because every helper treats "" as absent.
var allEnvKeys = []string{
	"NS_DB_URL", "NS_CAPTURE_MODE", "NS_POLL_INTERVAL",
	"NS_PCAP_INTERFACE", "NS_PCAP_BPF", "NS_PCAP_FLUSH_INTERVAL",
	"NS_GEOIP_DB_PATH", "NS_DNS_TTL", "NS_METRICS_PORT",
	"NS_AGG_INTERVAL", "NS_EXCLUDE_LOCAL",
}

// clearEnv blanks every NS_* variable for the duration of the test. t.Setenv
// restores the previous values automatically, so a developer's real environment
// cannot make these tests pass or fail spuriously.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range allEnvKeys {
		t.Setenv(k, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	cfg := Load()

	if want := "postgres://postgres:devpw@localhost:5433/scanner_db?sslmode=disable"; cfg.DatabaseURL != want {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, want)
	}
	if cfg.CaptureMode != "poller" {
		t.Errorf("CaptureMode = %q, want \"poller\"", cfg.CaptureMode)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", cfg.PollInterval)
	}
	if cfg.PcapFlushInterval != 10*time.Second {
		t.Errorf("PcapFlushInterval = %v, want 10s", cfg.PcapFlushInterval)
	}
	if cfg.DNSTTL != 10*time.Minute {
		t.Errorf("DNSTTL = %v, want 10m", cfg.DNSTTL)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
	if cfg.AggInterval != time.Minute {
		t.Errorf("AggInterval = %v, want 1m", cfg.AggInterval)
	}
	if !cfg.ExcludeLocal {
		t.Error("ExcludeLocal = false, want true (local traffic excluded by default)")
	}
	if cfg.GeoIPDBPath != "" {
		t.Errorf("GeoIPDBPath = %q, want \"\" (geolocation disabled unless configured)", cfg.GeoIPDBPath)
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv("NS_DB_URL", "postgres://user:pw@db.example.com:5432/prod?sslmode=require")
	t.Setenv("NS_CAPTURE_MODE", "pcap")
	t.Setenv("NS_POLL_INTERVAL", "250ms")
	t.Setenv("NS_PCAP_INTERFACE", "eth0")
	t.Setenv("NS_PCAP_BPF", "tcp port 443")
	t.Setenv("NS_PCAP_FLUSH_INTERVAL", "2s")
	t.Setenv("NS_GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb")
	t.Setenv("NS_DNS_TTL", "1h")
	t.Setenv("NS_METRICS_PORT", "9099")
	t.Setenv("NS_AGG_INTERVAL", "30s")
	t.Setenv("NS_EXCLUDE_LOCAL", "false")

	cfg := Load()

	if cfg.DatabaseURL != "postgres://user:pw@db.example.com:5432/prod?sslmode=require" {
		t.Errorf("DatabaseURL not read from NS_DB_URL, got %q", cfg.DatabaseURL)
	}
	if cfg.CaptureMode != "pcap" {
		t.Errorf("CaptureMode = %q, want \"pcap\"", cfg.CaptureMode)
	}
	if cfg.PollInterval != 250*time.Millisecond {
		t.Errorf("PollInterval = %v, want 250ms", cfg.PollInterval)
	}
	if cfg.PcapInterface != "eth0" {
		t.Errorf("PcapInterface = %q, want \"eth0\"", cfg.PcapInterface)
	}
	if cfg.PcapBPF != "tcp port 443" {
		t.Errorf("PcapBPF = %q, want \"tcp port 443\"", cfg.PcapBPF)
	}
	if cfg.PcapFlushInterval != 2*time.Second {
		t.Errorf("PcapFlushInterval = %v, want 2s", cfg.PcapFlushInterval)
	}
	if cfg.GeoIPDBPath != "/data/GeoLite2-City.mmdb" {
		t.Errorf("GeoIPDBPath = %q, want \"/data/GeoLite2-City.mmdb\"", cfg.GeoIPDBPath)
	}
	if cfg.DNSTTL != time.Hour {
		t.Errorf("DNSTTL = %v, want 1h", cfg.DNSTTL)
	}
	if cfg.MetricsPort != 9099 {
		t.Errorf("MetricsPort = %d, want 9099", cfg.MetricsPort)
	}
	if cfg.AggInterval != 30*time.Second {
		t.Errorf("AggInterval = %v, want 30s", cfg.AggInterval)
	}
	if cfg.ExcludeLocal {
		t.Error("ExcludeLocal = true, want false")
	}
}

// Malformed values fall back to the default rather than failing startup. This
// is a deliberate fail-soft choice: a typo in one variable degrades that single
// setting instead of taking the whole capture pipeline down.
func TestLoadMalformedValuesFallBackToDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("NS_POLL_INTERVAL", "five-seconds")
	t.Setenv("NS_PCAP_FLUSH_INTERVAL", "10")  // no unit suffix
	t.Setenv("NS_DNS_TTL", "")                // empty is treated as unset
	t.Setenv("NS_METRICS_PORT", "not-a-port")
	t.Setenv("NS_AGG_INTERVAL", "1 minute")   // space makes it unparseable
	t.Setenv("NS_EXCLUDE_LOCAL", "maybe")

	cfg := Load()

	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want the 5s default after a parse failure", cfg.PollInterval)
	}
	if cfg.PcapFlushInterval != 10*time.Second {
		t.Errorf("PcapFlushInterval = %v, want the 10s default after a parse failure", cfg.PcapFlushInterval)
	}
	if cfg.DNSTTL != 10*time.Minute {
		t.Errorf("DNSTTL = %v, want the 10m default", cfg.DNSTTL)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want the 9090 default after a parse failure", cfg.MetricsPort)
	}
	if cfg.AggInterval != time.Minute {
		t.Errorf("AggInterval = %v, want the 1m default after a parse failure", cfg.AggInterval)
	}
	if !cfg.ExcludeLocal {
		t.Error("ExcludeLocal = false, want the `true` default after a parse failure")
	}
}

// ParseBool accepts more spellings than "true"/"false"; these are the ones
// operators actually type.
func TestExcludeLocalAcceptedSpellings(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true}, {"TRUE", true}, {"True", true}, {"1", true}, {"t", true},
		{"false", false}, {"FALSE", false}, {"False", false}, {"0", false}, {"f", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("NS_EXCLUDE_LOCAL", tt.value)
			if got := Load().ExcludeLocal; got != tt.want {
				t.Errorf("NS_EXCLUDE_LOCAL=%q gave ExcludeLocal=%v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
