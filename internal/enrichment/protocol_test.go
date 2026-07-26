package enrichment

import "testing"

// IdentifyProtocol infers the application-layer protocol from the destination
// port alone -- a convention-based heuristic over the IANA registry, not deep
// packet inspection. A service on a non-standard port is therefore reported as
// its transport, which these cases pin down explicitly.
func TestIdentifyProtocol(t *testing.T) {
	tests := []struct {
		name      string
		port      int
		transport string
		want      string
	}{
		{"https", 443, "TCP", "HTTPS"},
		{"http", 80, "TCP", "HTTP"},
		{"ssh", 22, "TCP", "SSH"},
		{"dns", 53, "UDP", "DNS"},
		{"postgres", 5432, "TCP", "PostgreSQL"},
		{"prometheus", 9090, "TCP", "Prometheus"},
		{"mongodb", 27017, "TCP", "MongoDB"},

		// Unregistered ports fall back to the transport name. This is the
		// heuristic's blind spot: a web server on 8081 is indistinguishable
		// from any other TCP service.
		{"unregistered port falls back to transport", 8081, "TCP", "TCP"},
		{"ephemeral port falls back to transport", 54321, "TCP", "TCP"},
		{"zero port falls back to transport", 0, "TCP", "TCP"},
		{"fallback preserves UDP transport", 12345, "UDP", "UDP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IdentifyProtocol(tt.port, tt.transport); got != tt.want {
				t.Errorf("IdentifyProtocol(%d, %q) = %q, want %q", tt.port, tt.transport, got, tt.want)
			}
		})
	}
}

// IdentifyService differs from IdentifyProtocol only in its fallback: it has no
// transport to fall back to, so it reports "unknown".
func TestIdentifyService(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{443, "HTTPS"},
		{22, "SSH"},
		{3389, "RDP"},
		{8081, "unknown"},
		{0, "unknown"},
	}

	for _, tt := range tests {
		if got := IdentifyService(tt.port); got != tt.want {
			t.Errorf("IdentifyService(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}
