package capture

import (
	"testing"
	"time"
)

// trimBOM strips the byte-order marks PowerShell prepends to its output. Left
// in place they make the payload invalid JSON and the whole snapshot is
// discarded, so this is load-bearing for the capture path.
func TestTrimBOM(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "UTF-8 BOM is stripped",
			in:   append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"a":1}`)...),
			want: `{"a":1}`,
		},
		{
			name: "UTF-16 LE BOM is stripped",
			in:   append([]byte{0xFF, 0xFE}, []byte(`{"a":1}`)...),
			want: `{"a":1}`,
		},
		{
			name: "clean input is untouched",
			in:   []byte(`{"a":1}`),
			want: `{"a":1}`,
		},
		{
			name: "empty input stays empty",
			in:   []byte{},
			want: "",
		},
		{
			name: "nil input stays empty",
			in:   nil,
			want: "",
		},
		{
			name: "a BOM in the middle is not touched",
			in:   []byte("ab\xef\xbb\xbfcd"),
			want: "ab\xef\xbb\xbfcd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(trimBOM(tt.in)); got != tt.want {
				t.Errorf("trimBOM(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// isLocalIP implements the internal/external split. When ExcludeLocal is set
// (the default) these addresses are dropped, so the dashboard's scope is
// "traffic leaving this machine for the Internet".
func TestIsLocalIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},     // loopback
		{"::1", true},           // IPv6 loopback
		{"10.0.0.1", true},      // RFC1918 class A
		{"172.16.0.1", true},    // RFC1918 class B, low edge
		{"172.31.255.254", true},// RFC1918 class B, high edge
		{"192.168.1.1", true},   // RFC1918 class C
		{"169.254.10.5", true},  // link-local unicast (APIPA)
		{"fe80::1", true},       // IPv6 link-local

		{"8.8.8.8", false},      // public
		{"1.1.1.1", false},      // public
		{"172.32.0.1", false},   // just outside RFC1918 class B
		{"172.15.0.1", false},   // just below RFC1918 class B
		{"2606:4700::1111", false}, // public IPv6

		// Unparseable input is treated as non-local so it is kept rather than
		// silently dropped -- fail-open, so malformed data stays visible.
		{"not-an-ip", false},
		{"", false},
		{"*", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isLocalIP(tt.ip); got != tt.want {
				t.Errorf("isLocalIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// flowKey is the deduplication identity. It is a 4-tuple -- source port is
// absent from FlowRecord entirely -- so two concurrent connections from
// different ephemeral ports to the same service collapse into one flow. That is
// a deliberate cardinality reduction, and these cases document its edges.
func TestFlowKey(t *testing.T) {
	base := FlowRecord{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.10",
		DstIP:     "142.250.185.78",
		DstPort:   443,
		Protocol:  "TCP",
		Packets:   1,
	}

	t.Run("identical records share a key", func(t *testing.T) {
		other := base
		if flowKey(base) != flowKey(other) {
			t.Errorf("identical records produced different keys: %q vs %q", flowKey(base), flowKey(other))
		}
	})

	t.Run("timestamp and process are not part of the identity", func(t *testing.T) {
		other := base
		other.Timestamp = base.Timestamp.Add(time.Hour)
		other.ProcessName = "chrome"
		other.Packets = 99
		if flowKey(base) != flowKey(other) {
			t.Error("key must depend only on the 4-tuple, not on timestamp/process/counters")
		}
	})

	for _, tt := range []struct {
		name   string
		mutate func(*FlowRecord)
	}{
		{"different destination port", func(f *FlowRecord) { f.DstPort = 80 }},
		{"different destination IP", func(f *FlowRecord) { f.DstIP = "1.1.1.1" }},
		{"different source IP", func(f *FlowRecord) { f.SrcIP = "192.168.1.11" }},
		{"different protocol", func(f *FlowRecord) { f.Protocol = "UDP" }},
	} {
		t.Run(tt.name+" changes the key", func(t *testing.T) {
			other := base
			tt.mutate(&other)
			if flowKey(base) == flowKey(other) {
				t.Errorf("%s should produce a distinct key, both were %q", tt.name, flowKey(base))
			}
		})
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{80, "80"},
		{443, "443"},
		{8080, "8080"},
		{65535, "65535"},

		// Documented quirk, not a supported input: the loop condition is
		// `n > 0`, so negatives fall through and yield an empty string. Ports
		// are never negative in practice, so this is unreachable from flowKey.
		{-1, ""},
	}

	for _, tt := range tests {
		if got := itoa(tt.in); got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
