package scanner

import (
	"net"
	"testing"
)

// enumerateCIDR expands a prefix into its usable host addresses. For prefixes
// yielding more than two addresses it drops the network and broadcast address,
// which is the classic "usable hosts = 2^(32-prefix) - 2" rule.
func TestEnumerateCIDR(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		want  []string
		count int
	}{
		{
			name:  "/30 yields two usable hosts",
			cidr:  "192.168.1.0/30",
			want:  []string{"192.168.1.1", "192.168.1.2"},
			count: 2,
		},
		{
			name:  "/29 yields six usable hosts",
			cidr:  "10.0.0.0/29",
			want:  []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"},
			count: 6,
		},
		{
			name:  "/24 yields 254 usable hosts",
			cidr:  "172.16.5.0/24",
			count: 254,
		},
		{
			// Only two addresses exist, so the len(ips) > 2 guard does not fire
			// and both are returned unstripped. RFC 3021 point-to-point links
			// legitimately use both.
			name:  "/31 returns both addresses unstripped",
			cidr:  "192.168.1.0/31",
			want:  []string{"192.168.1.0", "192.168.1.1"},
			count: 2,
		},
		{
			name:  "/32 returns the single host unstripped",
			cidr:  "192.168.1.5/32",
			want:  []string{"192.168.1.5"},
			count: 1,
		},
		{
			// The host bits are masked off before enumeration, so a prefix
			// written with a non-zero host portion still enumerates its network.
			name:  "host bits are masked off",
			cidr:  "192.168.1.2/30",
			want:  []string{"192.168.1.1", "192.168.1.2"},
			count: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enumerateCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("enumerateCIDR(%q) returned error: %v", tt.cidr, err)
			}
			if len(got) != tt.count {
				t.Errorf("enumerateCIDR(%q) returned %d addresses, want %d", tt.cidr, len(got), tt.count)
			}
			if tt.want == nil {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("enumerateCIDR(%q) = %v, want %v", tt.cidr, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("enumerateCIDR(%q)[%d] = %q, want %q", tt.cidr, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestEnumerateCIDRInvalid(t *testing.T) {
	for _, cidr := range []string{"", "192.168.1.0", "not-a-cidr", "192.168.1.0/33", "999.999.999.999/24"} {
		if _, err := enumerateCIDR(cidr); err == nil {
			t.Errorf("enumerateCIDR(%q) = nil error, want a parse error", cidr)
		}
	}
}

// incIP increments an address in place, carrying across byte boundaries.
func TestIncIP(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"192.168.1.1", "192.168.1.2"},
		{"192.168.1.255", "192.168.2.0"},   // carry across one octet
		{"192.168.255.255", "192.169.0.0"}, // carry across two octets
		{"10.0.0.0", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ip := net.ParseIP(tt.in).To4()
			if ip == nil {
				t.Fatalf("failed to parse %q as IPv4", tt.in)
			}
			incIP(ip)
			if got := ip.String(); got != tt.want {
				t.Errorf("incIP(%s) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}
