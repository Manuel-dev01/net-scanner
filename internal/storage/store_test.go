package storage

import "testing"

// nullIfEmpty maps Go's zero value for a string onto SQL NULL, so an absent
// hostname or country is stored as NULL rather than an empty string. This keeps
// COUNT/GROUP BY aggregations in the dashboard panels from treating "unknown"
// as a distinct category.
func TestNullIfEmpty(t *testing.T) {
	if got := nullIfEmpty(""); got != nil {
		t.Errorf("nullIfEmpty(\"\") = %v, want nil", got)
	}

	for _, s := range []string{"example.com", "US", " ", "0"} {
		got := nullIfEmpty(s)
		str, ok := got.(string)
		if !ok {
			t.Errorf("nullIfEmpty(%q) returned %T, want string", s, got)
			continue
		}
		if str != s {
			t.Errorf("nullIfEmpty(%q) = %q, want %q", s, str, s)
		}
	}
}

// zeroIfNeg clamps counters at zero before they reach the database, where the
// byte/packet columns are non-negative by intent.
func TestZeroIfNeg(t *testing.T) {
	tests := []struct {
		in   int
		want int
	}{
		{-1, 0},
		{-9999, 0},
		{0, 0},
		{1, 1},
		{4096, 4096},
	}

	for _, tt := range tests {
		if got := zeroIfNeg(tt.in); got != tt.want {
			t.Errorf("zeroIfNeg(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
