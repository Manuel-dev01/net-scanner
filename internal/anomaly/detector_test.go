package anomaly

import (
	"math"
	"testing"
	"time"
)

// rollingAverage computes the baseline against which the current window is
// tested. It deliberately excludes the final (current) element: including the
// observation under test in its own baseline biases the estimator toward the
// observation, making a spike progressively harder to detect the larger it is.
func TestRollingAverage(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{
			// No history at all -- there is nothing to form a baseline from.
			name:   "empty slice has no baseline",
			values: nil,
			want:   0,
		},
		{
			// A single sample IS the current observation, so excluding it
			// leaves an empty baseline. Returning 0 means the caller's
			// `total > avg * multiplier` test cannot fire on the first window.
			name:   "single sample has no baseline",
			values: []float64{100},
			want:   0,
		},
		{
			name:   "two samples average only the prior one",
			values: []float64{10, 999},
			want:   10,
		},
		{
			name:   "current sample is excluded from its own baseline",
			values: []float64{10, 20, 30, 1000},
			want:   20, // (10+20+30)/3, not (10+20+30+1000)/4
		},
		{
			name:   "constant history yields that constant",
			values: []float64{50, 50, 50, 50},
			want:   50,
		},
		{
			name:   "zero-valued history yields zero",
			values: []float64{0, 0, 0},
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rollingAverage(tt.values)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("rollingAverage(%v) = %v, want %v", tt.values, got, tt.want)
			}
		})
	}
}

// The spike rule is `total > avg * multiplier`. This pins down the consequence
// of rollingAverage returning 0: a zero baseline can never be exceeded, so no
// spike fires until at least two windows of non-zero history exist. In poller
// mode, where byte counts are structurally 0, this is why spike detection is
// permanently quiet.
func TestSpikeRuleAgainstZeroBaseline(t *testing.T) {
	const multiplier = 2.0

	if avg := rollingAverage([]float64{0, 0}); 0 > avg*multiplier {
		t.Error("a zero-byte window must not register as a spike against a zero baseline")
	}

	// With real history a genuine spike does fire.
	avg := rollingAverage([]float64{100, 100, 100, 500})
	if !(500.0 > avg*multiplier) {
		t.Errorf("500 bytes against a baseline of %v should exceed the %.1fx threshold", avg, multiplier)
	}

	// And an ordinary window does not.
	avg = rollingAverage([]float64{100, 100, 100, 150})
	if 150.0 > avg*multiplier {
		t.Errorf("150 bytes against a baseline of %v should not exceed the %.1fx threshold", avg, multiplier)
	}
}

func TestDefaultThresholds(t *testing.T) {
	th := DefaultThresholds()
	if th.BytesPerMinuteSpike != 2.0 {
		t.Errorf("BytesPerMinuteSpike = %v, want 2.0", th.BytesPerMinuteSpike)
	}
	if th.NewDestWindow != 24*time.Hour {
		t.Errorf("NewDestWindow = %v, want 24h", th.NewDestWindow)
	}
}
