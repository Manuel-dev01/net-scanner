package capture

import (
	"context"
	"time"
)

// FlowRecord is the common output type from any capture mode.
type FlowRecord struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	DstPort     int
	Protocol    string // "TCP", "UDP", "ICMP", "OTHER"
	BytesSent   int64
	BytesRecv   int64
	Packets     int
	ProcessName string // only populated by poller mode
}

// Capturer is the interface both capture modes implement.
type Capturer interface {
	// Start begins capturing. It sends FlowRecords on the returned channel.
	// The channel is closed when ctx is canceled.
	Start(ctx context.Context) (<-chan FlowRecord, error)
	// Stop gracefully stops the capturer.
	Stop() error
	// Name returns "poller" or "pcap" for logging and DB tagging.
	Name() string
}
