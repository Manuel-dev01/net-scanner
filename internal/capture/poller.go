package capture

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// PollerConfig configures the active connections poller.
type PollerConfig struct {
	Interval     time.Duration // how often to snapshot, default 5s
	ExcludeLocal bool          // skip loopback and RFC1918
}

// Poller captures traffic by periodically snapshotting active TCP/UDP connections.
type Poller struct {
	cfg    PollerConfig
	stopCh chan struct{}
	mu     sync.Mutex
}

// NewPoller creates a new active connections poller.
func NewPoller(cfg PollerConfig) *Poller {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Poller{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (p *Poller) Name() string { return "poller" }

func (p *Poller) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.stopCh:
		// already stopped
	default:
		close(p.stopCh)
	}
	return nil
}

// Start begins polling active connections and sends new flows on the returned channel.
func (p *Poller) Start(ctx context.Context) (<-chan FlowRecord, error) {
	out := make(chan FlowRecord, 256)
	seen := make(map[string]bool)

	go func() {
		defer close(out)
		ticker := time.NewTicker(p.cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stopCh:
				return
			case <-ticker.C:
				flows := p.snapshot(ctx)
				for _, f := range flows {
					key := flowKey(f)
					if seen[key] {
						continue
					}
					seen[key] = true
					select {
					case out <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return out, nil
}

// psTCPEntry matches the PowerShell Get-NetTCPConnection JSON output.
// State is an integer enum: 2=Listen, 3=SynSent, 4=SynReceived, 5=Established,
// 6=FinWait1, 7=FinWait2, 8=CloseWait, 9=Closing, 10=LastAck, 11=TimeWait, 12=DeleteTCB
type psTCPEntry struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	State         int    `json:"State"`
	OwningProcess int    `json:"OwningProcess"`
	ProcessName   string `json:"ProcessName"`
}

// snapshot takes a point-in-time picture of active connections.
func (p *Poller) snapshot(ctx context.Context) []FlowRecord {
	var flows []FlowRecord

	// TCP connections
	tcpFlows := p.snapshotTCP(ctx)
	flows = append(flows, tcpFlows...)

	return flows
}

func (p *Poller) snapshotTCP(ctx context.Context) []FlowRecord {
	// Include process name by joining with Get-Process — more efficient than a separate call
	script := `Get-NetTCPConnection | Where-Object State -eq 5 | ForEach-Object {
		$proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
		[PSCustomObject]@{
			LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort;
			RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort;
			State=$_.State; OwningProcess=$_.OwningProcess;
			ProcessName=if($proc){$proc.ProcessName}else{"unknown"}
		}
	} | ConvertTo-Json -Compress`
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		// PowerShell may return non-zero if no connections; not critical
		return nil
	}

	out = trimBOM(out)
	if len(out) == 0 {
		return nil
	}

	// Handle single object (not array) from PowerShell
	var entries []psTCPEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		// Try single object
		var single psTCPEntry
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil
		}
		entries = []psTCPEntry{single}
	}

	now := time.Now()
	var flows []FlowRecord
	for _, e := range entries {
		// Skip if remote address is empty or local
		if e.RemoteAddress == "" || e.RemoteAddress == "*" {
			continue
		}
		if p.cfg.ExcludeLocal && isLocalIP(e.RemoteAddress) {
			continue
		}

		flows = append(flows, FlowRecord{
			Timestamp:   now,
			SrcIP:       e.LocalAddress,
			DstIP:       e.RemoteAddress,
			DstPort:     e.RemotePort,
			Protocol:    "TCP",
			BytesSent:   0, // poller can't track bytes
			BytesRecv:   0,
			Packets:     1,
			ProcessName: e.ProcessName,
		})
	}
	return flows
}

func flowKey(f FlowRecord) string {
	return f.SrcIP + ":" + f.DstIP + ":" + itoa(f.DstPort) + ":" + f.Protocol
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func trimBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	// Also trim PowerShell's BOM (UTF-16 LE BOM)
	dataStr := strings.TrimLeft(string(data), "\xef\xbb\xbf\xfe\xff")
	return []byte(dataStr)
}
