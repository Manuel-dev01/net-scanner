package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/prometheus-community/pro-bing"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

type Result struct {
	IP         string        `json:"ip"`
	Hostname   string        `json:"hostname"`
	RTT        time.Duration `json:"rtt_ms"`
	IsUp       bool          `json:"is_up"`
	OpenPorts  []int         `json:"open_ports"`
	ScannedAt  time.Time     `json:"scanned_at"`
}

type Config struct {
	CIDR string
}

// Run executes a high-performance bounded concurrent network scan.
func Run(ctx context.Context, cfg Config) ([]Result, error) {
	ips, err := enumerateCIDR(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	results := make([]Result, len(ips))
	
	// Bound concurrent workers to 64 to safeguard host resources
	sem := semaphore.NewWeighted(64)
	g, ctx := errgroup.WithContext(ctx)

	for i, ip := range ips {
		// Stop queueing workers if context is canceled
		if err := ctx.Err(); err != nil {
			break
		}

		// Acquire worker token blockingly
		if err := sem.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
		}

		// Capture iterator states safely for closure evaluation
		idx := i
		targetIP := ip

		g.Go(func() error {
			defer sem.Release(1)
			results[idx] = probeHost(ctx, targetIP)
			return nil
		})
	}

	// Wait for all active concurrent probes to finalize safely
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

func probeHost(ctx context.Context, ip string) Result {
	res := Result{
		IP:        ip,
		ScannedAt: time.Now(),
	}

	isUp, rtt := pingHost(ip)
	res.IsUp = isUp
	res.RTT = rtt

	commonPorts := []int{22, 80, 443, 8080}
	for _, port := range commonPorts {
		if checkTCPPort(ip, port) {
			res.OpenPorts = append(res.OpenPorts, port)
			res.IsUp = true 
		}
	}

	if res.IsUp {
		dnsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		names, err := net.DefaultResolver.LookupAddr(dnsCtx, ip)
		cancel()
		if err == nil && len(names) > 0 {
			res.Hostname = names[0]
		} else {
			res.Hostname = "unknown"
		}
	}

	return res
}

func pingHost(ip string) (bool, time.Duration) {
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		return false, 0
	}
	pinger.SetPrivileged(false)
	pinger.Count = 1
	pinger.Timeout = 500 * time.Millisecond

	err = pinger.Run()
	if err != nil {
		return false, 0
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		return true, stats.AvgRtt
	}
	return false, 0
}

func checkTCPPort(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func enumerateCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for nextIP := ip.Mask(ipNet.Mask); ipNet.Contains(nextIP); incIP(nextIP) {
		ips = append(ips, nextIP.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// HostDiff represents the change in state for a specific IP address between two scans.
type HostDiff struct {
	IP     string `json:"ip"`
	Status string `json:"status"` // "NEW", "REMOVED", or "MODIFIED"
}

// SubnetDiff tracks arrays of newly discovered or dropped hosts.
type SubnetDiff struct {
	CIDR    string     `json:"cidr"`
	Changes []HostDiff `json:"changes"`
}