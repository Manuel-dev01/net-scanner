package enrichment

import (
	"context"
	"net"
	"sync"
	"time"
)

type dnsCacheEntry struct {
	hostname  string
	resolvedAt time.Time
}

// DNSResolver performs reverse DNS lookups with an in-memory TTL cache.
type DNSResolver struct {
	cache map[string]*dnsCacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewDNSResolver creates a resolver with the given cache TTL.
func NewDNSResolver(ttl time.Duration) *DNSResolver {
	return &DNSResolver{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   ttl,
	}
}

// Resolve returns the reverse DNS hostname for an IP, or empty string on failure.
// Results are cached for the configured TTL. Non-blocking — DNS failures never stall the pipeline.
func (d *DNSResolver) Resolve(ctx context.Context, ip string) string {
	d.mu.RLock()
	if entry, ok := d.cache[ip]; ok {
		if time.Since(entry.resolvedAt) < d.ttl {
			d.mu.RUnlock()
			return entry.hostname
		}
	}
	d.mu.RUnlock()

	// Cache miss or expired — do lookup
	resolverCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(resolverCtx, ip)
	hostname := ""
	if err == nil && len(names) > 0 {
		// LookupAddr returns trailing dots; trim them
		hostname = names[0]
		if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
	}

	d.mu.Lock()
	d.cache[ip] = &dnsCacheEntry{hostname: hostname, resolvedAt: time.Now()}
	d.mu.Unlock()

	return hostname
}
