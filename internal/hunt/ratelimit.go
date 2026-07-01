package hunt

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// Per-host token-bucket rate limiting.

// --- per-host rate limiting ---

type HostRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

// NewHostRateLimiter builds a per-host token bucket. Passing rps <= 0
// returns an "unlimited" limiter — useful when scanning burner phishing
// infrastructure where the politeness/throughput trade-off doesn't apply.
func NewHostRateLimiter(rps float64, burst int) *HostRateLimiter {
	limit := rate.Limit(rps)
	if rps <= 0 {
		limit = rate.Inf
		if burst < 1 {
			burst = 1
		}
	}
	return &HostRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     limit,
		burst:    burst,
	}
}

func (h *HostRateLimiter) limiterFor(host string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l, ok := h.limiters[host]; ok {
		return l
	}
	l := rate.NewLimiter(h.rate, h.burst)
	h.limiters[host] = l
	return l
}

func (h *HostRateLimiter) Wait(ctx context.Context, host string) error {
	if h.rate == rate.Inf {
		return nil // skip the syscall entirely
	}
	return h.limiterFor(host).Wait(ctx)
}
