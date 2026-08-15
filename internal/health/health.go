// Package health reports whether the service and its state store are
// healthy, with a short in-memory cache so the health endpoint cannot be
// abused into hammering the database.

package health

import (
	"context"
	"sync"
	"time"
)

// Pinger reports whether the underlying state store answers queries,
// satisfied by *sql.DB.
type Pinger interface {
	PingContext(context.Context) error
}

// Checker reports the health of the state store, probing it at most once
// per interval and serving the cached verdict in between. The probe runs
// under a mutex, so concurrent requests share a single database round
// trip.
type Checker struct {
	pinger   Pinger
	interval time.Duration

	mu        sync.Mutex
	checkedAt time.Time
	healthy   bool
}

// New returns a checker that probes the given pinger at most once per
// interval.
func New(pinger Pinger, interval time.Duration) *Checker {
	return &Checker{pinger: pinger, interval: interval}
}

// OK reports whether the state store answered the most recent probe
// successfully. The probe runs when the previous verdict is older than
// the interval; otherwise the cached verdict is returned.
func (c *Checker) OK(ctx context.Context) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checkedAt) < c.interval {
		return c.healthy
	}
	c.healthy = c.pinger.PingContext(ctx) == nil
	c.checkedAt = time.Now()
	return c.healthy
}
