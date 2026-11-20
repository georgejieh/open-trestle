//go:build unix

package main

import (
	"sync"
	"time"
)

type daemonBudgetedHandlerClock struct {
	mu sync.Mutex
	at time.Time
}

func newDaemonBudgetedHandlerClock() *daemonBudgetedHandlerClock {
	zone := time.FixedZone("budgeted-raw-fixture", -7*60*60)
	at := time.Now().In(zone)
	if at.Nanosecond()%int(time.Millisecond) == 0 {
		at = at.Add(123456 * time.Nanosecond)
	}
	return &daemonBudgetedHandlerClock{at: at}
}

func (c *daemonBudgetedHandlerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *daemonBudgetedHandlerClock) UTCMS() time.Time {
	return c.Now().UTC().Truncate(time.Millisecond)
}

type daemonBudgetedRawClock struct{ at time.Time }

func (c daemonBudgetedRawClock) Now() time.Time { return c.at }
