package main

import (
	"sync"
	"time"
)

type daemonFakeHandlerClock struct {
	mu sync.Mutex
	at time.Time
}

func newDaemonFakeHandlerClock() *daemonFakeHandlerClock {
	zone := time.FixedZone("budgeted-raw-fixture", -7*60*60)
	at := time.Now().In(zone)
	if at.Nanosecond()%int(time.Millisecond) == 0 {
		at = at.Add(123456 * time.Nanosecond)
	}
	return &daemonFakeHandlerClock{at: at}
}

func (c *daemonFakeHandlerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *daemonFakeHandlerClock) UTCMS() time.Time {
	return c.Now().UTC().Truncate(time.Millisecond)
}

type daemonFakeRawClock struct{ at time.Time }

func (c daemonFakeRawClock) Now() time.Time { return c.at }
