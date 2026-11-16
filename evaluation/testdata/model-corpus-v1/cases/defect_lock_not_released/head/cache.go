// Package cache keeps short-lived values in memory.
package cache

import (
	"sync"
	"time"
)

type entry struct {
	value   string
	expires time.Time
}

// Cache is a map of expiring values. It is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	entries map[string]entry
	now     func() time.Time
}

// New returns an empty Cache that reads the current time from now.
func New(now func() time.Time) *Cache {
	return &Cache{entries: make(map[string]entry), now: now}
}

// Set stores value under key until ttl has elapsed.
func (c *Cache) Set(key, value string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry{value: value, expires: c.now().Add(ttl)}
}

// Get returns the value stored under key if it has not expired.
func (c *Cache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.now().Before(e.expires) {
		return "", false
	}
	return e.value, true
}

// Refresh extends the lifetime of key to ttl from now. It reports false when
// key is absent or has expired.
func (c *Cache) Refresh(key string, ttl time.Duration) bool {
	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok || !c.now().Before(e.expires) {
		return false
	}
	e.expires = c.now().Add(ttl)
	c.entries[key] = e
	c.mu.Unlock()
	return true
}
