package httpapi

import (
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

import "github.com/georgejieh/open-trestle/internal/apilimit"

const (
	maxRateLimit         = 10000
	maxRateLimitKeys     = 10000
	maxRateLimitWindow   = time.Hour
	maxRateLimitKeyBytes = apilimit.MaximumKeyBytes
)

var (
	// ErrInvalidRateLimiter identifies unusable rate or cardinality bounds.
	ErrInvalidRateLimiter = errors.New("invalid API rate limiter")
	// ErrRateLimiterCapacity identifies an exhausted authority-key cardinality safety bound.
	ErrRateLimiterCapacity = errors.New("API rate limiter capacity unavailable")
)

// RateLimiter grants bounded operations for one opaque authority key. An error denies the operation as unavailable.
type RateLimiter interface {
	Allow(context.Context, string, time.Time) (bool, error)
}
type rateWindow struct {
	startedAt time.Time
	count     uint32
}

// MemoryRateLimiter is a bounded fixed-window limiter for one daemon process.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	limit   uint32
	window  time.Duration
	maxKeys int
	entries map[string]rateWindow
}

func NewMemoryRateLimiter(limit uint32, window time.Duration, maxKeys int) (*MemoryRateLimiter, error) {
	if limit == 0 || limit > maxRateLimit || window < time.Second || window > maxRateLimitWindow || maxKeys <= 0 || maxKeys > maxRateLimitKeys {
		return nil, ErrInvalidRateLimiter
	}
	return &MemoryRateLimiter{limit: limit, window: window, maxKeys: maxKeys, entries: make(map[string]rateWindow, maxKeys)}, nil
}
func (l *MemoryRateLimiter) Allow(ctx context.Context, key string, at time.Time) (bool, error) {
	if l == nil || ctx == nil || ctx.Err() != nil || len(key) == 0 || len(key) > maxRateLimitKeyBytes || !utf8.ValidString(key) || at.IsZero() {
		return false, ErrInvalidRateLimiter
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.entries[key]
	if exists {
		if at.Before(entry.startedAt) {
			return false, nil
		}
		if at.Sub(entry.startedAt) < l.window {
			if entry.count >= l.limit {
				return false, nil
			}
			entry.count++
			l.entries[key] = entry
			return true, nil
		}
		delete(l.entries, key)
	}
	if len(l.entries) >= l.maxKeys {
		for candidate, value := range l.entries {
			if !at.Before(value.startedAt.Add(l.window)) {
				delete(l.entries, candidate)
			}
		}
	}
	if len(l.entries) >= l.maxKeys {
		return false, ErrRateLimiterCapacity
	}
	l.entries[key] = rateWindow{startedAt: at, count: 1}
	return true, nil
}
