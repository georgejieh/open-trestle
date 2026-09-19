package httpapi

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestMemoryRateLimiterBoundsKeysAndWindows(t *testing.T) {
	limiter, err := NewMemoryRateLimiter(2, time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1000, 0)
	allow := func(key string, at time.Time) bool {
		allowed, allowErr := limiter.Allow(context.Background(), key, at)
		if allowErr != nil {
			t.Fatal(allowErr)
		}
		return allowed
	}
	if !allow("a", at) || !allow("a", at) || allow("a", at) || !allow("b", at) {
		t.Fatal("unexpected rate decision")
	}
	if allowed, capacityErr := limiter.Allow(context.Background(), "c", at); allowed || !errors.Is(capacityErr, ErrRateLimiterCapacity) {
		t.Fatalf("capacity allowed=%v err=%v", allowed, capacityErr)
	}
	if !allow("c", at.Add(time.Minute)) {
		t.Fatal("expired window did not release capacity")
	}
}
func TestNewMemoryRateLimiterRejectsUnsafeBounds(t *testing.T) {
	for _, test := range []struct {
		limit  uint32
		window time.Duration
		keys   int
	}{{0, time.Minute, 1}, {1, 0, 1}, {1, time.Minute, 0}, {10001, time.Minute, 1}, {1, time.Hour + time.Second, 1}, {1, time.Minute, 10001}} {
		if limiter, err := NewMemoryRateLimiter(test.limit, test.window, test.keys); !errors.Is(err, ErrInvalidRateLimiter) || limiter != nil {
			t.Fatalf("limiter=(%#v,%v)", limiter, err)
		}
	}
}

func TestRequestAuthorityKeyCanonicalizesDirectTCPPeer(t *testing.T) {
	for remote, expected := range map[string]string{"192.0.2.1:443": "192.0.2.1", "[2001:0db8::1]:443": "2001:db8::1", "[::ffff:192.0.2.1]:443": "192.0.2.1", "malformed": "unknown", "": "unknown"} {
		if actual := requestAuthorityKey(&http.Request{RemoteAddr: remote}); actual != expected {
			t.Fatalf("remote=%q actual=%q expected=%q", remote, actual, expected)
		}
	}
}
