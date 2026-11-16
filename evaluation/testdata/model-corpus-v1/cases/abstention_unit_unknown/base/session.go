// Package session stores login sessions.
package session

import (
	"context"

	"example.test/kvstore"
)

// Config holds session settings.
type Config struct {
	// TTLSeconds is how long a session stays valid, in seconds.
	TTLSeconds int64
}

// Sessions writes sessions to a key-value store.
type Sessions struct {
	store *kvstore.Client
	cfg   Config
}

// New returns Sessions over store.
func New(store *kvstore.Client, cfg Config) *Sessions {
	return &Sessions{store: store, cfg: cfg}
}

// Save stores user under token, to expire after the configured TTL.
func (s *Sessions) Save(ctx context.Context, token, user string) error {
	return s.store.PutWithTTL(ctx, "session/"+token, []byte(user), s.cfg.TTLSeconds)
}
