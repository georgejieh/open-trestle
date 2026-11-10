// Package syncer pushes local records to the remote store.
package syncer

import (
	"context"

	"example.test/platform/retry"
)

const (
	pushAttempts      = 5
	pushBackoffMillis = 200
)

// Record is one local change.
type Record struct {
	Key   string
	Value []byte
}

// Remote accepts batches of records.
type Remote interface {
	Send(ctx context.Context, batch []Record) error
}

// Push sends batch to remote, retrying transient failures.
func Push(ctx context.Context, remote Remote, batch []Record) error {
	return retry.Do(ctx, pushAttempts, pushBackoffMillis, func(ctx context.Context) error {
		return remote.Send(ctx, batch)
	})
}
