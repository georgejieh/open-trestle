package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOpenRejectsUnsafeRemoteTransportBeforeConnecting(t *testing.T) {
	tests := []string{"postgres://user:password@db.example.test/reviews?sslmode=disable", "postgres://user:password@db.example.test/reviews?sslmode=require", "postgres://user:password@localhost/reviews?sslmode=disable", "postgres://user:password@db.example.test/reviews?sslmode=prefer"}
	for _, dataSource := range tests {
		database, err := Open(context.Background(), dataSource, PoolOptions{})
		if database != nil || !errors.Is(err, ErrInvalidDatabase) {
			t.Errorf("source=%q database=%v err=%v", dataSource, database, err)
		}
	}
}
func TestOpenRejectsUnboundedPoolOptions(t *testing.T) {
	options := PoolOptions{MaximumOpen: 257, MaximumIdle: 1, MaximumLifetime: time.Hour, MaximumIdleTime: time.Minute}
	database, err := Open(context.Background(), "postgres://user:password@127.0.0.1/reviews?sslmode=disable", options)
	if database != nil || !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("database=%v err=%v", database, err)
	}
}
