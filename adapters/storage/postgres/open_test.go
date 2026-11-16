package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

func TestOpenRejectsSimpleQueryProtocolBeforeConnecting(t *testing.T) {
	dataSource := "postgres://user:password@127.0.0.1/reviews?sslmode=disable&default_query_exec_mode=simple_protocol"
	database, err := Open(context.Background(), dataSource, PoolOptions{})
	if database != nil || !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("database=%v err=%v", database, err)
	}
}

func TestPgxDefaultQueryModeUsesExtendedProtocol(t *testing.T) {
	config, err := pgx.ParseConfig("postgres://user:password@127.0.0.1/reviews?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if config.DefaultQueryExecMode != pgx.QueryExecModeCacheStatement {
		t.Fatalf("default query mode = %v", config.DefaultQueryExecMode)
	}
}
