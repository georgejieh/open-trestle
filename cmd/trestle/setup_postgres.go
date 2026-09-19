package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupPostgresExecutor func(context.Context, string) (string, error)
type setupPostgresStorageProbe struct {
	environment func(string) string
	execute     setupPostgresExecutor
	identity    string
}

func newSetupPostgresStorageProbe(environment func(string) string, execute setupPostgresExecutor) (*setupPostgresStorageProbe, error) {
	if environment == nil || execute == nil {
		return nil, errors.New("invalid PostgreSQL setup probe")
	}
	sum := sha256.Sum256([]byte("open-trestle/setup-postgresql-probe/v1;environment=OPEN_TRESTLE_POSTGRES_URL;max-open=1;max-idle=0;timeout=30s;migrations=exact;authority=v1"))
	return &setupPostgresStorageProbe{environment, execute, hex.EncodeToString(sum[:])}, nil
}
func (p *setupPostgresStorageProbe) ConfigurationIdentity() string {
	if p == nil {
		return ""
	}
	return p.identity
}
func (p *setupPostgresStorageProbe) Probe(ctx context.Context) setupcore.PostgresStorageProbeResult {
	if p == nil || p.environment == nil || p.execute == nil || ctx == nil || ctx.Err() != nil {
		return setupcore.NewInvalidPostgresStorageProbeResult()
	}
	dataSource := p.environment("OPEN_TRESTLE_POSTGRES_URL")
	if ctx.Err() != nil {
		return setupcore.NewUnavailablePostgresStorageProbeResult()
	}
	identity, err := p.execute(ctx, dataSource)
	if ctx.Err() != nil {
		return setupcore.NewUnavailablePostgresStorageProbeResult()
	}
	if err == nil {
		return setupcore.NewVerifiedPostgresStorageProbeResult(identity)
	}
	if errors.Is(err, postgresstore.ErrDatabaseUnavailable) {
		return setupcore.NewUnavailablePostgresStorageProbeResult()
	}
	return setupcore.NewInvalidPostgresStorageProbeResult()
}
func executeSetupPostgresStorage(ctx context.Context, dataSource string) (string, error) {
	database, err := postgresstore.Open(ctx, dataSource, postgresstore.PoolOptions{MaximumOpen: 1, MaximumIdle: 0, MaximumLifetime: time.Minute, MaximumIdleTime: 30 * time.Second})
	if err != nil {
		return "", err
	}
	authority, err := postgresstore.VerifyDatabaseStorageAuthority(ctx, database)
	if err != nil {
		_ = database.Close()
		return "", err
	}
	if closeErr := database.Close(); closeErr != nil {
		return "", postgresstore.ErrDatabaseUnavailable
	}
	return authority.Identity(), nil
}
func (p *setupPostgresStorageProbe) String() string { return "setup PostgreSQL storage probe" }
func (p *setupPostgresStorageProbe) GoString() string {
	return "main.setupPostgresStorageProbe{<redacted>}"
}
func (p *setupPostgresStorageProbe) Format(state fmt.State, verb rune) {
	value := p.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = p.GoString()
	}
	_, _ = state.Write([]byte(value))
}
