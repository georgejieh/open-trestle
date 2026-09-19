package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	defaultMaximumConnections = 16
	maximumConnections        = 256
)

// PoolOptions bounds PostgreSQL connection reuse.
type PoolOptions struct {
	MaximumOpen     int
	MaximumIdle     int
	MaximumLifetime time.Duration
	MaximumIdleTime time.Duration
}

// Open validates transport security, opens a pgx database pool, and confirms connectivity.
func Open(ctx context.Context, dataSource string, options PoolOptions) (*sql.DB, error) {
	if ctx == nil || ctx.Err() != nil || len(dataSource) == 0 || len(dataSource) > 4096 || !utf8.ValidString(dataSource) || strings.ContainsAny(dataSource, "\x00\r\n") {
		return nil, ErrInvalidDatabase
	}
	options = defaultPoolOptions(options)
	if !validPoolOptions(options) {
		return nil, ErrInvalidDatabase
	}
	config, err := pgx.ParseConfig(dataSource)
	if err != nil || !safeConnection(config) {
		return nil, ErrInvalidDatabase
	}
	if config.ConnectTimeout <= 0 || config.ConnectTimeout > 30*time.Second {
		config.ConnectTimeout = 10 * time.Second
	}
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["application_name"] = "open-trestle"
	database := stdlib.OpenDB(*config)
	database.SetMaxOpenConns(options.MaximumOpen)
	database.SetMaxIdleConns(options.MaximumIdle)
	database.SetConnMaxLifetime(options.MaximumLifetime)
	database.SetConnMaxIdleTime(options.MaximumIdleTime)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, ErrDatabaseUnavailable
	}
	return database, nil
}

func defaultPoolOptions(options PoolOptions) PoolOptions {
	if options == (PoolOptions{}) {
		return PoolOptions{
			MaximumOpen: defaultMaximumConnections, MaximumIdle: 4,
			MaximumLifetime: 30 * time.Minute, MaximumIdleTime: 5 * time.Minute,
		}
	}
	return options
}
func validPoolOptions(options PoolOptions) bool {
	validCounts := options.MaximumOpen > 0 && options.MaximumOpen <= maximumConnections && options.MaximumIdle >= 0 && options.MaximumIdle <= options.MaximumOpen
	validLifetime := options.MaximumLifetime >= time.Minute && options.MaximumLifetime <= 24*time.Hour
	validIdle := options.MaximumIdleTime >= 30*time.Second && options.MaximumIdleTime <= time.Hour
	return validCounts && validLifetime && validIdle
}
func safeConnection(config *pgx.ConnConfig) bool {
	if config == nil || config.User == "" || config.Database == "" || config.Host == "" || !safeTarget(config.Host, config.TLSConfig) {
		return false
	}
	for _, fallback := range config.Fallbacks {
		if fallback == nil || !safeTarget(fallback.Host, fallback.TLSConfig) {
			return false
		}
	}
	return true
}
func safeTarget(host string, tlsConfig *tls.Config) bool {
	if strings.HasPrefix(host, "/") {
		return true
	}
	address := net.ParseIP(host)
	if address != nil && address.IsLoopback() {
		return true
	}
	return tlsConfig != nil && !tlsConfig.InsecureSkipVerify && tlsConfig.ServerName != ""
}
