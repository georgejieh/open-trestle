// Package config loads service settings.
package config

import "time"

// Config holds the service settings.
type Config struct {
	ListenAddress string        `json:"listen_address"`
	ReadTimeout   time.Duration `json:"read_timeout"`
	MaxBodyBytes  int64         `json:"max_body_bytes"`
}

// Default returns the settings used when no configuration file is given.
func Default() Config {
	return Config{ListenAddress: "127.0.0.1:8080", ReadTimeout: 10 * time.Second, MaxBodyBytes: 1 << 20}
}
