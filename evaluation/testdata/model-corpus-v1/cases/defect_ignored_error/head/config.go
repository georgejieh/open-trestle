// Package config loads service settings.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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

// Load reads a JSON configuration file. Settings absent from the file keep
// their default values.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	cfg := Default()
	json.Unmarshal(raw, &cfg)
	return cfg, nil
}
