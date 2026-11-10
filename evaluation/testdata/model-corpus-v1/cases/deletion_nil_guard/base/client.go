// Package upload sends files to a storage endpoint.
package upload

import "time"

// Options configures a Client. A nil *Options selects DefaultOptions.
type Options struct {
	Timeout time.Duration
	Retries int
}

// DefaultOptions returns the options NewClient uses when it receives nil.
func DefaultOptions() *Options {
	return &Options{Timeout: 30 * time.Second, Retries: 3}
}

// Client uploads to one endpoint.
type Client struct {
	endpoint string
	timeout  time.Duration
	retries  int
}

// NewClient returns a Client for endpoint configured by opts.
func NewClient(endpoint string, opts *Options) *Client {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Client{endpoint: endpoint, timeout: opts.Timeout, retries: opts.Retries}
}
