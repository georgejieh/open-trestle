//go:build !linux

package secretscan

import "context"

type Client struct{}

func NewClient() *Client { return &Client{} }

func (client *Client) scan(_ context.Context, _ [][]byte) ScanResult {
	return ScanResult{failure: FailurePolicy}
}
