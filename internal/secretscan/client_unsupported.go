//go:build !linux

package secretscan

import "context"

type Client struct{}

func NewClient() *Client { return &Client{} }

func (client *Client) BinaryDigests() (string, string) { return "", "" }

func (client *Client) scan(_ context.Context, _ [][]byte) ScanResult {
	return ScanResult{failure: FailurePolicy}
}

// InstalledPrerequisite always refuses: the sandboxed scanner is Linux-only.
func (client *Client) InstalledPrerequisite() error { return ErrScannerUnsupportedPlatform }
