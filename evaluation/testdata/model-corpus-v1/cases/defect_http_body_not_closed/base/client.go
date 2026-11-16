// Package status queries a service's HTTP endpoints.
package status

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// Client calls one service.
type Client struct {
	base string
	http *http.Client
}

// NewClient returns a Client for the service at base, such as
// "http://127.0.0.1:8080".
func NewClient(base string, httpClient *http.Client) *Client {
	return &Client{base: base, http: httpClient}
}

// Version returns the body of the service's /version endpoint.
func (c *Client) Version(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/version", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("version: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
