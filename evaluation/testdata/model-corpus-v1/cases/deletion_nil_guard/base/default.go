package upload

// Default returns a Client for endpoint with the default options.
func Default(endpoint string) *Client {
	return NewClient(endpoint, nil)
}
