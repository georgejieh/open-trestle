package provider

import "testing"

func TestParseServiceEndpointAcceptsHTTPSAndLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{"https://api.example.test/v1", "https://127.0.0.1:8443/v1/", "https://[::1]/v1", "https://[2001:db8::1]:443/v1", "http://127.0.0.1:8080/v1", "http://127.1.2.3/v1", "http://[::1]:8080/v1"} {
		endpoint, err := ParseServiceEndpoint(raw)
		if err != nil || endpoint.String() != raw {
			t.Fatalf("%q: %#v %v", raw, endpoint, err)
		}
	}
}
func TestParseServiceEndpointRejectsUnsafeOrNoncanonicalAuthority(t *testing.T) {
	values := []string{"http://example.com/v1", "https://user:secret@example.com/v1", "https://EXAMPLE.com/v1", "https://example.com:0443/v1", "https://example.com/v1?x=1", "https://example.com/v1#x", "https://example.com/v1//responses", "https://example.com/v1/../other", "https://example.com/v%31", "https://example.com/v1\\other", "https://bad..example/v1", "http://2130706433/v1", "http://0177.0.0.1/v1", "https://2130706433/v1", "https://0177.0.0.1/v1", "https://example.com:/v1", "http://127.0.0.1:/v1", "https://[::1]:/v1", "https://[::::]/v1", "https://[0:0:0:0:0:0:0:1]/v1", "https://[2001:db8:0:0:0:0:0:1]/v1", "https://[::ffff:c000:201]/v1"}
	for _, raw := range values {
		if _, err := ParseServiceEndpoint(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestClassifyServiceEndpointUsesClosedLocality(t *testing.T) {
	tests := map[string]ServiceEndpointLocality{"http://127.0.0.1:8080/v1": ServiceEndpointLoopback, "https://[::1]/v1": ServiceEndpointLoopback, "https://api.example.test/v1": ServiceEndpointRemote, "https://10.0.0.8/v1": ServiceEndpointRemote, "https://[2001:db8::1]/v1": ServiceEndpointRemote}
	for raw, want := range tests {
		got, err := ClassifyServiceEndpoint(raw)
		if err != nil || got != want {
			t.Fatalf("%s=%s %v", raw, got, err)
		}
	}
	for _, raw := range []string{"https://localhost/v1", "https://api.localhost/v1", "https://0.0.0.0/v1", "https://[::]/v1", "https://169.254.1.1/v1", "https://224.0.0.1/v1", "https://[ff02::1]/v1"} {
		if got, err := ClassifyServiceEndpoint(raw); err == nil || got != 0 {
			t.Fatalf("accepted %s as %s", raw, got)
		}
	}
}
