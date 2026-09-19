package apilimit

import "testing"

func TestRequestAuthorityKeyCanonicalizesDirectTCPPeer(t *testing.T) {
	for remote, expected := range map[string]string{"192.0.2.1:443": "192.0.2.1", "[2001:0db8::1]:443": "2001:db8::1", "[::ffff:192.0.2.1]:443": "192.0.2.1", "malformed": "unknown", "": "unknown"} {
		if actual := RequestAuthorityKey(remote); actual != expected {
			t.Fatalf("remote=%q actual=%q expected=%q", remote, actual, expected)
		}
	}
}
func TestPrincipalAuthorityKeyBindsTenantAndPrincipal(t *testing.T) {
	first := PrincipalAuthorityKey("tenant-a", "principal-a")
	if len(first) != 64 || first == PrincipalAuthorityKey("tenant-b", "principal-a") || first == PrincipalAuthorityKey("tenant-a", "principal-b") {
		t.Fatalf("unexpected identity %q", first)
	}
}
