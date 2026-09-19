// Package apilimit defines bounded application request and response policies.
package apilimit

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"time"
)

const (
	RequestLimit                 uint32 = 120
	RequestMaximumKeys                  = 10_000
	PrincipalLimit               uint32 = 600
	PrincipalMaximumKeys                = 1_024
	MaximumKeyBytes                     = 256
	DeniedHTTPStatus                    = 429
	UnavailableHTTPStatus               = 503
	DeniedRetryAfterSeconds             = 60
	UnavailableRetryAfterSeconds        = 1
	DeniedErrorCode                     = "rate_limited"
	UnavailableErrorCode                = "rate_limit_unavailable"
	Window                              = time.Minute
	OperationTimeout                    = 15 * time.Second
	RequestKeyAuthority                 = "canonical_ip_unmapped_direct_tcp_peer_no_forwarded_headers"
	PrincipalKeyAuthority               = "sha256_tenant_and_principal_identity"
)

// RequestAuthorityKey derives an opaque authority from a direct TCP peer.
func RequestAuthorityKey(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return "unknown"
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	return address.Unmap().String()
}

// PrincipalAuthorityKey derives a content-free authority from one authenticated tenant and principal.
func PrincipalAuthorityKey(tenantID, principalIdentity string) string {
	digest := sha256.Sum256([]byte(tenantID + "\x00" + principalIdentity))
	return hex.EncodeToString(digest[:])
}
