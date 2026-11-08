package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Evidence fetching for `trestle init`. When the operator names a public web
// page they reviewed, the wizard can fetch it once and compute its SHA-256 on
// this machine instead of asking them to save and hash it by hand. The fetch is
// a single credential-free HTTPS GET: no key, cookie, repository content or
// query string is ever sent, only public addresses are dialed, the body is
// bounded, and nothing is stored except the resulting digest. The operator still
// confirms the URL and digest, and still types yes to every declaration.

const (
	initEvidenceMaxBytes = 8 << 20
	initEvidenceTimeout  = 20 * time.Second

	// The one OpenRouter page docs/openrouter-zdr-profile.md cites for the ZDR
	// routing contract, its documented exceptions and which endpoints honor it.
	initOpenRouterZDRDocs = "https://openrouter.ai/docs/guides/features/zdr"
	// OpenRouter's model list, read only with the operator's key variable.
	initOpenRouterModels = "https://openrouter.ai/api/v1/models"
)

// Tests replace the transport; production dials public addresses only.
var initEvidenceTransport http.RoundTripper

type initFetchedEvidence struct {
	url    string // the address actually read, after any HTTPS redirect
	digest string
	size   int64
}

// initPublicEvidenceURL accepts only an https address with a public host and no
// credentials, query or fragment: the same shape the bootstrap records.
func initPublicEvidenceURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") || parsed.Hostname() == "" {
		return errors.New("only an https:// address without a user name, ?query or #fragment can be fetched")
	}
	host := strings.ToLower(parsed.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil && !initPublicAddress(ip) || host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") && err != nil {
		return errors.New("only public web addresses are fetched")
	}
	return nil
}

// initNonPublicPrefixes are ranges that IsGlobalUnicast admits but that never
// name a public web server: shared address space, "this network", benchmarking,
// reserved class E, and the NAT64 well-known prefix, which can translate to any
// IPv4 address, including private ones.
var initNonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

func initPublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range initNonPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func initEvidenceClient() *http.Client {
	transport := initEvidenceTransport
	if transport == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		transport = &http.Transport{
			Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: true,
			MaxResponseHeaderBytes: 64 << 10, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, errors.New("evidence address rejected")
				}
				addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil || len(addresses) == 0 || len(addresses) > 32 {
					return nil, errors.New("the web address could not be resolved")
				}
				for _, ip := range addresses {
					if !initPublicAddress(ip) {
						return nil, errors.New("the web address resolves to a private or local network address")
					}
				}
				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].String(), port))
			},
		}
	}
	return &http.Client{Transport: transport, Timeout: initEvidenceTimeout, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return initPublicEvidenceURL(request.URL.String())
	}}
}

// initFetchEvidence performs one bounded GET and hashes the exact bytes served.
func initFetchEvidence(ctx context.Context, location string) (initFetchedEvidence, error) {
	if err := initPublicEvidenceURL(location); err != nil {
		return initFetchedEvidence{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, initEvidenceTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, location, nil)
	if err != nil {
		return initFetchedEvidence{}, errors.New("that address cannot be requested")
	}
	request.Header.Set("User-Agent", "open-trestle-init/1 (evidence digest)")
	request.Header.Set("Accept", "text/html,application/pdf;q=0.9,*/*;q=0.8")
	response, err := initEvidenceClient().Do(request)
	if err != nil {
		if requestCtx.Err() != nil {
			return initFetchedEvidence{}, errors.New("no answer within 20 seconds")
		}
		var redirect *url.Error
		if errors.As(err, &redirect) && redirect.Err != nil {
			return initFetchedEvidence{}, redirect.Err
		}
		return initFetchedEvidence{}, errors.New("the page could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return initFetchedEvidence{}, fmt.Errorf("the server answered with HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > initEvidenceMaxBytes {
		return initFetchedEvidence{}, errors.New("the page is larger than 8 MiB")
	}
	sum := sha256.New()
	size, err := io.Copy(sum, io.LimitReader(response.Body, initEvidenceMaxBytes+1))
	if err != nil {
		return initFetchedEvidence{}, errors.New("the page could not be read completely")
	}
	if size > initEvidenceMaxBytes {
		return initFetchedEvidence{}, errors.New("the page is larger than 8 MiB")
	}
	if size == 0 {
		return initFetchedEvidence{}, errors.New("the page was empty")
	}
	final := location
	if response.Request != nil && response.Request.URL != nil {
		final = response.Request.URL.String()
	}
	if initPublicEvidenceURL(final) != nil {
		return initFetchedEvidence{}, errors.New("the page redirected to an address that cannot be recorded")
	}
	return initFetchedEvidence{url: final, digest: hex.EncodeToString(sum.Sum(nil)), size: size}, nil
}
