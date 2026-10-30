package modelcatalog

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func validateSource(source Source, allowRemote bool) error {
	if !sourceIDValid(source.ID) || source.CredentialEnvironment != "" && !validCredentialReference(source.CredentialEnvironment) {
		return ErrInvalid
	}
	endpoint, err := url.Parse(source.URL)
	if err != nil || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Host == "" || endpoint.RawPath != "" || endpoint.String() != source.URL {
		return ErrInvalid
	}
	if source.Kind == "openai_models" {
		if endpoint.Path != "/models" && !strings.HasSuffix(endpoint.Path, "/models") {
			return ErrInvalid
		}
	} else if source.Kind == "ollama_tags" {
		if endpoint.Path != "/api/tags" {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	if strings.Contains(endpoint.Path, "//") || strings.Contains(endpoint.Path, "/../") || strings.Contains(endpoint.Path, "/./") {
		return ErrInvalid
	}
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" {
		return ErrInvalid
	}
	host := endpoint.Hostname()
	ip, parseErr := netip.ParseAddr(host)
	if parseErr == nil && ip.Zone() == "" && ip.IsLoopback() && ip.String() == host {
		return nil
	}
	if !allowRemote || endpoint.Scheme != "https" || parseErr == nil && !publicAddress(ip) {
		return ErrInvalid
	}
	if strings.Contains(host, "%") || host == "" || strings.EqualFold(host, "localhost") {
		return ErrInvalid
	}
	return nil
}
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
func fetchWithCredentials(ctx context.Context, source Source, resolver CredentialResolver) (Snapshot, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	endpoint, _ := url.Parse(source.URL)
	localIP, ipErr := netip.ParseAddr(endpoint.Hostname())
	local := ipErr == nil && localIP.IsLoopback()
	dialer := net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || host != endpoint.Hostname() {
				return nil, errors.New("metadata address rejected")
			}
			if local {
				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(localIP.String(), port))
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addresses) == 0 || len(addresses) > 32 {
				return nil, errors.New("metadata address unavailable")
			}
			for _, ip := range addresses {
				if !publicAddress(ip) {
					return nil, errors.New("metadata address rejected")
				}
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, source.URL, nil)
	if err != nil {
		return Snapshot{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "open-trestle/modelcatalog")
	if source.CredentialEnvironment != "" {
		if resolver == nil {
			return Snapshot{}, ErrInvalid
		}
		provider, err := resolver.ResolveOpenAICredentials(source.CredentialEnvironment)
		if err != nil || provider == nil {
			return Snapshot{}, ErrInvalid
		}
		key, err := provider.Retrieve(requestCtx)
		if err != nil || key.Authorize(request) != nil {
			return Snapshot{}, ErrInvalid
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > MaxResponseBytes || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return Snapshot{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes {
		return Snapshot{}, ErrInvalid
	}
	models, err := parseModels(source.Kind, data)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{source, time.Now().UTC().Format(time.RFC3339Nano), Digest(data), models}, nil
}

func validCredentialReference(value string) bool {
	if len(value) < 23 || len(value) > 128 || !strings.HasPrefix(value, "OPEN_TRESTLE_PROVIDER_") {
		return false
	}
	for _, r := range value {
		if r != '_' && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
