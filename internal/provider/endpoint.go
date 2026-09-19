package provider

import (
	"errors"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxServiceEndpointBytes = 2048

// ErrInvalidServiceEndpoint identifies an unsafe or noncanonical provider endpoint.
var ErrInvalidServiceEndpoint = errors.New("invalid provider service endpoint")

// ServiceEndpointLocality is a closed, syntax-derived endpoint location class.
type ServiceEndpointLocality uint8

const (
	ServiceEndpointLoopback ServiceEndpointLocality = iota + 1
	ServiceEndpointRemote
)

func (l ServiceEndpointLocality) String() string {
	switch l {
	case ServiceEndpointLoopback:
		return "loopback"
	case ServiceEndpointRemote:
		return "remote"
	default:
		return ""
	}
}
func (l ServiceEndpointLocality) Validate() error {
	if l.String() == "" {
		return ErrInvalidServiceEndpoint
	}
	return nil
}

// ClassifyServiceEndpoint validates an endpoint and rejects ambiguous local or non-unicast authorities.
func ClassifyServiceEndpoint(raw string) (ServiceEndpointLocality, error) {
	endpoint, err := ParseServiceEndpoint(raw)
	if err != nil {
		return 0, ErrInvalidServiceEndpoint
	}
	host := endpoint.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return 0, ErrInvalidServiceEndpoint
	}
	if address := net.ParseIP(host); address != nil {
		if address.IsLoopback() {
			return ServiceEndpointLoopback, nil
		}
		if !address.IsGlobalUnicast() {
			return 0, ErrInvalidServiceEndpoint
		}
		return ServiceEndpointRemote, nil
	}
	return ServiceEndpointRemote, nil
}

// ParseServiceEndpoint validates one canonical HTTPS or loopback HTTP provider authority.
func ParseServiceEndpoint(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxServiceEndpointBytes || !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw {
		return nil, ErrInvalidServiceEndpoint
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.String() != raw || endpoint.Opaque != "" || endpoint.User != nil || endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" || endpoint.RawPath != "" {
		return nil, ErrInvalidServiceEndpoint
	}
	if strings.HasSuffix(endpoint.Host, ":") || !validServiceHost(endpoint.Hostname()) || !validServicePort(endpoint.Port()) || strings.ContainsAny(endpoint.Path, "\\\x00\r\n\t ") {
		return nil, ErrInvalidServiceEndpoint
	}
	cleaned := path.Clean(endpoint.Path)
	if cleaned == "." {
		cleaned = ""
	}
	if endpoint.Path != cleaned && endpoint.Path != cleaned+"/" || strings.Contains(endpoint.Path, "//") {
		return nil, ErrInvalidServiceEndpoint
	}
	if endpoint.Scheme == "https" {
		return endpoint, nil
	}
	address := net.ParseIP(endpoint.Hostname())
	if endpoint.Scheme != "http" || address == nil || !address.IsLoopback() {
		return nil, ErrInvalidServiceEndpoint
	}
	return endpoint, nil
}
func validServiceHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if address := net.ParseIP(host); address != nil {
		return address.String() == host
	}
	if strings.ToLower(host) != host {
		return false
	}
	numericOnly := true
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			numericOnly = false
			break
		}
	}
	if numericOnly {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}
func validServicePort(port string) bool {
	if port == "" {
		return true
	}
	value, err := strconv.Atoi(port)
	return err == nil && value >= 1 && value <= 65535 && strconv.Itoa(value) == port
}
