package openai

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestDefaultClientDoesNotInheritAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18999")
	t.Setenv("NO_PROXY", "")
	client, err := boundedClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("default client did not return an inspectable HTTP transport")
	}
	if transport.Proxy != nil {
		request, err := http.NewRequest(http.MethodGet, "https://openrouter.ai/api/v1/models", nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := transport.Proxy(request)
		if err != nil {
			t.Fatal(err)
		}
		if proxy != nil {
			t.Fatalf("default provider transport selected unapproved ambient proxy %s without any network call", proxy.Host)
		}
		t.Fatal("default provider transport retains an ambient proxy function")
	}
}

func TestNilTransportClientDoesNotInheritAmbientProxy(t *testing.T) {
	configured := &http.Client{Timeout: time.Second}
	client, err := boundedClient(configured)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || configured.Transport != nil || client.Timeout != time.Second {
		t.Fatal("nil transport did not receive an isolated direct transport")
	}
}

func TestDefaultTransportBoundsAndExplicitProxyAuthority(t *testing.T) {
	client, err := boundedClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.MaxResponseHeaderBytes != maximumHeaderBytes || client.Timeout != defaultRequestTimeout {
		t.Fatal("default TLS, header or time bounds changed")
	}
	if err := client.CheckRedirect(nil, nil); err != ErrInvalidConfig {
		t.Fatal("redirect was not refused")
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:18999")
	explicit := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	configured := &http.Client{Transport: explicit, Timeout: time.Second}
	injected, err := boundedClient(configured)
	if err != nil || injected.Transport != explicit || configured.CheckRedirect != nil {
		t.Fatal("explicit transport authority was replaced or caller mutated")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/v1", nil)
	selected, err := injected.Transport.(*http.Transport).Proxy(request)
	if err != nil || selected.String() != proxyURL.String() {
		t.Fatal("explicit proxy authority was not preserved")
	}
}

func TestDefaultClientDoesNotInheritProcessTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	proxyURL, _ := url.Parse("http://127.0.0.1:18999")
	http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client, err := boundedClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default provider transport inherited process-wide authority")
	}
}
