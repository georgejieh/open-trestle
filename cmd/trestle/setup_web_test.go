package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSetupWebHandlerServesConsoleAndProtectsAPI(t *testing.T) {
	root := t.TempDir()
	token := "setup-" + strings.Repeat("s", 40)
	handler, err := newSetupWebHandler(context.Background(), filepath.Join(root, "plan.json"), token, func(string) string { return "" }, fixedSetupClock{setupTimeCLI()}, "127.0.0.1:8742", setupGitHubPermissionHostConfiguration{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if handler.Close() != nil {
			t.Error("setup handler cleanup failed")
		}
	}()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8742/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTemporaryRedirect || response.Header().Get("Location") != "/console/setup" {
		t.Fatalf("redirect=%d %s", response.Code, response.Header().Get("Location"))
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8742/api/v1/setup", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("api=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8742/console/", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("console=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "http://localhost:8742/console/", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("host=%d", response.Code)
	}
}
func TestSetupWebRejectsNonLoopbackAndMissingAuthority(t *testing.T) {
	var stdout, stderr bytes.Buffer
	getenv := func(string) string { return "" }
	if code := runSetupWeb(context.Background(), []string{"--state", filepath.Join(t.TempDir(), "plan.json"), "--listen", "0.0.0.0:8742"}, getenv, &stdout, &stderr); code != 2 {
		t.Fatalf("remote=%d", code)
	}
	if code := runSetupWeb(context.Background(), []string{"--state", filepath.Join(t.TempDir(), "plan.json")}, getenv, &stdout, &stderr); code != 2 {
		t.Fatalf("token=%d", code)
	}
}
func TestValidSetupWebAddressIsCanonicalLoopback(t *testing.T) {
	for _, value := range []string{"127.0.0.1:8742", "[::1]:8742"} {
		if !validSetupWebAddress(value) {
			t.Fatalf("rejected %s", value)
		}
	}
	for _, value := range []string{"localhost:8742", "0.0.0.0:8742", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:08742", "[0:0:0:0:0:0:0:1]:8742"} {
		if validSetupWebAddress(value) {
			t.Fatalf("accepted %s", value)
		}
	}
}
func TestSetupWebValidationDoesNotCreateState(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	code := runSetupWeb(context.Background(), []string{"--state", state, "--listen", "localhost:8742"}, func(name string) string {
		if name == "OPEN_TRESTLE_SETUP_TOKEN" {
			return "setup-" + strings.Repeat("s", 40)
		}
		return ""
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	for _, path := range []string{state, state + ".lock", state + ".receipts", state + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
}

type setupWebTestAddress string

func (a setupWebTestAddress) Network() string { return "tcp" }
func (a setupWebTestAddress) String() string  { return string(a) }

type setupWebTestListener struct {
	closed  chan struct{}
	once    sync.Once
	address net.Addr
}

func (l *setupWebTestListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, errors.New("closed")
}
func (l *setupWebTestListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *setupWebTestListener) Addr() net.Addr { return l.address }
func TestSetupWebGracefullyStopsInjectedListener(t *testing.T) {
	listener := &setupWebTestListener{closed: make(chan struct{}), address: setupWebTestAddress("127.0.0.1:8742")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	code := runSetupWebWithListener(ctx, []string{"--state", filepath.Join(t.TempDir(), "plan.json"), "--listen", "127.0.0.1:8742"}, func(name string) string {
		if name == "OPEN_TRESTLE_SETUP_TOKEN" {
			return "setup-" + strings.Repeat("s", 40)
		}
		return ""
	}, &stdout, &stderr, func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "127.0.0.1:8742" {
			t.Fatal("wrong authority")
		}
		// Start with a live owned lifetime; cancel only after construction.
		cancel()
		return listener, nil
	})
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "http://127.0.0.1:8742/console/setup") {
		t.Fatalf("run=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}
