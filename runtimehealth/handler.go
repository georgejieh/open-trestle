// Package runtimehealth provides content-free daemon liveness and readiness probes.
package runtimehealth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var ErrInvalidHealthHandler = errors.New("invalid runtime health handler")

type Handler struct{ readiness []<-chan struct{} }

func New(readiness []<-chan struct{}) (*Handler, error) {
	if len(readiness) > 256 {
		return nil, ErrInvalidHealthHandler
	}
	checks := append([]<-chan struct{}(nil), readiness...)
	for _, check := range checks {
		if check == nil {
			return nil, ErrInvalidHealthHandler
		}
	}
	return &Handler{readiness: checks}, nil
}
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setHeaders(writer)
	if h == nil || request == nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	if request.URL.RawQuery != "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if request.URL.EscapedPath() != "/healthz" && request.URL.EscapedPath() != "/readyz" {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	status, code := "live", http.StatusOK
	if request.URL.EscapedPath() == "/readyz" && !h.ready() {
		status, code = "not_ready", http.StatusServiceUnavailable
	} else if request.URL.EscapedPath() == "/readyz" {
		status = "ready"
	}
	encoded, err := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
	}{"open-trestle/health", 1, status})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(code)
	if request.Method == http.MethodGet {
		_, _ = writer.Write(encoded)
	}
}
func (h *Handler) ready() bool {
	for _, check := range h.readiness {
		select {
		case <-check:
		default:
			return false
		}
	}
	return true
}
func setHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}
func (h *Handler) String() string   { return "runtime health handler" }
func (h *Handler) GoString() string { return "runtimehealth.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	value := "runtime health handler"
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = "runtimehealth.Handler{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}

var _ http.Handler = (*Handler)(nil)
