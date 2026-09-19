// Package lspserver exposes verified review findings as read-only LSP diagnostics.
package lspserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"io"
	"math"
	"net/url"
	"path"
	"reflect"
	"strconv"
	"strings"
)

const (
	maxLSPHeaderBytes = 8 << 10
	maxLSPBodyBytes   = 1 << 20
)

var (
	// ErrInvalidServer identifies a missing diagnostic reader.
	ErrInvalidServer = errors.New("invalid LSP server")
	// ErrInvalidFrame identifies malformed or excessive LSP transport input.
	ErrInvalidFrame = errors.New("invalid LSP frame")
	// ErrOutput identifies a failed protocol response write.
	ErrOutput = errors.New("LSP output failure")
)

// DiagnosticReader loads one canonical verified diagnostic set.
type DiagnosticReader interface {
	GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error)
}

// Server implements a bounded read-only LSP 3.17 diagnostic provider.
type Server struct{ reader DiagnosticReader }

func New(reader DiagnosticReader) (*Server, error) {
	if isNilReader(reader) {
		return nil, ErrInvalidServer
	}
	return &Server{reader: reader}, nil
}

type session struct {
	initialized, shutdown bool
	scope                 audit.ReviewScope
	rootURI               *url.URL
}

func (s *Server) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	if s == nil || isNilReader(s.reader) || ctx == nil || input == nil || output == nil {
		return ErrInvalidServer
	}
	reader := bufio.NewReaderSize(input, 8<<10)
	state := session{}
	for {
		body, err := readFrame(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		response, exit := s.handle(ctx, &state, body)
		if response != nil {
			if err := writeFrame(output, response); err != nil {
				return err
			}
		}
		if exit {
			return nil
		}
	}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Server) handle(ctx context.Context, state *session, body []byte) (any, bool) {
	var message request
	if json.Unmarshal(body, &message) != nil || message.JSONRPC != "2.0" || message.Method == "" {
		return failure(json.RawMessage("null"), -32700, "Invalid JSON-RPC message."), false
	}
	notification := len(message.ID) == 0
	if !notification && !validJSONRPCID(message.ID) {
		return failure(json.RawMessage("null"), -32600, "Invalid request identifier."), false
	}
	switch message.Method {
	case "initialize":
		if notification || state.initialized {
			return failure(message.ID, -32600, "Invalid initialize request."), false
		}
		result, err := initialize(state, message.Params)
		if err != nil {
			return failure(message.ID, -32602, "Invalid initialization parameters."), false
		}
		return success(message.ID, result), false
	case "initialized":
		if !notification || !state.initialized {
			return nil, false
		}
		return nil, false
	case "textDocument/diagnostic":
		if notification {
			return nil, false
		}
		if !state.initialized || state.shutdown {
			return failure(message.ID, -32002, "Server is not available."), false
		}
		return s.diagnostic(ctx, state, message.ID, message.Params), false
	case "shutdown":
		if notification || !state.initialized {
			return failure(message.ID, -32600, "Invalid shutdown request."), false
		}
		state.shutdown = true
		return success(message.ID, nil), false
	case "exit":
		if !notification {
			return failure(message.ID, -32600, "Exit must be a notification."), false
		}
		return nil, true
	case "$/cancelRequest":
		return nil, false
	default:
		if notification {
			return nil, false
		}
		return failure(message.ID, -32601, "Method not found."), false
	}
}
func initialize(state *session, encoded []byte) (map[string]any, error) {
	var params struct {
		RootURI               string `json:"rootUri"`
		InitializationOptions struct {
			TenantID     string `json:"tenant_id"`
			RepositoryID string `json:"repository_id"`
			ReviewRunID  string `json:"review_run_id"`
		} `json:"initializationOptions"`
	}
	if json.Unmarshal(encoded, &params) != nil {
		return nil, ErrInvalidFrame
	}
	root, err := url.Parse(params.RootURI)
	if err != nil || root.Scheme != "file" || root.User != nil || root.RawQuery != "" || root.Fragment != "" || root.Path == "" {
		return nil, ErrInvalidFrame
	}
	root.Path = path.Clean(root.Path)
	root.RawPath = ""
	scope, err := audit.NewReviewScope(params.InitializationOptions.TenantID, params.InitializationOptions.RepositoryID, params.InitializationOptions.ReviewRunID)
	if err != nil {
		return nil, err
	}
	state.initialized = true
	state.scope = scope
	state.rootURI = root
	capabilities := map[string]any{
		"positionEncoding": "utf-16", "textDocumentSync": 0,
		"diagnosticProvider": map[string]any{
			"identifier": "open-trestle", "interFileDependencies": true, "workspaceDiagnostics": false,
		},
	}
	return map[string]any{
		"capabilities": capabilities,
		"serverInfo":   map[string]any{"name": "open-trestle", "version": "0.1.0"},
	}, nil
}
func (s *Server) diagnostic(ctx context.Context, state *session, id json.RawMessage, encoded []byte) any {
	var params struct {
		TextDocument struct {
			URI string `json:"uri"`
		} `json:"textDocument"`
		PreviousResultID string `json:"previousResultId,omitempty"`
	}
	if json.Unmarshal(encoded, &params) != nil || len(params.PreviousResultID) > 64 {
		return failure(id, -32602, "Invalid diagnostic parameters.")
	}
	relative, err := relativeDocumentPath(state.rootURI, params.TextDocument.URI)
	if err != nil {
		return failure(id, -32602, "Document is outside the initialized workspace.")
	}
	set, err := s.reader.GetDiagnosticSet(ctx, state.scope)
	if err != nil || set.Validate() != nil || set.Scope().Identity() != state.scope.Identity() {
		return failure(id, -32603, "Verified diagnostics are unavailable.")
	}
	if params.PreviousResultID == set.Identity() {
		return success(id, map[string]any{"kind": "unchanged", "resultId": set.Identity()})
	}
	items := make([]lspDiagnostic, 0)
	for _, finding := range set.Findings() {
		if finding.Path() != relative {
			continue
		}
		items = append(items, toLSPDiagnostic(set, finding))
	}
	return success(id, map[string]any{"kind": "full", "resultId": set.Identity(), "items": items})
}

type lspPosition struct {
	Line      uint32 `json:"line"`
	Character uint32 `json:"character"`
}
type lspRange struct {
	Start lspPosition `json:"start"`
	End   lspPosition `json:"end"`
}
type lspDiagnostic struct {
	Range    lspRange       `json:"range"`
	Severity int            `json:"severity"`
	Code     string         `json:"code"`
	Source   string         `json:"source"`
	Message  string         `json:"message"`
	Data     map[string]any `json:"data"`
}

func toLSPDiagnostic(set diagnostics.Set, finding diagnostics.Finding) lspDiagnostic {
	return lspDiagnostic{
		Range: lspRange{
			Start: lspPosition{Line: finding.StartLine() - 1},
			End:   lspPosition{Line: finding.EndLine()},
		},
		Severity: int(finding.Severity()), Code: finding.Fingerprint(), Source: "open-trestle",
		Message: finding.Title() + ": " + finding.Message() + "\n\n[untrusted review output; verify before editing]",
		Data: map[string]any{
			"diagnostic_identity": finding.Identity(), "source_identity": finding.SourceIdentity(),
			"evidence_ids": finding.EvidenceIDs(), "diagnostic_set_identity": set.Identity(),
			"snapshot_identity": set.SnapshotIdentity(), "head_revision": set.HeadRevision(),
		},
	}
}
func relativeDocumentPath(root *url.URL, raw string) (string, error) {
	document, err := url.Parse(raw)
	if err != nil || document.Scheme != "file" || document.User != nil || document.RawQuery != "" || document.Fragment != "" || document.Host != root.Host {
		return "", ErrInvalidFrame
	}
	rootPath := strings.TrimSuffix(root.Path, "/")
	prefix := rootPath + "/"
	if !strings.HasPrefix(document.Path, prefix) {
		return "", ErrInvalidFrame
	}
	relative := strings.TrimPrefix(document.Path, prefix)
	if relative == "" || path.Clean(relative) != relative || strings.HasPrefix(relative, "../") {
		return "", ErrInvalidFrame
	}
	return relative, nil
}
func readFrame(reader *bufio.Reader) ([]byte, error) {
	headerBytes := 0
	contentLength := -1
	for {
		line, err := readHeaderLine(reader, maxLSPHeaderBytes-headerBytes)
		if errors.Is(err, io.EOF) && line == "" {
			return nil, io.EOF
		}
		if err != nil {
			return nil, ErrInvalidFrame
		}
		headerBytes += len(line)
		if line == "\r\n" {
			break
		}
		if !strings.HasSuffix(line, "\r\n") {
			return nil, ErrInvalidFrame
		}
		parts := strings.SplitN(strings.TrimSuffix(line, "\r\n"), ":", 2)
		if len(parts) != 2 {
			return nil, ErrInvalidFrame
		}
		if strings.EqualFold(parts[0], "Content-Length") {
			if contentLength != -1 {
				return nil, ErrInvalidFrame
			}
			value, parseErr := strconv.Atoi(strings.TrimSpace(parts[1]))
			if parseErr != nil || value < 0 || value > maxLSPBodyBytes {
				return nil, ErrInvalidFrame
			}
			contentLength = value
		}
	}
	if contentLength < 0 {
		return nil, ErrInvalidFrame
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, ErrInvalidFrame
	}
	return body, nil
}
func readHeaderLine(reader *bufio.Reader, limit int) (string, error) {
	if limit <= 0 {
		return "", ErrInvalidFrame
	}
	line := make([]byte, 0, min(limit, 1024))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > limit {
			return "", ErrInvalidFrame
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return string(line), err
	}
}
func validJSONRPCID(encoded []byte) bool {
	if len(encoded) == 0 || len(encoded) > 128 {
		return false
	}
	var value any
	if json.Unmarshal(encoded, &value) != nil {
		return false
	}
	switch candidate := value.(type) {
	case string:
		return candidate != "" && len(candidate) <= 96
	case float64:
		return candidate >= 0 && candidate <= 1<<53 && math.Trunc(candidate) == candidate
	default:
		return false
	}
}

func writeFrame(output io.Writer, response any) error {
	body, err := json.Marshal(response)
	if err != nil || len(body) > maxLSPBodyBytes {
		return ErrOutput
	}
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := io.WriteString(output, header); err != nil {
		return ErrOutput
	}
	if _, err := output.Write(body); err != nil {
		return ErrOutput
	}
	return nil
}
func success(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}
func failure(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}}
}
func isNilReader(reader DiagnosticReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
