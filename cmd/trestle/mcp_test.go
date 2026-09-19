package main

import (
	"bytes"
	"encoding/json"
	"github.com/georgejieh/open-trestle/mcpserver"
	"strings"
	"testing"
)

func TestRunMCPServesModernDiscoveryWithoutStdoutNoise(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	meta := map[string]any{"io.modelcontextprotocol/protocolVersion": mcpserver.ProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": map[string]any{"_meta": meta}})
	request = append(request, '\n')
	var stdout, stderr bytes.Buffer
	exit := runMCP(nil, bytes.NewReader(request), &stdout, &stderr)
	if exit != 0 || stderr.Len() != 0 {
		t.Fatalf("run=(%d,%q)", exit, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], mcpserver.ProtocolVersion) || strings.Contains(stdout.String(), "OPEN_TRESTLE_API_TOKEN") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
func TestRunMCPRequiresEnvironmentCredential(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	var stdout, stderr bytes.Buffer
	if exit := runMCP(nil, bytes.NewReader(nil), &stdout, &stderr); exit != 2 || !strings.Contains(stderr.String(), "OPEN_TRESTLE_API_TOKEN") || stdout.Len() != 0 {
		t.Fatalf("run=(%d,%q,%q)", exit, stdout.String(), stderr.String())
	}
}
