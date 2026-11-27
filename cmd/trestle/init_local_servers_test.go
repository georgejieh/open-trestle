package main

import (
	"slices"
	"testing"
)

// llama.cpp is offered at its current default port and still looked for at
// the port earlier builds used.
func TestInitLooksForLlamaCppAtBothDefaultPorts(t *testing.T) {
	type server = struct{ name, endpoint string }
	if !slices.Contains(initLocalServers, server{"llama.cpp", "http://127.0.0.1:9931/v1"}) || !slices.Contains(initEarlierLocalServers, server{"llama.cpp", "http://127.0.0.1:8080/v1"}) {
		t.Fatalf("offered %v, also looked for %v", initLocalServers, initEarlierLocalServers)
	}
}
