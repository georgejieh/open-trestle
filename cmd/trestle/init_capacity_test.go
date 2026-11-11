package main

import "testing"

// A local server is proposed the named local runtime examples' 32768-token
// context, never more than its listed value: a listed model length is not proof
// that the server was started with it, and a declaration above the server's
// setting would let an over-long prompt be truncated.
func TestInitProposesTheExampleContextForLocalServers(t *testing.T) {
	for _, tc := range []struct {
		provider     string
		listed, want uint64
	}{
		{"local", 0, 32768},
		{"local", 128000, 32768},
		{"local", 16384, 16384},
		{"openrouter", 128000, 128000},
		{"openrouter", 0, 0},
	} {
		if got := initContextProposal(tc.provider, tc.listed); got != tc.want {
			t.Fatalf("%s with listed context %d: proposed %d, want %d", tc.provider, tc.listed, got, tc.want)
		}
	}
}
