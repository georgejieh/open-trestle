package review

import (
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/config"
)

func TestLoadFixtureProducesStableIdentityForEquivalentJSON(t *testing.T) {
	compact := `{"schema_version":1,"provider_route":"local","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":3}]}}}`
	reordered := `{
		"request": {
			"snapshot": {
				"ranges": [{"end_line": 3, "start_line": 1, "path": "main.go"}],
				"revision": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"workspace": "workspace"
			},
			"id": "review-1"
		},
		"requested_capabilities": [],
		"provider_route": "local",
		"schema_version": 1
	}`
	omittedCapabilities := `{"schema_version":1,"provider_route":"local","request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":3}]}}}`

	first, err := LoadFixture(strings.NewReader(compact), config.DefaultLocal())
	if err != nil {
		t.Fatalf("LoadFixture(compact) error = %v", err)
	}
	second, err := LoadFixture(strings.NewReader(reordered), config.DefaultLocal())
	if err != nil {
		t.Fatalf("LoadFixture(reordered) error = %v", err)
	}
	third, err := LoadFixture(strings.NewReader(omittedCapabilities), config.DefaultLocal())
	if err != nil {
		t.Fatalf("LoadFixture(omitted capabilities) error = %v", err)
	}

	if first.Identity() == "" || first.Identity() != second.Identity() || first.Identity() != third.Identity() {
		t.Fatalf("fixture identities = %q, %q, and %q, want equal non-empty values", first.Identity(), second.Identity(), third.Identity())
	}
	if first.Request().ID() != "review-1" {
		t.Fatalf("Request().ID() = %q, want %q", first.Request().ID(), "review-1")
	}
	if first.Request().Snapshot().Identity() != second.Request().Snapshot().Identity() {
		t.Fatalf("snapshot identities = %q and %q, want equality", first.Request().Snapshot().Identity(), second.Request().Snapshot().Identity())
	}
}

func TestLoadFixtureRejectsInvalidOrEffectfulInput(t *testing.T) {
	testCases := []struct {
		name    string
		fixture string
	}{
		{name: "unsupported schema", fixture: `{"schema_version":2,"provider_route":"local","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`},
		{name: "remote route", fixture: `{"schema_version":1,"provider_route":"remote","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`},
		{name: "publication capability", fixture: `{"schema_version":1,"provider_route":"local","requested_capabilities":["publication"],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`},
		{name: "invalid source path", fixture: `{"schema_version":1,"provider_route":"local","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"../main.go","start_line":1,"end_line":1}]}}}`},
		{name: "unknown field", fixture: `{"schema_version":1,"provider_route":"local","requested_capabilities":[],"unexpected":true,"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`},
		{name: "trailing object", fixture: `{"schema_version":1,"provider_route":"local","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}} {}`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := LoadFixture(strings.NewReader(testCase.fixture), config.DefaultLocal()); err == nil {
				t.Fatal("LoadFixture() error = nil, want validation error")
			}
		})
	}
}

func TestLoadFixtureRejectsOversizedInput(t *testing.T) {
	fixture := fmt.Sprintf(`{"schema_version":1,"provider_route":"local","requested_capabilities":[],"request":{"id":"%s","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`, strings.Repeat("a", 1<<20))

	if _, err := LoadFixture(strings.NewReader(fixture), config.DefaultLocal()); err == nil {
		t.Fatal("LoadFixture() error = nil, want oversized fixture error")
	}
}

func TestLoadFixtureRejectsInvalidConfiguration(t *testing.T) {
	fixture := `{"schema_version":1,"provider_route":"","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`

	if _, err := LoadFixture(strings.NewReader(fixture), config.LocalConfig{}); err == nil {
		t.Fatal("LoadFixture() error = nil, want invalid configuration error")
	}
}
