package provider

import (
	"errors"
	"strings"
	"testing"
)

func TestRouteReferencePreservesExactTaggedModelSelector(t *testing.T) {
	for _, selector := range []string{
		"qwen2.5-coder:7b", "library/llama3.2:3b", "org/Model:exact-q4", "provider/model:free",
		"Model:V1_2+Q4.0", "evil.example:443", "127.0.0.1:8080", "https:evil.example",
		"m:" + strings.Repeat("t", 253),
	} {
		t.Run(selector, func(t *testing.T) {
			route, err := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "connection", selector, "")
			if err != nil || route.ModelID() != selector || route.ModelVersion() != "" || route.Validate() != nil {
				t.Fatalf("selector %q was rejected or rewritten: %v", selector, err)
			}
			other, err := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "connection", selector+"x", "")
			if len(selector) < maxProviderModelIDBytes && (err != nil || other == route) {
				t.Fatal("different exact tag did not produce a different route")
			}
		})
	}
}

func TestRouteReferenceRejectsMalformedTaggedModelSelectors(t *testing.T) {
	for _, selector := range []string{
		"https://host/model", "https://user:secret@host/model", "model:", ":tag", "model::tag",
		"Model:v1:v2", "org:tag/model", "model:tag/child", "model:tag?key=value", "model:tag\n",
		"model:tag\r", "model:tag\x00", "model:tag#fragment", "model:tag@version", "model:tag%20",
		"model: tag", "model:.tag", "model:-tag", "model:_tag", "model:+tag", "model:täg",
		"/model:tag", "org//model:tag", "org/../model:tag", "model/:tag", "m:" + strings.Repeat("t", 254),
	} {
		t.Run(selector, func(t *testing.T) {
			for _, version := range []string{"", "Version"} {
				route, err := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "connection", selector, version)
				if !errors.Is(err, ErrInvalidModelID) || route != (RouteReference{}) {
					t.Fatalf("selector %q version %q: route=%#v err=%v, want invalid model ID", selector, version, route, err)
				}
			}
		})
	}
}

func TestRouteReferenceRejectsConflictingTaggedSelectorAndVersion(t *testing.T) {
	// Host/port and opaque-URI lookalikes are model text only with an empty version.
	// Unlike the old generic invalid-field fixture, these cases isolate the conflict.
	for _, selector := range []string{"qwen2.5-coder:7b", "provider/model:free", "evil.example:443", "127.0.0.1:8080", "https:evil.example"} {
		t.Run(selector, func(t *testing.T) {
			route, err := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "connection", selector, "Version")
			if !errors.Is(err, ErrInvalidModelVersion) || route != (RouteReference{}) {
				t.Fatalf("selector %q accepted conflicting version or wrong refusal: %v", selector, err)
			}
		})
	}
}

func TestRouteReferenceTaggedExtensionPreservesOldModelPairs(t *testing.T) {
	for _, pair := range [][2]string{
		{"Model-A", ""}, {"Qwen2.5-Coder", "32B-q4"}, {"org/Model+Q4.0", "Version_1+Q4"},
		{strings.Repeat("m", 255), strings.Repeat("v", 128)},
	} {
		route, err := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "connection", pair[0], pair[1])
		if err != nil || route.ModelID() != pair[0] || route.ModelVersion() != pair[1] || route.Validate() != nil {
			t.Fatalf("old pair was rejected or rewritten: %v", err)
		}
	}
}
