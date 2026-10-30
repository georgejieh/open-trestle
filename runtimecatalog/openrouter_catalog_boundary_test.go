package runtimecatalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type refusingBrokeredResolver struct{ calls int }

func (r *refusingBrokeredResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	r.calls++
	return nil, runtimecatalog.ErrInvalidRouteAuthority
}

func TestBrokeredCatalogExpiryAndLocalOnlyRefuseBeforeResolver(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	configuration, inventory := brokeredRuntimePolicy(t, now)
	for _, denial := range []string{"expired", "until boundary", "future", "local only"} {
		resolver := &refusingBrokeredResolver{}
		if denial != "local only" {
			at := now.Add(2 * time.Second)
			if denial == "until boundary" {
				at = now.Add(time.Second)
			}
			if denial == "future" {
				at = now.Add(-time.Minute - time.Nanosecond)
			}
			clock := &requiredClock{at: at}
			if _, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, resolver, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Timeout: time.Minute}, HTTPClientIdentity: requiredDigest("negative")}); err == nil {
				t.Fatalf("%s profile admitted", denial)
			}
		} else {
			if _, err := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, configuration, resolver); err == nil {
				t.Fatal("local-only builder admitted brokered routes")
			}
		}
		if resolver.calls != 0 {
			t.Fatal("denied profile resolved credentials")
		}
	}
}

func TestBrokeredCatalogMissingOrInvalidPrivacyWitnessRefusesBeforeResolver(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	for _, name := range []string{"missing", "invalid"} {
		t.Run(name, func(t *testing.T) {
			inventory, encoded := brokeredRuntimePolicyDocument(t, now, func(manifest []byte) []byte {
				if name == "missing" {
					return []byte(`{"fixture":"no privacy witness"}`)
				}
				var wire map[string]any
				requiredCheck(t, json.Unmarshal(manifest, &wire))
				wire["openrouter_privacy"].(map[string]any)["tools"] = "enabled"
				changed, err := json.Marshal(wire)
				requiredCheck(t, err)
				return changed
			})
			resolver := &refusingBrokeredResolver{}
			policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
			if err == nil {
				_, err = runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, policy, resolver, runtimecatalog.OpenAICatalogOptions{Clock: &requiredClock{at: now}, HTTPClient: &http.Client{Timeout: time.Minute}, HTTPClientIdentity: requiredDigest("negative-witness")})
				if err == nil {
					t.Fatal("invalid witness reached a catalog")
				}
			}
			if resolver.calls != 0 {
				t.Fatal("invalid witness resolved credentials")
			}
		})
	}
}
