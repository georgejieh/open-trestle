package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

var namedLocalRuntimes = []struct {
	name, generation, verification, endpoint string
}{
	{"llama-cpp", "trestle-generation", "trestle-verification", "http://127.0.0.1:8080/v1"},
	{"ollama-local", "qwen3:8b", "gemma3:4b", "http://127.0.0.1:11434/v1"},
	{"vllm", "trestle-generation", "trestle-verification", "http://127.0.0.1:8000/v1"},
	{"lm-studio", "trestle-generation", "trestle-verification", "http://127.0.0.1:1234/v1"},
}

func namedLocalDocument(t *testing.T, name, file string) []byte {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("..", "examples", "named-local-runtimes", name, file))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func namedLocalConfiguration(t *testing.T, name, endpoint string, qualified bool) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) {
	t.Helper()
	return namedLocalConfigurationWith(t, name, endpoint, qualified, nil)
}

// namedLocalConfigurationWith binds the named template after change edits it.
func namedLocalConfigurationWith(t *testing.T, name, endpoint string, qualified bool, change func(map[string]any)) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) {
	t.Helper()
	inventoryDocument := namedLocalDocument(t, name, "routes.json")
	template := namedLocalDocument(t, name, "runtime-policy.template.json")
	if change != nil {
		var wire map[string]any
		if err := json.Unmarshal(template, &wire); err != nil {
			t.Fatal(err)
		}
		change(wire)
		template, _ = json.Marshal(wire)
	}
	if qualified {
		var wire map[string]any
		if err := json.Unmarshal(inventoryDocument, &wire); err != nil {
			t.Fatal(err)
		}
		for _, value := range wire["routes"].([]any) {
			route := value.(map[string]any)
			route["registry_status"], route["health"], route["quota"] = "approved", "healthy", "available"
			route["content_logging"], route["pricing_known"] = "disabled", true
		}
		inventoryDocument, _ = json.Marshal(wire)
	}
	if endpoint != "" {
		var wire map[string]any
		if err := json.Unmarshal(template, &wire); err != nil {
			t.Fatal(err)
		}
		for _, connection := range wire["connections"].([]any) {
			connection.(map[string]any)["endpoint"] = endpoint
		}
		template, _ = json.Marshal(wire)
	}
	directory := t.TempDir()
	if err := setTestMode(t, directory, 0o700); err != nil {
		t.Fatal(err)
	}
	inventoryPath, templatePath := filepath.Join(directory, "routes.json"), filepath.Join(directory, "template.json")
	for path, data := range map[string][]byte{inventoryPath: inventoryDocument, templatePath: template} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bound, err := runtimeconfig.BindProtectedRuntimePolicy(context.Background(), inventoryPath, templatePath, "local-generation", "local-verification")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryDocument))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(bound), inventory)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, policy
}

func namedLocalCatalog(t *testing.T, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) gateway.RouteDispatcherCatalog {
	t.Helper()
	resolver, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(string) string { t.Error("anonymous local route resolved credentials"); return "" })
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestNamedLocalTemplatesBindWithoutGrantingReadiness(t *testing.T) {
	for _, runtime := range namedLocalRuntimes {
		t.Run(runtime.name, func(t *testing.T) {
			inventory, policy := namedLocalConfiguration(t, runtime.name, "", false)
			if policy.ValidateAgainstInventory(inventory) != nil {
				t.Fatal("unbound template")
			}
			models := map[string]string{}
			for _, candidate := range inventory.Candidates() {
				record := candidate.ResolvedRecord().RouteRegistryRecord()
				route := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
				models[route.AdapterID()] = route.ModelID()
				if route.ModelVersion() != "" || record.Status() != provider.RouteRegistryPending || candidate.OperationalState().Health() != provider.RouteHealthUnknown {
					t.Fatal("example claims readiness or overrides model selector")
				}
			}
			if models["local-generation"] != runtime.generation || models["local-verification"] != runtime.verification {
				t.Fatalf("models=%v", models)
			}
			for _, connection := range policy.Connections() {
				endpoint := runtime.endpoint
				if connection.AdapterID() == "local-verification" {
					switch runtime.name {
					case "llama-cpp":
						endpoint = "http://127.0.0.1:8081/v1"
					case "vllm":
						endpoint = "http://127.0.0.1:8001/v1"
					}
				}
				if connection.Endpoint() != endpoint || connection.Implementation() != "openai_chat_completions" || connection.CredentialMode() != "none" {
					t.Fatalf("connection=%#v", connection)
				}
			}
			plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
			if err != nil {
				t.Fatal(err)
			}
			checker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			if err != nil {
				t.Fatal(err)
			}
			if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
				t.Fatal("pending template passed setup")
			}
			if namedLocalCatalog(t, inventory, policy).Len() != 2 {
				t.Fatal("named template did not reach shared adapters")
			}
		})
	}
}

func namedLocalRequest(t *testing.T) (audit.ReviewScope, provider.Request) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "offline-local-fixture")
	if err != nil {
		t.Fatal(err)
	}
	memoryScope, err := memory.NewScope("tenant-a", "repo-a", "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	if err != nil {
		t.Fatal(err)
	}
	location, err := evidence.NewSourceRange("src/main.go", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := review.NewReviewSnapshot("offline-local-fixture", strings.Repeat("b", 64), []evidence.SourceRange{location})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("return nil\n")
	digest := sha256.Sum256(content)
	item, err := evidence.NewEvidenceItem("source-1", evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), location)
	if err != nil {
		t.Fatal(err)
	}
	source, err := review.NewContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, content)
	if err != nil {
		t.Fatal(err)
	}
	query, err := memory.NewLexicalQuery(memoryScope, "src/main.go", nil, nil, time.UnixMilli(100), 5)
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewContextLimits(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	sanitized, err := review.NewSanitizedModelRequest(scope.Identity(), raw, raw)
	if err != nil {
		t.Fatal(err)
	}
	request, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	return scope, request
}

func TestNamedLocalChatProtocolFixtures(t *testing.T) {
	for _, runtime := range namedLocalRuntimes {
		t.Run(runtime.name, func(t *testing.T) {
			for _, scenario := range []string{"success", "refusal", "missing usage", "mismatched selector", "invalid usage", "cancel before dispatch", "cancel in flight"} {
				t.Run(scenario, func(t *testing.T) {
					document := namedLocalDocument(t, runtime.name, "generation.response.json")
					if scenario == "refusal" {
						document = namedLocalDocument(t, runtime.name, "refusal.response.json")
					}
					var response map[string]any
					if err := json.Unmarshal(document, &response); err != nil {
						t.Fatal(err)
					}
					switch scenario {
					case "missing usage":
						delete(response, "usage")
					case "mismatched selector":
						response["model"] = runtime.generation + "-different"
					case "invalid usage":
						response["usage"].(map[string]any)["total_tokens"] = 1
					}
					document, _ = json.Marshal(response)
					var calls atomic.Int32
					started := make(chan struct{})
					serverCancelled := make(chan struct{})
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						var wire struct {
							Model     string `json:"model"`
							Messages  []struct{ Role, Content string }
							MaxTokens uint32 `json:"max_tokens"`
							Stream    bool
						}
						var fields map[string]json.RawMessage
						if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
							t.Error(err)
						}
						encoded, _ := json.Marshal(fields)
						if err := json.Unmarshal(encoded, &wire); err != nil {
							t.Error(err)
						}
						if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" || len(fields) != 4 || wire.Model != runtime.generation || wire.MaxTokens != 1024 || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[0].Content == "" || wire.Messages[1].Role != "user" || !strings.Contains(wire.Messages[1].Content, "return nil") {
							t.Errorf("unbound request: %s %s %s", r.Method, r.URL, encoded)
						}
						if scenario == "cancel in flight" {
							close(started)
							<-r.Context().Done()
							close(serverCancelled)
							return
						}
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(document)
					}))
					defer server.Close()
					inventory, policy := namedLocalConfiguration(t, runtime.name, server.URL+"/v1", true)
					catalog := namedLocalCatalog(t, inventory, policy)
					scope, request := namedLocalRequest(t)
					authorization, err := authorizeSetupRoute(scope, request, inventory, policy, policy.Ranking(), inventory.Candidates(), policy.Requirements(), policy.Budget())
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if scenario == "cancel before dispatch" {
						cancel()
					}
					if scenario == "cancel in flight" {
						go func() {
							select {
							case <-started:
								cancel()
							case <-ctx.Done():
							}
						}()
					}
					result, err := gateway.DispatchAuthorizedRouteFromCatalog(ctx, catalog, authorization, request)
					if scenario == "cancel before dispatch" {
						if err == nil || calls.Load() != 0 {
							t.Fatal("pre-cancelled request dispatched")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					switch scenario {
					case "mismatched selector", "invalid usage":
						if result.Failure() != gateway.RouteFailureInvalidResponse {
							t.Fatalf("failure=%s", result.Failure())
						}
					case "cancel in flight":
						if result.Failure() != gateway.RouteFailureCancelled || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown {
							t.Fatalf("cancel=%#v", result)
						}
						select {
						case <-serverCancelled:
						case <-time.After(5 * time.Second):
							t.Fatal("server did not observe cancellation")
						}
					default:
						if result.Status() != gateway.RouteDispatchSucceeded {
							t.Fatalf("result=%#v failure=%s", result, result.Failure())
						}
						if scenario == "missing usage" {
							if result.Usage().IsKnown() {
								t.Fatal("invented missing usage")
							}
							return
						}
						if result.Usage().InputTokens() != 120 || result.Usage().OutputTokens() != 30 && scenario != "refusal" {
							t.Fatalf("usage=%#v", result.Usage())
						}
						if scenario == "refusal" && result.Response().Parts()[0].Kind() != provider.ResponsePartRefusal {
							t.Fatal("refusal lost")
						}
					}
					if calls.Load() != 1 {
						t.Fatalf("calls=%d", calls.Load())
					}
				})
			}
		})
	}
}

type namedLocalInferenceFactory struct {
	catalog gateway.RouteDispatcherCatalog
}

func (f namedLocalInferenceFactory) FactoryIdentity() string {
	return setupDigest("named-local-real-adapter-fixture")
}
func (f namedLocalInferenceFactory) Build(context.Context, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) (gateway.RouteDispatcherCatalog, error) {
	return f.catalog, nil
}

func TestNamedLocalTemplatesRunActualSetupInferencePair(t *testing.T) {
	for _, runtime := range namedLocalRuntimes {
		t.Run(runtime.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var wire struct {
					Model     string
					Messages  []struct{ Role, Content string }
					MaxTokens uint32 `json:"max_tokens"`
					Stream    bool
				}
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Error(err)
				}
				sequence := calls.Add(1)
				role, expectedModel, task := "generation", runtime.generation, "candidate_generation"
				if sequence == 2 {
					role, expectedModel, task = "verification", runtime.verification, "candidate_verification"
				}
				if sequence > 2 || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "" || wire.Model != expectedModel || wire.MaxTokens != 256 || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[0].Content == "" || wire.Messages[1].Role != "user" || !strings.Contains(wire.Messages[1].Content, `"task":"`+task+`"`) || !strings.Contains(wire.Messages[1].Content, "func setupProbe() {}") {
					t.Errorf("unexpected bounded setup request: %#v", wire)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(namedLocalDocument(t, runtime.name, role+".response.json"))
			}))
			defer server.Close()
			inventory, policy := namedLocalConfiguration(t, runtime.name, server.URL+"/v1", true)
			plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
			if err != nil {
				t.Fatal(err)
			}
			policyChecker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			if err != nil {
				t.Fatal(err)
			}
			plan = policyCheckedPlan(t, plan, policyChecker)
			checker, err := NewLocalInferenceChecker(policyChecker, namedLocalInferenceFactory{namedLocalCatalog(t, inventory, policy)})
			if err != nil {
				t.Fatal(err)
			}
			result := checker.Check(context.Background(), plan)
			if result.State() != CheckPassed || calls.Load() != 2 {
				t.Fatalf("state=%s calls=%d", result.State(), calls.Load())
			}
		})
	}
}
