package runtimeadmin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validOptions() ConfigurationOptions {
	return ConfigurationOptions{
		TenantID: "tenant-a", RepositoryIDs: []string{"repo-b", "repo-a"},
		MetadataBackend: MetadataPostgres, DatabaseAuthorityIdentity: digest("database"), ArtifactBackend: ArtifactS3,
		ArtifactProtection: ProtectionEnvelopeEncrypted, NotificationBackend: NotificationPostgres,
		RateLimitBackend: RateLimitPostgres, RateLimitAuthorityIdentity: digest("rate-limit"),
		ReviewMode: ReviewRequired, WebhookIngress: true, LocalWorkers: true,
		PublicationEnabled: true, PublicationFenceVerified: true,
		RouteInventoryIdentity: digest("inventory"), RuntimePolicyIdentity: digest("policy"),
		RouteCount: 2, Handlers: []HandlerBinding{{Kind: "verify_candidates", Identity: digest("verify")}, {Kind: "generate_candidates", Identity: digest("generate")}},
	}
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestConfigurationIsCanonicalAndScoped(t *testing.T) {
	first, err := NewConfiguration(validOptions())
	if err != nil {
		t.Fatal(err)
	}
	options := validOptions()
	options.RepositoryIDs = []string{"repo-a", "repo-b"}
	options.Handlers[0], options.Handlers[1] = options.Handlers[1], options.Handlers[0]
	second, err := NewConfiguration(options)
	if err != nil || first.Identity() != second.Identity() {
		t.Fatalf("noncanonical configuration: %v", err)
	}
	repositories := first.RepositoryIDs()
	repositories[0] = "changed"
	if first.RepositoryIDs()[0] != "repo-a" {
		t.Fatal("repository slice escaped")
	}
	if first.DatabaseAuthorityIdentity() != digest("database") {
		t.Fatal("database authority missing")
	}
	if first.RateLimitBackend() != RateLimitPostgres || first.RateLimitAuthorityIdentity() != digest("rate-limit") {
		t.Fatal("rate-limit authority missing")
	}
	changedOptions := validOptions()
	changedOptions.DatabaseAuthorityIdentity = digest("other-database")
	changed, _ := NewConfiguration(changedOptions)
	if changed.Identity() == first.Identity() {
		t.Fatal("database authority omitted from configuration identity")
	}
	changedOptions = validOptions()
	changedOptions.RateLimitAuthorityIdentity = digest("other-rate-limit")
	changed, _ = NewConfiguration(changedOptions)
	if changed.Identity() == first.Identity() {
		t.Fatal("rate-limit authority omitted from configuration identity")
	}
}

func TestConfigurationRejectsInconsistentAuthority(t *testing.T) {
	cases := []func(*ConfigurationOptions){
		func(o *ConfigurationOptions) { o.TenantID = "../tenant" },
		func(o *ConfigurationOptions) { o.RepositoryIDs = []string{"repo-a", "repo-a"} },
		func(o *ConfigurationOptions) { o.MetadataBackend = "mysql" },
		func(o *ConfigurationOptions) { o.DatabaseAuthorityIdentity = "" },
		func(o *ConfigurationOptions) { o.RateLimitAuthorityIdentity = "" },
		func(o *ConfigurationOptions) { o.PublicationEnabled = false },
		func(o *ConfigurationOptions) { o.RouteInventoryIdentity = "" },
		func(o *ConfigurationOptions) { o.Handlers = append(o.Handlers, o.Handlers[0]) },
		func(o *ConfigurationOptions) {
			o.Handlers = append(o.Handlers, HandlerBinding{Kind: o.Handlers[0].Kind, Identity: digest("different")})
		},
	}
	for index, mutate := range cases {
		options := validOptions()
		mutate(&options)
		if _, err := NewConfiguration(options); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("case %d: %v", index, err)
		}
	}
}

func TestServiceReportsExactReadinessWithoutPayloads(t *testing.T) {
	configuration, _ := NewConfiguration(validOptions())
	ready := make(chan struct{})
	service, err := NewService(configuration, []ReadinessProbe{{Name: "task_notifications", Ready: ready}})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	starting, err := service.Snapshot("tenant-a", "repo-a", at)
	if err != nil {
		t.Fatal(err)
	}
	if starting.Ready() || starting.Components()[0].State() != ComponentStarting {
		t.Fatal("unexpected ready status")
	}
	close(ready)
	running, err := service.Snapshot("tenant-a", "repo-a", at.Add(time.Second))
	if err != nil || !running.Ready() || running.Components()[0].State() != ComponentReady {
		t.Fatalf("not ready: %v", err)
	}
	if running.ConfigurationIdentity() != running.Configuration().Identity() || running.ConfigurationIdentity() == configuration.Identity() || running.Identity() == starting.Identity() {
		t.Fatal("status identity mismatch")
	}
	if _, err := service.Snapshot("tenant-a", "other", at); !errors.Is(err, ErrScopeNotConfigured) {
		t.Fatalf("scope: %v", err)
	}
}

func TestSnapshotEncodingIsStrictAndReconstructive(t *testing.T) {
	configuration, _ := NewConfiguration(validOptions())
	ready := make(chan struct{})
	close(ready)
	service, _ := NewService(configuration, []ReadinessProbe{{Name: "worker", Ready: ready}})
	snapshot, _ := service.Snapshot("tenant-a", "repo-a", time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("repo-b")) {
		t.Fatal("snapshot leaked another repository")
	}
	decoded, err := DecodeSnapshot(encoded)
	if err != nil || decoded.Identity() != snapshot.Identity() {
		t.Fatalf("decode: %v", err)
	}
	var value map[string]any
	_ = json.Unmarshal(encoded, &value)
	value["ready"] = false
	tampered, _ := json.Marshal(value)
	if _, err := DecodeSnapshot(tampered); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("tamper: %v", err)
	}
	value = map[string]any{}
	_ = json.Unmarshal(encoded, &value)
	value["extra"] = true
	unknown, _ := json.Marshal(value)
	if _, err := DecodeSnapshot(unknown); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestRepositoryStatusIdentityIgnoresOtherRepositoryMembership(t *testing.T) {
	firstOptions := validOptions()
	first, _ := NewConfiguration(firstOptions)
	firstService, _ := NewService(first, nil)
	at := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	firstStatus, _ := firstService.Snapshot("tenant-a", "repo-a", at)
	secondOptions := validOptions()
	secondOptions.RepositoryIDs = []string{"repo-a", "repo-c"}
	second, _ := NewConfiguration(secondOptions)
	secondService, _ := NewService(second, nil)
	secondStatus, _ := secondService.Snapshot("tenant-a", "repo-a", at)
	if firstStatus.ConfigurationIdentity() != secondStatus.ConfigurationIdentity() || firstStatus.Identity() != secondStatus.Identity() {
		t.Fatal("unrelated repository membership changed scoped status")
	}
}
