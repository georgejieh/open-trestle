package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func repositoryProofFixture(t *testing.T, run string) (audit.ReviewScope, SanitizedDispatchProof, string) {
	t.Helper()
	originalScope, _, _, originalArtifact, raw := generationContextFixture(t)
	scope, err := audit.NewReviewScope(originalScope.TenantID(), originalScope.RepositoryID(), run)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.ReplaceAll(raw.Payload(), []byte(originalScope.Identity()), []byte(scope.Identity()))
	raw, err = provider.NewRequest(raw.Capability(), raw.MediaType(), payload)
	if err != nil {
		t.Fatal(err)
	}
	contextArtifact, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential,
		artifact.OriginHost, artifact.ProtectionProcessPrivate, originalArtifact.Provenance(), raw.Payload(), time.UnixMilli(50), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, requestArtifact, receiptArtifact, expected := sanitizedGenerationFixture(t, scope, contextArtifact, raw, "")
	proof, err := newGenerationDispatchProof(contextArtifact, requestArtifact, receiptArtifact, expected)
	if err != nil {
		t.Fatal(err)
	}
	return scope, proof, receipt.SanitizedRequestIdentity()
}

func TestRepositoryAttestedProofAcceptsTwoRunsWithoutWildcardScope(t *testing.T) {
	scopeA, proofA, requestA := repositoryProofFixture(t, "run-a")
	scopeB, proofB, requestB := repositoryProofFixture(t, "run-b")
	for _, tc := range []struct {
		scope   audit.ReviewScope
		proof   SanitizedDispatchProof
		request string
	}{
		{scopeA, proofA, requestA}, {scopeB, proofB, requestB},
	} {
		bound, err := bindSanitizedDispatchProofScope(tc.proof, tc.scope)
		if err != nil {
			t.Fatal(err)
		}
		if err := bound.ValidateRepositoryScope("tenant-a", "repo-a", tc.scope.Identity(), tc.request); err != nil {
			t.Fatal(err)
		}
		if bound.ValidateRepositoryScope("tenant-a", "repo-a", strings.Repeat("f", 64), tc.request) == nil {
			t.Fatal("repository acceptance removed exact run binding")
		}
	}
	boundA, err := bindSanitizedDispatchProofScope(proofA, scopeA)
	if err != nil {
		t.Fatal(err)
	}
	if boundA.ValidateRepositoryScope("tenant-a", "repo-a", scopeB.Identity(), requestB) == nil {
		t.Fatal("proof replayed across runs")
	}
}

func TestRepositoryAttestationRequiresTrustedMatchingScope(t *testing.T) {
	scope, proof, request := repositoryProofFixture(t, "run-a")
	if proof.ValidateRepositoryScope("tenant-a", "repo-a", scope.Identity(), request) == nil {
		t.Fatal("legacy scope hash silently became tenant/repository attestation")
	}
	wrong, err := audit.NewReviewScope("other-tenant", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bindSanitizedDispatchProofScope(proof, wrong); err == nil {
		t.Fatal("mismatched trusted task scope bound")
	}
	bound, err := bindSanitizedDispatchProofScope(proof, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tenant, repository, scope, request string }{
		{"other-tenant", "repo-a", scope.Identity(), request},
		{"tenant-a", "other-repo", scope.Identity(), request},
		{"tenant-a", "repo-a", scope.Identity(), strings.Repeat("f", 64)},
	} {
		if bound.ValidateRepositoryScope(tc.tenant, tc.repository, tc.scope, tc.request) == nil {
			t.Fatal("substituted repository dispatch authority accepted")
		}
	}
	mutated := bound
	mutated.tenantID = "other-tenant"
	if mutated.ValidateRepositoryScope("other-tenant", "repo-a", scope.Identity(), request) == nil {
		t.Fatal("scope attestation omitted from proof identity")
	}
}

func TestUnattestedSanitizedProofKeepsV1Preimage(t *testing.T) {
	_, proof, _ := repositoryProofFixture(t, "run-a")
	encoded, err := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Kind     string `json:"kind"`
		Scope    string `json:"scope"`
		Request  string `json:"request"`
		Receipt  string `json:"receipt"`
	}{"open-trestle/sanitized-egress-dispatch-proof", 1, string(proof.kind), proof.reviewScopeIdentity, proof.requestIdentity, proof.receiptIdentity})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if proof.identity != hex.EncodeToString(sum[:]) {
		t.Fatal("legacy proof preimage changed")
	}
}
