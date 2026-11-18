package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"sort"
)

var ErrInvalidProtectedSourceBinding = errors.New("invalid protected review source binding")

type ProtectedSourceBinding struct {
	identity, sourceIdentity, contextBindingIdentity, reviewScopeIdentity, repositoryIdentity, headRevisionIdentity, headSnapshotArtifactIdentity, headSnapshotIdentity, headManifestIdentity, changeArtifactIdentity, changeIdentity, evidenceArtifactIdentity, contextArtifactIdentity, contextIdentity, pipelineSnapshotIdentity string
	evidenceBindingIdentities                                                                                                                                                                                                                                                                                                       []string
}

func NewProtectedSourceBinding(scope audit.ReviewScope, repository evidence.RepositoryIdentity, head evidence.RevisionIdentity, headSnapshotArtifactIdentity, headSnapshotIdentity, headManifestIdentity, changeArtifactIdentity, changeIdentity, evidenceArtifactIdentity, contextArtifactIdentity, contextIdentity, pipelineSnapshotIdentity string, evidenceBindings []string) (ProtectedSourceBinding, error) {
	r, err := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	h, herr := evidence.NewRevisionIdentity(head.Kind(), head.Algorithm(), head.Digest())
	bindings := append([]string(nil), evidenceBindings...)
	sort.Strings(bindings)
	b := ProtectedSourceBinding{reviewScopeIdentity: scope.Identity(), repositoryIdentity: repository.Identity(), headRevisionIdentity: head.Identity(), headSnapshotArtifactIdentity: headSnapshotArtifactIdentity, headSnapshotIdentity: headSnapshotIdentity, headManifestIdentity: headManifestIdentity, changeArtifactIdentity: changeArtifactIdentity, changeIdentity: changeIdentity, evidenceArtifactIdentity: evidenceArtifactIdentity, contextArtifactIdentity: contextArtifactIdentity, contextIdentity: contextIdentity, pipelineSnapshotIdentity: pipelineSnapshotIdentity, evidenceBindingIdentities: bindings}
	b.sourceIdentity = deriveProtectedSourceIdentity(b)
	b.contextBindingIdentity = deriveProtectedContextBindingIdentity(b)
	b.identity = deriveProtectedSourceBindingIdentity(b)
	if err != nil || herr != nil || r.Identity() != repository.Identity() || h.Identity() != head.Identity() || scope.Validate() != nil || !validCandidateDigest(pipelineSnapshotIdentity) || b.Validate() != nil {
		return ProtectedSourceBinding{}, ErrInvalidProtectedSourceBinding
	}
	return b, nil
}
func (b ProtectedSourceBinding) Identity() string                 { return b.identity }
func (b ProtectedSourceBinding) SourceIdentity() string           { return b.sourceIdentity }
func (b ProtectedSourceBinding) ContextBindingIdentity() string   { return b.contextBindingIdentity }
func (b ProtectedSourceBinding) ReviewScopeIdentity() string      { return b.reviewScopeIdentity }
func (b ProtectedSourceBinding) RepositoryIdentity() string       { return b.repositoryIdentity }
func (b ProtectedSourceBinding) HeadRevisionIdentity() string     { return b.headRevisionIdentity }
func (b ProtectedSourceBinding) PipelineSnapshotIdentity() string { return b.pipelineSnapshotIdentity }
func (b ProtectedSourceBinding) ContextIdentity() string          { return b.contextIdentity }
func (b ProtectedSourceBinding) Validate() error {
	ids := []string{b.sourceIdentity, b.contextBindingIdentity, b.reviewScopeIdentity, b.repositoryIdentity, b.headRevisionIdentity, b.headSnapshotArtifactIdentity, b.headSnapshotIdentity, b.headManifestIdentity, b.changeArtifactIdentity, b.changeIdentity, b.evidenceArtifactIdentity, b.contextArtifactIdentity, b.contextIdentity, b.pipelineSnapshotIdentity}
	for _, id := range ids {
		if !validCandidateDigest(id) {
			return ErrInvalidProtectedSourceBinding
		}
	}
	if len(b.evidenceBindingIdentities) == 0 || len(b.evidenceBindingIdentities) > maxSelectedContextSources {
		return ErrInvalidProtectedSourceBinding
	}
	previous := ""
	for _, id := range b.evidenceBindingIdentities {
		if !validCandidateDigest(id) || id <= previous {
			return ErrInvalidProtectedSourceBinding
		}
		previous = id
	}
	if b.sourceIdentity != deriveProtectedSourceIdentity(b) || b.contextBindingIdentity != deriveProtectedContextBindingIdentity(b) || b.identity != deriveProtectedSourceBindingIdentity(b) {
		return ErrInvalidProtectedSourceBinding
	}
	return nil
}
func deriveProtectedSourceIdentity(b ProtectedSourceBinding) string {
	encoded, _ := json.Marshal(struct {
		Contract         string `json:"contract"`
		Version          int    `json:"version"`
		Scope            string `json:"scope"`
		Repository       string `json:"repository"`
		Head             string `json:"head"`
		HeadArtifact     string `json:"head_artifact"`
		HeadSnapshot     string `json:"head_snapshot"`
		HeadManifest     string `json:"head_manifest"`
		ChangeArtifact   string `json:"change_artifact"`
		Change           string `json:"change"`
		EvidenceArtifact string `json:"evidence_artifact"`
	}{"open-trestle/protected-source-snapshot", 1, b.reviewScopeIdentity, b.repositoryIdentity, b.headRevisionIdentity, b.headSnapshotArtifactIdentity, b.headSnapshotIdentity, b.headManifestIdentity, b.changeArtifactIdentity, b.changeIdentity, b.evidenceArtifactIdentity})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func deriveProtectedContextBindingIdentity(b ProtectedSourceBinding) string {
	encoded, _ := json.Marshal(struct {
		Contract        string   `json:"contract"`
		Version         int      `json:"version"`
		Source          string   `json:"source"`
		ContextArtifact string   `json:"context_artifact"`
		Context         string   `json:"context"`
		Pipeline        string   `json:"pipeline"`
		Evidence        []string `json:"evidence"`
	}{"open-trestle/protected-context-binding", 1, b.sourceIdentity, b.contextArtifactIdentity, b.contextIdentity, b.pipelineSnapshotIdentity, b.evidenceBindingIdentities})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func deriveProtectedSourceBindingIdentity(b ProtectedSourceBinding) string {
	encoded, _ := json.Marshal(struct {
		Contract         string   `json:"contract"`
		Version          int      `json:"version"`
		Scope            string   `json:"scope"`
		Repository       string   `json:"repository"`
		Head             string   `json:"head"`
		HeadArtifact     string   `json:"head_artifact"`
		HeadSnapshot     string   `json:"head_snapshot"`
		HeadManifest     string   `json:"head_manifest"`
		ChangeArtifact   string   `json:"change_artifact"`
		Change           string   `json:"change"`
		EvidenceArtifact string   `json:"evidence_artifact"`
		ContextArtifact  string   `json:"context_artifact"`
		Context          string   `json:"context"`
		PipelineSnapshot string   `json:"pipeline_snapshot"`
		EvidenceBindings []string `json:"evidence_bindings"`
	}{"open-trestle/protected-review-source-binding", 1, b.reviewScopeIdentity, b.repositoryIdentity, b.headRevisionIdentity, b.headSnapshotArtifactIdentity, b.headSnapshotIdentity, b.headManifestIdentity, b.changeArtifactIdentity, b.changeIdentity, b.evidenceArtifactIdentity, b.contextArtifactIdentity, b.contextIdentity, b.pipelineSnapshotIdentity, b.evidenceBindingIdentities})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// NewPublicationPlanFromProtectedSource creates a proposal from verified protected runtime artifacts.
func NewPublicationPlanFromProtectedSource(readiness PublicationReadiness, target PublicationTarget, source ProtectedSourceBinding) (PublicationPlan, error) {
	if readiness.Validate() != nil || target.Validate() != nil || source.Validate() != nil || source.reviewScopeIdentity != readiness.ReviewScopeIdentity() || source.pipelineSnapshotIdentity != readiness.snapshotIdentity || source.contextIdentity != readiness.GenerationContextIdentity() || source.repositoryIdentity != target.RepositoryIdentity().Identity() || source.headRevisionIdentity != target.HeadRevision().Identity() {
		return PublicationPlan{}, ErrInvalidSourceSnapshotBinding
	}
	plan, err := newPublicationPlan(readiness, target, source.SourceIdentity())
	if err != nil {
		return PublicationPlan{}, err
	}
	plan.hasAcquiredSource = true
	plan.sourceRepositoryIdentity = source.repositoryIdentity
	plan.sourceHeadRevisionIdentity = source.headRevisionIdentity
	plan.acquiredContextBindingIdentity = source.ContextBindingIdentity()
	plan.identity = derivePublicationPlanIdentity(plan)
	if plan.Validate() != nil {
		return PublicationPlan{}, ErrInvalidPublicationPlan
	}
	return plan, nil
}
