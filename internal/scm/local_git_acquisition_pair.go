package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// LocalGitAcquisitionPair binds ordered acquisition envelopes to their manifest delta.
type LocalGitAcquisitionPair struct {
	identity      string
	baseEnvelope  LocalGitAcquisitionEnvelope
	headEnvelope  LocalGitAcquisitionEnvelope
	manifestDelta evidence.RepositoryManifestDelta
}

type localGitAcquisitionEndpoint func(context.Context, evidence.RepositoryAcquisitionRequest, *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, error)

// ExecuteLocalGitAcquisitionPair acquires two explicit revisions through one local store.
func ExecuteLocalGitAcquisitionPair(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionPair, error) {
	return executeLocalGitAcquisitionPairWithEndpoint(ctx, baseRequest, headRequest, adapter, executeLocalGitAcquisitionEnvelopeWithManifest)
}

func executeLocalGitAcquisitionPairWithEndpoint(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter, endpoint localGitAcquisitionEndpoint) (LocalGitAcquisitionPair, error) {
	if err := validateLocalGitAcquisitionPairInputs(ctx, baseRequest, headRequest, adapter); err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	if endpoint == nil {
		return LocalGitAcquisitionPair{}, fmt.Errorf("local Git acquisition endpoint is nil")
	}
	baseEnvelope, baseManifest, err := endpoint(ctx, baseRequest, adapter)
	if err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	headEnvelope, headManifest := baseEnvelope, baseManifest
	if baseRequest.Identity() != headRequest.Identity() {
		headEnvelope, headManifest, err = endpoint(ctx, headRequest, adapter)
		if err != nil {
			return LocalGitAcquisitionPair{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	delta, err := evidence.NewRepositoryManifestDelta(baseManifest, headManifest)
	if err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	pair, err := newLocalGitAcquisitionPair(baseEnvelope, headEnvelope, delta)
	if err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitAcquisitionPair{}, err
	}
	return pair, nil
}

func validateLocalGitAcquisitionPairInputs(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) error {
	if isNilInterface(ctx) {
		return fmt.Errorf("repository acquisition context is nil")
	}
	if adapter == nil || adapter.store == nil {
		return fmt.Errorf("source adapter is nil")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(baseRequest); err != nil {
		return fmt.Errorf("base repository acquisition request: %w", err)
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(headRequest); err != nil {
		return fmt.Errorf("head repository acquisition request: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if baseRequest.Artifact() != evidence.AcquisitionArtifactManifestAndContent || headRequest.Artifact() != evidence.AcquisitionArtifactManifestAndContent || baseRequest.Effect() != evidence.AcquisitionEffectReadOnly || headRequest.Effect() != evidence.AcquisitionEffectReadOnly {
		return fmt.Errorf("paired local Git acquisition requires read-only manifest and content requests")
	}
	adapterIdentity := adapter.Identity().Identity()
	if adapterIdentity == "" || baseRequest.SourceAdapterIdentity() != adapterIdentity || headRequest.SourceAdapterIdentity() != adapterIdentity {
		return fmt.Errorf("paired local Git acquisition requests do not match the source adapter")
	}
	if baseRequest.RepositoryIdentity() != headRequest.RepositoryIdentity() || baseRequest.RepositoryIdentity() != adapter.store.RepositoryIdentity() {
		return fmt.Errorf("paired local Git acquisition requests do not share one repository identity")
	}
	if baseRequest.Revision().Algorithm() != headRequest.Revision().Algorithm() {
		return fmt.Errorf("paired local Git acquisition revisions use different object algorithms")
	}
	return nil
}

func newLocalGitAcquisitionPair(base, head LocalGitAcquisitionEnvelope, delta evidence.RepositoryManifestDelta) (LocalGitAcquisitionPair, error) {
	canonicalBase, err := newLocalGitAcquisitionEnvelope(base.ProfiledAcquisition(), base.EvidenceBinding())
	if err != nil || canonicalBase != base {
		return LocalGitAcquisitionPair{}, fmt.Errorf("base local Git acquisition envelope is not canonical")
	}
	canonicalHead, err := newLocalGitAcquisitionEnvelope(head.ProfiledAcquisition(), head.EvidenceBinding())
	if err != nil || canonicalHead != head {
		return LocalGitAcquisitionPair{}, fmt.Errorf("head local Git acquisition envelope is not canonical")
	}
	baseBinding := base.EvidenceBinding()
	headBinding := head.EvidenceBinding()
	if delta.Identity() == "" || baseBinding.RepositoryIdentity() != headBinding.RepositoryIdentity() || baseBinding.SourceAdapterIdentity() != headBinding.SourceAdapterIdentity() || delta.BaseManifestIdentity() != baseBinding.ManifestIdentity() || delta.HeadManifestIdentity() != headBinding.ManifestIdentity() {
		return LocalGitAcquisitionPair{}, fmt.Errorf("paired local Git acquisition children do not agree")
	}
	preimage := struct {
		Contract                        string `json:"contract"`
		SchemaVersion                   int    `json:"schema_version"`
		BaseAcquisitionEnvelopeIdentity string `json:"base_acquisition_envelope_identity"`
		HeadAcquisitionEnvelopeIdentity string `json:"head_acquisition_envelope_identity"`
		RepositoryManifestDeltaIdentity string `json:"repository_manifest_delta_identity"`
	}{
		Contract:                        "open-trestle/local-git-acquisition-pair",
		SchemaVersion:                   1,
		BaseAcquisitionEnvelopeIdentity: base.Identity(),
		HeadAcquisitionEnvelopeIdentity: head.Identity(),
		RepositoryManifestDeltaIdentity: delta.Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return LocalGitAcquisitionPair{}, fmt.Errorf("encode local Git acquisition pair identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return LocalGitAcquisitionPair{
		identity:      hex.EncodeToString(digest[:]),
		baseEnvelope:  base,
		headEnvelope:  head,
		manifestDelta: delta,
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (p LocalGitAcquisitionPair) Identity() string { return p.identity }

// BaseEnvelope returns the caller-designated base acquisition.
func (p LocalGitAcquisitionPair) BaseEnvelope() LocalGitAcquisitionEnvelope { return p.baseEnvelope }

// HeadEnvelope returns the caller-designated head acquisition.
func (p LocalGitAcquisitionPair) HeadEnvelope() LocalGitAcquisitionEnvelope { return p.headEnvelope }

// ManifestDelta returns the ordered metadata-only manifest comparison.
func (p LocalGitAcquisitionPair) ManifestDelta() evidence.RepositoryManifestDelta {
	return p.manifestDelta
}
