package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/setup"
)

// inspectRestoredOwner compares recorded owner bytes with separately observed
// directories and configured setup/repository identity. The caller retains all
// existing writer locks and repeats this check after its remaining observations.
func inspectRestoredOwner(ctx context.Context, statePath, setupPath string, stateRoot, artifactRoot *os.Root, repository evidence.RepositoryIdentity) (record localSourceOwnerRecord, plan setup.Plan, result error) {
	if ctx == nil || ctx.Err() != nil || stateRoot == nil || artifactRoot == nil {
		return record, plan, ErrLocalSourceOwnerMismatch
	}
	record, err := readLocalSourceOwnerRecord(stateRoot, statePath)
	if err != nil {
		return record, plan, err
	}
	plan, err = setup.InspectStateFile(ctx, setupPath)
	if err != nil {
		return record, plan, err
	}
	posture := plan.Posture()
	if plan.Validate() != nil || plan.Profile() != setup.ProfileLocalSingleNode || posture.MetadataBackend() != setup.MetadataLocal || posture.ArtifactBackend() != setup.ArtifactLocal || posture.Egress() != setup.EgressDenied || posture.Protection() != setup.ProtectionProcessPrivate || posture.NotificationBackend() != setup.NotificationProcessLocal || posture.Inference() != setup.InferenceLocalOnly || posture.Integration() != setup.IntegrationLocal || posture.PublicationEnabled() || posture.DynamicValidationEnabled() {
		return record, plan, ErrLocalSourceOwnerMismatch
	}
	gitRoot, sourceDigest, err := openDaemonLocalGitRoot(record.GitObjectsPath, repository)
	if err != nil {
		return record, plan, err
	}
	defer func() { result = errors.Join(result, gitRoot.Close()) }()
	stateID, err := observeLocalSourceDirectory(statePath, stateRoot)
	if err != nil {
		return record, plan, err
	}
	artifactID, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, statePath)
	if err != nil {
		return record, plan, err
	}
	gitID, err := observeLocalSourceDirectory(record.GitObjectsPath, gitRoot)
	if err != nil {
		return record, plan, err
	}
	store, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		return record, plan, err
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		return record, plan, err
	}
	observed := localSourceOwnerRecord{StatePath: statePath, ArtifactPath: filepath.Join(statePath, "artifacts"), GitObjectsPath: record.GitObjectsPath, TenantID: plan.TenantID(), RepositoryID: plan.RepositoryID(), RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity(), Profile: string(store.Profile()), SourcePathDigest: sourceDigest, State: stateID, Artifact: artifactID, Git: gitID}
	if err := matchLocalSourceOwnerRecord(record, observed); err != nil {
		return record, plan, err
	}
	if err := ctx.Err(); err != nil {
		return record, plan, err
	}
	return record, plan, nil
}
