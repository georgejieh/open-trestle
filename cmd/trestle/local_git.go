package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type localGitInspectOptions struct {
	objectsRoot string
}

type localGitRootHandle struct {
	root  *os.Root
	close func() error
}

type localGitRootOpener func(string) (localGitRootHandle, error)

type localGitInspectResult struct {
	Contract                             string `json:"contract"`
	SchemaVersion                        int    `json:"schema_version"`
	Status                               string `json:"status"`
	EnvelopeIdentity                     string `json:"envelope_identity"`
	RepositoryIdentity                   string `json:"repository_identity"`
	RevisionIdentity                     string `json:"revision_identity"`
	SourceAdapterIdentity                string `json:"source_adapter_identity"`
	RequestIdentity                      string `json:"request_identity"`
	ReceiptIdentity                      string `json:"receipt_identity"`
	AcquisitionExecutionIdentity         string `json:"acquisition_execution_identity"`
	ProfiledAcquisitionExecutionIdentity string `json:"profiled_acquisition_execution_identity"`
	EvidenceBindingIdentity              string `json:"evidence_binding_identity"`
	ManifestIdentity                     string `json:"manifest_identity"`
	GitCommitIdentity                    string `json:"git_commit_identity"`
	GitTreeGraphIdentity                 string `json:"git_tree_graph_identity"`
	CorrespondenceIdentity               string `json:"correspondence_identity"`
	ProfileBundleIdentity                string `json:"profile_bundle_identity"`
	ContentCoverage                      string `json:"content_coverage"`
}

func runLocalGitInspect(args []string, stdout, stderr io.Writer) int {
	return runLocalGitInspectWithOpener(args, stdout, stderr, openLocalGitRoot)
}

func runLocalGitInspectWithOpener(args []string, stdout, stderr io.Writer, opener localGitRootOpener) int {
	options, repository, revision, err := parseLocalGitInspectOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "local-git inspect: %v\n", err)
		writeLocalGitInspectUsage(stderr)
		return 2
	}
	handle, err := opener(options.objectsRoot)
	if err != nil {
		fmt.Fprintln(stderr, "open object root: unavailable")
		return 1
	}
	if handle.close == nil {
		if handle.root != nil {
			_ = handle.root.Close()
		}
		fmt.Fprintln(stderr, "open object root: invalid root handle")
		return 1
	}
	if handle.root == nil {
		closeErr := handle.close()
		fmt.Fprint(stderr, "open object root: invalid root handle")
		if closeErr != nil {
			fmt.Fprint(stderr, "; close object root: failed")
		}
		fmt.Fprintln(stderr)
		return 1
	}
	encoded, inspectErr := buildLocalGitInspectResult(handle.root, repository, revision)
	closeErr := handle.close()
	if inspectErr != nil {
		fmt.Fprint(stderr, "inspect local Git: failed")
		if closeErr != nil {
			fmt.Fprint(stderr, "; close object root: failed")
		}
		fmt.Fprintln(stderr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintln(stderr, "close object root: failed")
		return 1
	}
	written, err := stdout.Write(encoded)
	if err == nil && written != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fmt.Fprintln(stderr, "write result: failed")
		return 1
	}
	return 0
}

func parseLocalGitInspectOptions(args []string) (localGitInspectOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, error) {
	if len(args) != 12 {
		return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("exactly six flag-value pairs are required")
	}
	values := make(map[string]string, 6)
	allowed := map[string]bool{
		"--objects-root": true, "--repository-authority": true, "--repository-namespace": true,
		"--repository-name": true, "--revision-algorithm": true, "--revision-digest": true,
	}
	for i := 0; i < len(args); i += 2 {
		name, value := args[i], args[i+1]
		if !allowed[name] {
			return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("unknown flag")
		}
		if _, exists := values[name]; exists {
			return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("duplicate flag")
		}
		if value == "" {
			return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("flag %q requires a non-empty value", name)
		}
		values[name] = value
	}
	for name := range allowed {
		if _, exists := values[name]; !exists {
			return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("missing flag %q", name)
		}
	}
	namespace := strings.Split(values["--repository-namespace"], "/")
	repository, err := evidence.NewRepositoryIdentity(values["--repository-authority"], namespace, values["--repository-name"])
	if err != nil {
		return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("repository identity is invalid")
	}
	algorithm := evidence.RevisionAlgorithm(values["--revision-algorithm"])
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, values["--revision-digest"])
	if err != nil {
		return localGitInspectOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("revision identity is invalid")
	}
	return localGitInspectOptions{objectsRoot: values["--objects-root"]}, repository, revision, nil
}

func openLocalGitRoot(path string) (localGitRootHandle, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return localGitRootHandle{}, err
	}
	return localGitRootHandle{root: root, close: root.Close}, nil
}

func buildLocalGitInspectResult(root *os.Root, repository evidence.RepositoryIdentity, revision evidence.RevisionIdentity) ([]byte, error) {
	store, err := scm.NewLocalGitObjectStore(root, repository)
	if err != nil {
		return nil, err
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		return nil, err
	}
	request, err := evidence.NewRepositoryAcquisitionRequest(repository, revision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return nil, err
	}
	envelope, err := scm.ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
	if err != nil {
		return nil, err
	}
	result, err := newLocalGitInspectResult(envelope)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode local Git inspect result: %w", err)
	}
	return append(encoded, '\n'), nil
}

func newLocalGitInspectResult(envelope scm.LocalGitAcquisitionEnvelope) (localGitInspectResult, error) {
	profiled := envelope.ProfiledAcquisition()
	execution := profiled.Acquisition()
	receipt := execution.Receipt()
	binding := envelope.EvidenceBinding()
	bundle := profiled.ProfileBundle()
	if envelope.Identity() == "" || profiled.Identity() == "" || execution.Identity() == "" || binding.Identity() == "" || bundle.Identity() == "" || binding.BindingStatus() != evidence.RepositoryAcquisitionEvidenceStatusSupplied || receipt.ContentCoverage() != evidence.ContentCoverageComplete {
		return localGitInspectResult{}, fmt.Errorf("local Git acquisition envelope is incomplete")
	}
	if binding.RequestIdentity() != execution.RequestIdentity() || binding.ReceiptIdentity() != execution.ReceiptIdentity() || binding.RepositoryIdentity() != receipt.RepositoryIdentity() || binding.RevisionIdentity() != execution.RevisionIdentity() || binding.SourceAdapterIdentity() != execution.SourceAdapterIdentity() || binding.ManifestIdentity() != execution.ManifestIdentity() || binding.ManifestIdentity() != receipt.ManifestIdentity() || binding.ManifestIdentity() != bundle.ManifestIdentity() || binding.GitCommitIdentity() != execution.GitCommitIdentity() || binding.GitTreeGraphIdentity() != execution.GitTreeGraphIdentity() || binding.CorrespondenceIdentity() != execution.CorrespondenceIdentity() {
		return localGitInspectResult{}, fmt.Errorf("local Git acquisition envelope identities do not agree")
	}
	return localGitInspectResult{
		Contract: "open-trestle/local-git-inspect-result", SchemaVersion: 1, Status: string(binding.BindingStatus()),
		EnvelopeIdentity: envelope.Identity(), RepositoryIdentity: binding.RepositoryIdentity(), RevisionIdentity: binding.RevisionIdentity(),
		SourceAdapterIdentity: binding.SourceAdapterIdentity(), RequestIdentity: binding.RequestIdentity(), ReceiptIdentity: binding.ReceiptIdentity(),
		AcquisitionExecutionIdentity: execution.Identity(), ProfiledAcquisitionExecutionIdentity: profiled.Identity(), EvidenceBindingIdentity: binding.Identity(),
		ManifestIdentity: binding.ManifestIdentity(), GitCommitIdentity: binding.GitCommitIdentity(), GitTreeGraphIdentity: binding.GitTreeGraphIdentity(),
		CorrespondenceIdentity: binding.CorrespondenceIdentity(), ProfileBundleIdentity: bundle.Identity(), ContentCoverage: string(receipt.ContentCoverage()),
	}, nil
}

func writeLocalGitInspectUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle local-git inspect --objects-root PATH --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --revision-digest FULL_LOWERCASE_HEX")
}
