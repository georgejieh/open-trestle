package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

type localGitGoImpactBuilder func(evidence.Change, map[string][]byte) (analysis.ChangeImpactProfile, analysis.GoChangeImpactReceipt, error)

// LocalGitGoImpactExecution binds one change execution to detached Go impact evidence.
type LocalGitGoImpactExecution struct {
	identity        string
	changeExecution LocalGitChangeExecution
	hasImpact       bool
	profile         analysis.ChangeImpactProfile
	receipt         analysis.GoChangeImpactReceipt
}

// ExecuteLocalGitChangeWithGoImpact derives Go impact while head bytes remain in scope.
func ExecuteLocalGitChangeWithGoImpact(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitGoImpactExecution, error) {
	return executeLocalGitChangeWithGoImpact(ctx, baseRequest, headRequest, adapter, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, analysis.BuildGoChangeImpactProfile)
}

func executeLocalGitChangeWithGoImpact(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter, endpoint localGitChangeEndpoint, fileExecutor localGitFileDeltaExecutor, builder localGitGoImpactBuilder) (LocalGitGoImpactExecution, error) {
	if builder == nil {
		return LocalGitGoImpactExecution{}, fmt.Errorf("Go impact builder is nil")
	}
	changeExecution, retainedHeadContents, err := executeLocalGitChangeRetainingHead(ctx, baseRequest, headRequest, adapter, endpoint, fileExecutor, localGitHeadRetentionGo)
	if err != nil {
		return LocalGitGoImpactExecution{}, err
	}
	defer clearLocalGitRetainedHeadContents(retainedHeadContents)
	if !changeExecution.HasChange() {
		return newLocalGitGoImpactExecution(changeExecution, analysis.ChangeImpactProfile{}, analysis.GoChangeImpactReceipt{}, false)
	}
	profile, receipt, err := builder(changeExecution.Change(), retainedHeadContents)
	clearLocalGitRetainedHeadContents(retainedHeadContents)
	retainedHeadContents = nil
	if err != nil {
		return LocalGitGoImpactExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitGoImpactExecution{}, err
	}
	return newLocalGitGoImpactExecution(changeExecution, profile, receipt, true)
}

func newLocalGitGoImpactExecution(changeExecution LocalGitChangeExecution, profile analysis.ChangeImpactProfile, receipt analysis.GoChangeImpactReceipt, hasImpact bool) (LocalGitGoImpactExecution, error) {
	canonicalChangeExecution, err := newLocalGitChangeExecution(changeExecution.AcquisitionPair(), changeExecution.Change(), changeExecution.HasChange(), changeExecution.EntryExecutions())
	if err != nil || canonicalChangeExecution.Identity() != changeExecution.Identity() {
		return LocalGitGoImpactExecution{}, fmt.Errorf("local Git change execution is not canonical")
	}
	profileIdentity, receiptIdentity := "", ""
	if hasImpact {
		if !changeExecution.HasChange() || profile.Identity() == "" || receipt.Identity() == "" || profile.ChangeIdentity() != changeExecution.Change().Identity() || receipt.ChangeIdentity() != changeExecution.Change().Identity() || receipt.ProfileIdentity() != profile.Identity() {
			return LocalGitGoImpactExecution{}, fmt.Errorf("Go impact evidence does not match change execution")
		}
		profileIdentity = profile.Identity()
		receiptIdentity = receipt.Identity()
	} else if changeExecution.HasChange() || profile.Identity() != "" || receipt.Identity() != "" {
		return LocalGitGoImpactExecution{}, fmt.Errorf("absent Go impact evidence must be zero")
	}
	preimage := struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		ChangeExecutionIdentity string `json:"change_execution_identity"`
		ImpactPresent           bool   `json:"impact_present"`
		ProfileIdentity         string `json:"profile_identity"`
		ReceiptIdentity         string `json:"receipt_identity"`
	}{
		Contract:                "open-trestle/local-git-go-impact-execution",
		SchemaVersion:           1,
		ChangeExecutionIdentity: changeExecution.Identity(),
		ImpactPresent:           hasImpact,
		ProfileIdentity:         profileIdentity,
		ReceiptIdentity:         receiptIdentity,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return LocalGitGoImpactExecution{}, err
	}
	digest := sha256.Sum256(encoded)
	return LocalGitGoImpactExecution{
		identity: hex.EncodeToString(digest[:]), changeExecution: changeExecution,
		hasImpact: hasImpact, profile: profile, receipt: receipt,
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (e LocalGitGoImpactExecution) Identity() string { return e.identity }

// ChangeExecution returns the exact owning local Git change execution.
func (e LocalGitGoImpactExecution) ChangeExecution() LocalGitChangeExecution {
	return e.changeExecution
}

// HasImpact reports whether a supported Change produced Go impact evidence.
func (e LocalGitGoImpactExecution) HasImpact() bool { return e.hasImpact }

// Profile returns the detached canonical change impact profile.
func (e LocalGitGoImpactExecution) Profile() analysis.ChangeImpactProfile { return e.profile }

// Receipt returns the detached Go resolver coverage receipt.
func (e LocalGitGoImpactExecution) Receipt() analysis.GoChangeImpactReceipt { return e.receipt }
