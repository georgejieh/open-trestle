package artifact_test

import (
	"github.com/georgejieh/open-trestle/artifact"
	"strings"
	"testing"
)

func TestProgressPinnedFenceCannotBeDeletedThroughCurrentClaim(t *testing.T) {
	o := progressMetadata(t)
	at := o.Operation.PreparedAt()
	allowance, err := artifact.NewResumeAllowance(artifact.ResumeAllowanceOptions{Operation: o.Operation, RecoveryPolicyIdentity: strings.Repeat("7", 64), ProtectedPolicyIdentity: o.Operation.ProtectedPolicyIdentity(), PrincipalIdentity: strings.Repeat("9", 64), IssuanceIdentity: strings.Repeat("b", 64), ExpectedBucketOwner: "123456789012", NotBefore: at, NotAfter: at.Add(300000000000), Maximum: artifact.ResumeBudget{Requests: 4, Reads: 4, Mutations: 4, Deletes: 4, ResponseBytes: 20000}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := artifact.NewExactObjectKey(o.Namespace.Identity(), o.Namespace.Prefix()+"/artifacts/"+o.Operation.Scope().Identity()+"/"+o.Operation.ArtifactIdentity())
	if err != nil {
		t.Fatal(err)
	}
	version, err := artifact.NewObjectVersion(key.NamespaceIdentity(), key.Key(), artifact.ObjectVersionData, "required-fence-token")
	if err != nil {
		t.Fatal(err)
	}
	reserve := func(kind artifact.AttemptKind, id string, sequence uint64, observation string) artifact.ErasureAttempt {
		opts := artifact.AttemptRequestOptions{Operation: o.Operation, Allowance: allowance, Kind: kind, Key: key, ReservationIdentity: strings.Repeat(id, 64), MaximumResponseBytes: 4096, ObservationIdentity: observation}
		if kind == artifact.AttemptVersionDelete {
			opts.Version = version
		}
		request, e := artifact.NewAttemptRequest(opts)
		if e != nil {
			t.Fatal(e)
		}
		attempt, e := artifact.NewErasureAttempt(request, sequence, at)
		if e != nil {
			t.Fatal(e)
		}
		return attempt
	}
	first := reserve(artifact.AttemptCurrentRead, "c", 1, "")
	fence, e := artifact.NewErasureFence(o.Operation)
	if e != nil {
		t.Fatal(e)
	}
	body, e := artifact.EncodeErasureFence(fence)
	if e != nil {
		t.Fatal(e)
	}
	observed, e := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: first, Code: artifact.AttemptResponsePresent, ObservedAt: at, Version: version, ContentKind: "fence", ContentDigest: progressHash(body), CanonicalRecord: body, ResponseBytes: uint32(len(body))})
	if e != nil {
		t.Fatal(e)
	}
	pinned, e := artifact.NewFenceObservationEvidence(o.Operation, key, observed, at)
	if e != nil {
		t.Fatal(e)
	}
	second := reserve(artifact.AttemptCurrentRead, "d", 2, "")
	claimed, e := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: second, Code: artifact.AttemptResponsePresent, ObservedAt: at, Version: version, ContentKind: "ciphertext", ContentDigest: progressHash(body), ResponseBytes: uint32(len(body))})
	if e != nil {
		t.Fatal(e)
	}
	// A content-kind claim cannot overrule the known pinned token.
	deletion := reserve(artifact.AttemptVersionDelete, "e", 3, claimed.Identity())
	spent := artifact.ResumeBudget{Requests: 3, Reads: 2, Mutations: 1, Deletes: 1, ResponseBytes: 3 * 4097}
	o.AllowanceSnapshots = []artifact.ErasureAllowanceSnapshot{{Allowance: allowance, AcceptedPolicyBytes: o.OperationPolicyBytes, AcceptedAt: at, Usage: artifact.AllowanceUsage{AllowanceIdentity: allowance.Identity(), Spent: spent, NextSequence: 4}, AttemptCount: 3, TotalCost: spent}}
	o.Attempts = []artifact.ErasureAttempt{first, second, deletion}
	o.Evidence = []artifact.ErasureEvidence{observed, pinned, claimed}
	o.UnrecordedUncertainty = []artifact.ErasureAttempt{deletion}
	o.UnresolvedExists = true
	got, e := artifact.NewErasureProgress(o)
	if e != artifact.ErrErasureBindingMismatch || got.Operation().Identity() != "" {
		t.Fatalf("pinned token deletion accepted or wrong refusal: %v", e)
	}
}
