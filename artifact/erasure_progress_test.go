package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func progressHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func progressWire(t *testing.T, fields map[string]any, order, domain string) []byte {
	t.Helper()
	encode := func(identity bool) []byte {
		var parts []string
		for _, key := range strings.Fields(order) {
			if key == "identity" && !identity {
				continue
			}
			v, ok := fields[key]
			if !ok {
				t.Fatal("missing independent canonical field", key)
			}
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, fmt.Sprintf("%q:%s", key, raw))
		}
		return []byte("{" + strings.Join(parts, ",") + "}")
	}
	fields["identity"] = progressHash(append([]byte(domain), encode(false)...))
	return encode(true)
}
func progressMetadata(t *testing.T) artifact.ErasureProgressOptions {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Millisecond)
	scope, err := audit.NewReviewScope("tenant-progress", "repo-progress", "run-progress")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := artifact.NewStorageNamespace(strings.Repeat("1", 64), "progress-fixture", strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted, artifact.OriginMemory, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("3", 64)}, []byte("metadata-only payload"), at.Add(-time.Minute), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := artifact.NewArtifactAdmission(value, ns.Identity(), at)
	if err != nil {
		t.Fatal(err)
	}
	policyFields := map[string]any{"contract": "open-trestle/protected-artifact-erasure-policy", "schema_version": 1, "namespace_identity": ns.Identity(), "backend_configuration_identity": ns.BackendConfigurationIdentity(), "prefix": ns.Prefix(), "namespace_epoch_identity": ns.NamespaceEpochIdentity(), "backend_kind": "aws_s3_general_purpose", "database_authority_identity": strings.Repeat("4", 64), "namespace_mode": "protected_new_nonnull", "protocol": "same-key-fence-v2", "ownership": "all_versions_at_exact_key", "fence_retention_policy_identity": strings.Repeat("5", 64), "erasure_policy_identity": strings.Repeat("6", 64), "recovery_policy_identity": strings.Repeat("7", 64), "configuration_evidence_identity": strings.Repeat("8", 64), "not_before_milliseconds": at.Add(-time.Minute).UnixMilli(), "not_after_milliseconds": at.Add(time.Hour).UnixMilli()}
	policy := progressWire(t, policyFields, "contract schema_version identity namespace_identity backend_configuration_identity prefix namespace_epoch_identity backend_kind database_authority_identity namespace_mode protocol ownership fence_retention_policy_identity erasure_policy_identity recovery_policy_identity configuration_evidence_identity not_before_milliseconds not_after_milliseconds", "open-trestle/protected-artifact-erasure-policy/v1\x00")
	grantFields := map[string]any{"contract": "open-trestle/artifact-erasure-authorization", "schema_version": 2, "namespace_identity": ns.Identity(), "scope_identity": scope.Identity(), "tenant_id": scope.TenantID(), "repository_id": scope.RepositoryID(), "review_run_id": scope.ReviewRunID(), "artifact_identity": value.Identity(), "admission_identity": admission.Identity(), "policy_identity": strings.Repeat("6", 64), "principal_identity": strings.Repeat("9", 64), "hold_clearance_identity": strings.Repeat("a", 64), "ownership": "all_versions_at_exact_key", "fence_retention_policy_identity": strings.Repeat("5", 64), "reason": "tenant_erasure", "issued_at_milliseconds": at.Add(-time.Second).UnixMilli(), "expires_at_milliseconds": at.Add(10 * time.Minute).UnixMilli(), "legacy_receipt_identity": ""}
	grantRaw := progressWire(t, grantFields, "contract schema_version identity namespace_identity scope_identity tenant_id repository_id review_run_id artifact_identity admission_identity policy_identity principal_identity hold_clearance_identity ownership fence_retention_policy_identity reason issued_at_milliseconds expires_at_milliseconds legacy_receipt_identity", "open-trestle/artifact-erasure-authorization/v2\x00")
	grant, err := artifact.ParseErasureAuthorizationV2(grantRaw)
	if err != nil {
		t.Fatal(err)
	}
	opFields := map[string]any{"contract": "open-trestle/artifact-erasure-operation", "schema_version": 2, "namespace_identity": ns.Identity(), "scope_identity": scope.Identity(), "artifact_identity": value.Identity(), "admission_identity": admission.Identity(), "original_authorization_identity": grant.Identity(), "authorization_document_digest": progressHash(grantRaw), "policy_identity": strings.Repeat("6", 64), "protected_policy_identity": policyFields["identity"], "ownership": "all_versions_at_exact_key", "prepared_at_milliseconds": at.UnixMilli(), "erasure_protocol": "same-key-fence-v2", "legacy_receipt_identity": ""}
	opRaw := progressWire(t, opFields, "contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity original_authorization_identity authorization_document_digest policy_identity protected_policy_identity ownership prepared_at_milliseconds erasure_protocol legacy_receipt_identity", "open-trestle/artifact-erasure-operation/v2\x00")
	op, err := artifact.ParseErasureOperation(opRaw, scope)
	if err != nil {
		t.Fatal(err)
	}
	return artifact.ErasureProgressOptions{Operation: op, Admission: admission, Namespace: ns, OriginalAuthorization: grant, AdmissionPolicyBytes: append([]byte(nil), policy...), OperationPolicyBytes: append([]byte(nil), policy...), OperationAcceptedAt: at}
}
func progressWithAttempt(t *testing.T) artifact.ErasureProgressOptions {
	o := progressMetadata(t)
	at := o.Operation.PreparedAt()
	a, err := artifact.NewResumeAllowance(artifact.ResumeAllowanceOptions{Operation: o.Operation, RecoveryPolicyIdentity: strings.Repeat("7", 64), ProtectedPolicyIdentity: o.Operation.ProtectedPolicyIdentity(), PrincipalIdentity: strings.Repeat("9", 64), IssuanceIdentity: strings.Repeat("b", 64), ExpectedBucketOwner: "123456789012", NotBefore: at, NotAfter: at.Add(5 * time.Minute), Maximum: artifact.ResumeBudget{Requests: 4, Reads: 4, ResponseBytes: 20000}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := artifact.NewExactObjectKey(o.Namespace.Identity(), o.Namespace.Prefix()+"/artifacts/"+o.Operation.Scope().Identity()+"/"+o.Operation.ArtifactIdentity())
	if err != nil {
		t.Fatal(err)
	}
	r, err := artifact.NewAttemptRequest(artifact.AttemptRequestOptions{ReservationIdentity: strings.Repeat("c", 64), Operation: o.Operation, Allowance: a, Kind: artifact.AttemptCurrentRead, Key: key, MaximumResponseBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := artifact.NewErasureAttempt(r, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	cost := artifact.ResumeBudget{Requests: 1, Reads: 1, ResponseBytes: 4097}
	usage := artifact.AllowanceUsage{AllowanceIdentity: a.Identity(), Spent: cost, NextSequence: 2}
	o.AllowanceSnapshots = []artifact.ErasureAllowanceSnapshot{{Allowance: a, AcceptedPolicyBytes: append([]byte(nil), o.OperationPolicyBytes...), AcceptedAt: at, Usage: usage, AttemptCount: 1, TotalCost: cost}}
	o.Attempts = []artifact.ErasureAttempt{attempt}
	o.UnrecordedUncertainty = []artifact.ErasureAttempt{attempt}
	o.RequestedAllowanceIdentity = a.Identity()
	o.UnresolvedExists = true
	return o
}
func TestErasureProgressPureMetadataCopiesAndPresentation(t *testing.T) {
	o := progressWithAttempt(t)
	p, err := artifact.NewErasureProgress(o)
	if err != nil || p.Validate() != nil {
		t.Fatal("complete metadata", err)
	}
	if p.Operation().Identity() != o.Operation.Identity() || p.Admission().Identity() != o.Admission.Identity() || !p.HasUnknownHistory() || !p.HasUnresolvedAttempts() || len(p.UnrecordedUncertainty()) != 1 || len(p.AllowanceUsages()) != 1 {
		t.Fatal("copied progress getters")
	}
	if _, ok := p.Fence(); ok {
		t.Fatal("metadata invented fence")
	}
	if _, ok := p.Candidate(); ok {
		t.Fatal("metadata invented candidate")
	}
	if _, ok := p.Published(); ok {
		t.Fatal("metadata invented publication")
	}
	policy := p.AcceptedPolicyBytes()
	saved := append([]byte(nil), policy[0]...)
	policy[0][0] = '!'
	o.AdmissionPolicyBytes[0] = '!'
	o.OperationPolicyBytes[0] = '!'
	o.AllowanceSnapshots[0].AcceptedPolicyBytes[0] = '!'
	o.Attempts[0] = artifact.ErasureAttempt{}
	o.UnrecordedUncertainty[0] = artifact.ErasureAttempt{}
	o.AllowanceSnapshots[0].Usage.Spent.Requests = 99
	if p.Validate() != nil || !bytes.Equal(p.AcceptedPolicyBytes()[0], saved) || p.Attempts()[0].Identity() == "" || p.AllowanceUsages()[0].Spent.Requests != 1 {
		t.Fatal("input or getter aliases private metadata")
	}
	attempts := p.Attempts()
	attempts[0] = artifact.ErasureAttempt{}
	allowances := p.Allowances()
	allowances[0] = artifact.ResumeAllowance{}
	unrecorded := p.UnrecordedUncertainty()
	unrecorded[0] = artifact.ErasureAttempt{}
	if p.Attempts()[0].Identity() == "" || p.Allowances()[0].Identity() == "" || p.UnrecordedUncertainty()[0].Identity() == "" {
		t.Fatal("slice getter alias")
	}
	if p.Allowances()[0].ProtectedDocumentDigest() != "" {
		t.Fatal("progress retained allowance witness")
	}
	if p.String() != "artifact erasure progress" || p.GoString() != "artifact.ErasureProgress{<redacted>}" {
		t.Fatal("presentation contract")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%1000v", "%.2v"} {
		text := fmt.Sprintf(format, p)
		if strings.Contains(text, p.Operation().Identity()) || strings.Contains(text, "tenant-progress") || len(text) > 128 {
			t.Fatal("presentation disclosed metadata or applied padding")
		}
	}
}
func TestErasureProgressMetadataRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*artifact.ErasureProgressOptions)
		want   error
	}{
		{"operation absent", func(o *artifact.ErasureProgressOptions) { o.Operation = artifact.ErasureOperation{} }, artifact.ErrInvalidErasureContract},
		{"admission absent", func(o *artifact.ErasureProgressOptions) { o.Admission = artifact.ArtifactAdmission{} }, artifact.ErrInvalidErasureContract},
		{"namespace absent", func(o *artifact.ErasureProgressOptions) { o.Namespace = artifact.StorageNamespace{} }, artifact.ErrInvalidErasureContract},
		{"authorization absent", func(o *artifact.ErasureProgressOptions) { o.OriginalAuthorization = artifact.ErasureAuthorizationV2{} }, artifact.ErrInvalidErasureContract},
		{"admission policy absent", func(o *artifact.ErasureProgressOptions) { o.AdmissionPolicyBytes = nil }, artifact.ErrInvalidErasureContract},
		{"operation policy absent", func(o *artifact.ErasureProgressOptions) { o.OperationPolicyBytes = nil }, artifact.ErrInvalidErasureContract},
		{"allowance preimage absent", func(o *artifact.ErasureProgressOptions) { o.AllowanceSnapshots = nil }, artifact.ErrInvalidErasureContract},
		{"request preimage absent", func(o *artifact.ErasureProgressOptions) { o.Attempts = nil }, artifact.ErrInvalidErasureContract},
		{"duplicate attempt", func(o *artifact.ErasureProgressOptions) { o.Attempts = append(o.Attempts, o.Attempts[0]) }, artifact.ErrInvalidErasureContract},
		{"duplicate allowance", func(o *artifact.ErasureProgressOptions) {
			o.AllowanceSnapshots = append(o.AllowanceSnapshots, o.AllowanceSnapshots[0])
		}, artifact.ErrInvalidErasureContract},
		{"partial confirmation", func(o *artifact.ErasureProgressOptions) { o.ConfirmedVersion = "version:synthetic" }, artifact.ErrInvalidErasureContract},
		{"missing selected allowance", func(o *artifact.ErasureProgressOptions) { o.RequestedAllowanceIdentity = strings.Repeat("f", 64) }, artifact.ErrErasureConflict},
		{"wrong next sequence", func(o *artifact.ErasureProgressOptions) { o.AllowanceSnapshots[0].Usage.NextSequence++ }, artifact.ErrErasureBindingMismatch},
		{"wrong aggregate count", func(o *artifact.ErasureProgressOptions) { o.AllowanceSnapshots[0].AttemptCount++ }, artifact.ErrErasureBindingMismatch},
		{"wrong aggregate cost", func(o *artifact.ErasureProgressOptions) { o.AllowanceSnapshots[0].TotalCost.ResponseBytes++ }, artifact.ErrErasureBindingMismatch},
		{"unresolved contradiction", func(o *artifact.ErasureProgressOptions) { o.UnresolvedExists = false }, artifact.ErrErasureBindingMismatch},
		{"more without full page", func(o *artifact.ErasureProgressOptions) { o.UncertaintyBookkeepingMore = true }, artifact.ErrErasureBindingMismatch},
		{"acceptance before preparation", func(o *artifact.ErasureProgressOptions) {
			o.OperationAcceptedAt = o.Operation.PreparedAt().Add(-time.Millisecond)
		}, artifact.ErrErasureBindingMismatch},
		{"257 attempts", func(o *artifact.ErasureProgressOptions) { o.Attempts = make([]artifact.ErasureAttempt, 257) }, artifact.ErrInvalidErasureContract},
		{"193 allowance snapshots", func(o *artifact.ErasureProgressOptions) {
			o.AllowanceSnapshots = make([]artifact.ErasureAllowanceSnapshot, 193)
		}, artifact.ErrInvalidErasureContract},
		{"385 evidence records", func(o *artifact.ErasureProgressOptions) { o.Evidence = make([]artifact.ErasureEvidence, 385) }, artifact.ErrInvalidErasureContract},
		{"65 returned uncertainty entries", func(o *artifact.ErasureProgressOptions) {
			o.UnrecordedUncertainty = make([]artifact.ErasureAttempt, 65)
		}, artifact.ErrInvalidErasureContract},
		{"oversized policy", func(o *artifact.ErasureProgressOptions) { o.OperationPolicyBytes = make([]byte, 16385) }, artifact.ErrInvalidErasureContract},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := progressWithAttempt(t)
			tc.change(&o)
			p, err := artifact.NewErasureProgress(o)
			if !errors.Is(err, tc.want) || p.Operation().Identity() != "" || p.Validate() == nil {
				t.Fatal("metadata refusal", err)
			}
		})
	}
	if (artifact.ErasureProgress{}).Validate() == nil {
		t.Fatal("valid zero progress")
	}
}
func TestAttemptResponseMetadataBridgeAndUnknownPair(t *testing.T) {
	for _, code := range []artifact.AttemptResponseCode{artifact.AttemptResponseAbsent, artifact.AttemptResponseUnavailable, artifact.AttemptResponseMalformed, artifact.AttemptResponseDenied, artifact.AttemptResponseAbandoned} {
		t.Run(code.String(), func(t *testing.T) {
			o := progressWithAttempt(t)
			a := o.Attempts[0]
			input := artifact.AttemptResponseOptions{Attempt: a, Code: code, ObservedAt: a.ReservedAt()}
			e, err := artifact.NewAttemptResponseEvidence(input)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := artifact.ParseAttemptResponseEvidence(e, a)
			if err != nil || parsed.Code != code || parsed.Attempt.Identity() != a.Identity() || !parsed.ObservedAt.Equal(a.ReservedAt()) {
				t.Fatal("response metadata bridge", err)
			}
			other, err := artifact.NewErasureAttempt(a.Request(), 2, a.ReservedAt())
			if err != nil {
				t.Fatal(err)
			}
			zero, err := artifact.ParseAttemptResponseEvidence(e, other)
			if err == nil || zero.Attempt.Identity() != "" || zero.Code != 0 || len(zero.CanonicalRecord) != 0 || len(zero.Page.Entries) != 0 {
				t.Fatal("bridge mismatched attempt returned data")
			}
			o.Evidence = []artifact.ErasureEvidence{e}
			o.UnrecordedUncertainty = nil
			o.UnresolvedExists = false
			uncertain := code == artifact.AttemptResponseUnavailable || code == artifact.AttemptResponseMalformed
			if uncertain {
				p, err := artifact.NewErasureProgress(o)
				if err == nil || p.Operation().Identity() != "" {
					t.Fatal("uncertain response alone")
				}
				unknown, err := artifact.NewAttemptUnknownEvidence(a, a.ReservedAt())
				if err != nil {
					t.Fatal(err)
				}
				o.Evidence = append(o.Evidence, unknown)
				o.UnknownExists = true
			}
			p, err := artifact.NewErasureProgress(o)
			if err != nil || p.HasUnknownHistory() != uncertain {
				t.Fatal("response closure", err)
			}
			evidence := p.Evidence()
			evidence[0] = artifact.ErasureEvidence{}
			if p.Evidence()[0].Identity() == "" {
				t.Fatal("evidence alias")
			}
		})
	}
}

func TestErasureProgressAggregateBytesAreSeparateFromCollectionCaps(t *testing.T) {
	for _, count := range []int{24, 32} {
		t.Run(fmt.Sprintf("evidence=%d", count), func(t *testing.T) {
			o := progressMetadata(t)
			at := o.Operation.PreparedAt()
			maximum := artifact.ResumeBudget{Requests: 64, Lists: 64, Pages: 64, Versions: 16384, ResponseBytes: 1 << 30, ListBytes: 64 << 20}
			a, err := artifact.NewResumeAllowance(artifact.ResumeAllowanceOptions{Operation: o.Operation, RecoveryPolicyIdentity: strings.Repeat("7", 64), ProtectedPolicyIdentity: o.Operation.ProtectedPolicyIdentity(), PrincipalIdentity: strings.Repeat("9", 64), IssuanceIdentity: strings.Repeat("b", 64), ExpectedBucketOwner: "123456789012", NotBefore: at, NotAfter: at.Add(5 * time.Minute), Maximum: maximum})
			if err != nil {
				t.Fatal(err)
			}
			key, err := artifact.NewExactObjectKey(o.Namespace.Identity(), o.Namespace.Prefix()+"/artifacts/"+o.Operation.Scope().Identity()+"/"+o.Operation.ArtifactIdentity())
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				r, err := artifact.NewAttemptRequest(artifact.AttemptRequestOptions{ReservationIdentity: progressHash([]byte(fmt.Sprintf("byte-budget-%d", i))), Operation: o.Operation, Allowance: a, Kind: artifact.AttemptVersionList, Key: key, PageLimit: 256, MaximumResponseBytes: 1 << 20})
				if err != nil {
					t.Fatal(err)
				}
				attempt, err := artifact.NewErasureAttempt(r, uint64(i+1), at)
				if err != nil {
					t.Fatal(err)
				}
				o.Attempts = append(o.Attempts, attempt)
				page := artifact.VersionPage{ResponseBytes: 200000}
				for j := 0; j < 256; j++ {
					id := fmt.Sprintf("%04d%04d%s", i, j, strings.Repeat("v", 482))
					version, err := artifact.NewObjectVersion(key.NamespaceIdentity(), key.Key(), artifact.ObjectVersionData, id)
					if err != nil {
						t.Fatal(err)
					}
					page.Entries = append(page.Entries, artifact.VersionEntry{Version: version, IsLatest: j == 0})
				}
				evidence, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: artifact.AttemptResponsePresent, ObservedAt: at, Page: page, ResponseBytes: 200000})
				if err != nil {
					t.Fatal(err)
				}
				o.Evidence = append(o.Evidence, evidence)
			}
			cost := artifact.ResumeBudget{Requests: uint32(count), Lists: uint32(count), Pages: uint32(count), Versions: uint32(256 * count), ResponseBytes: uint64(count) * ((1 << 20) + 1), ListBytes: uint64(count) * ((1 << 20) + 1)}
			o.AllowanceSnapshots = []artifact.ErasureAllowanceSnapshot{{Allowance: a, AcceptedPolicyBytes: append([]byte(nil), o.OperationPolicyBytes...), AcceptedAt: at, Usage: artifact.AllowanceUsage{AllowanceIdentity: a.Identity(), Spent: cost, NextSequence: uint64(count + 1)}, AttemptCount: uint64(count), TotalCost: cost}}
			p, err := artifact.NewErasureProgress(o)
			if count == 24 {
				if err != nil || p.Validate() != nil || len(p.Evidence()) != 24 {
					t.Fatal("bounded large metadata rejected", err)
				}
			} else {
				// Version IDs and version identities alone exceed8MiB after evidence hex framing.
				if 2*(490+64)*256*count <= 8<<20 {
					t.Fatal("independent byte lower bound")
				}
				if !errors.Is(err, artifact.ErrInvalidErasureContract) || p.Operation().Identity() != "" {
					t.Fatal("aggregate canonical byte cap", err)
				}
			}
		})
	}
}
func TestErasureProgressUnspentAllowanceAndRequestedUsage(t *testing.T) {
	o := progressWithAttempt(t)
	o.Attempts = nil
	o.UnrecordedUncertainty = nil
	o.UnresolvedExists = false
	snapshot := &o.AllowanceSnapshots[0]
	snapshot.Usage.Spent = artifact.ResumeBudget{}
	snapshot.Usage.NextSequence = 1
	snapshot.AttemptCount = 0
	snapshot.TotalCost = artifact.ResumeBudget{}
	p, err := artifact.NewErasureProgress(o)
	if err != nil || len(p.AllowanceUsages()) != 1 || p.AllowanceUsages()[0].Spent != (artifact.ResumeBudget{}) || p.AllowanceUsages()[0].NextSequence != 1 {
		t.Fatal("zero usage is valid", err)
	}
	o.RequestedAllowanceIdentity = ""
	p, err = artifact.NewErasureProgress(o)
	if err != nil || len(p.AllowanceUsages()) != 0 || len(p.Allowances()) != 1 {
		t.Fatal("unrequested historical allowance closure", err)
	}
}

func TestProgressIndependentCanonicalHashCalibration(t *testing.T) {
	raw := progressWire(t, map[string]any{"contract": "open-trestle/artifact-erasure-attempt", "schema_version": 1, "request_identity": strings.Repeat("b", 64), "sequence": 1, "reserved_at_milliseconds": int64(1788912000000)}, "contract schema_version identity request_identity sequence reserved_at_milliseconds", "open-trestle/artifact-erasure-attempt/v1\x00")
	if string(raw) != `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"ffd84d6b0a79b906a52534b9c148c4f4272bed0d012373028c933e933ace1d65","request_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sequence":1,"reserved_at_milliseconds":1788912000000}` || progressHash(raw) != "59a8a6f5807cd0080fec35511f9b986f065ff5b6b55a6df436afcc423d04326c" {
		t.Fatal("independent canonical hash calibration")
	}
}
