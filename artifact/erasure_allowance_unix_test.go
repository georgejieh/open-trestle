//go:build unix

package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/erasureauthority"
)

// Only real protected file loaders mint fixtures. No private witness seeding.
func raFile(t *testing.T, wire string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "resume-authority-private.json")
	if err := os.WriteFile(path, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func raPolicy(t *testing.T, changes map[string]string) ProtectedErasurePolicy {
	t.Helper()
	wire := raVariant(t, raPolicyJSON, raPolicyOrder, "open-trestle/protected-artifact-erasure-policy/v1\x00", changes)
	p, err := LoadProtectedErasurePolicy(context.Background(), raFile(t, wire))
	if err != nil || p.Validate() != nil || string(p.Bytes()) != wire {
		t.Fatal("actual protected policy fixture refused", err)
	}
	return p
}
func raLoad(t *testing.T, path string, p ProtectedErasurePolicy, s audit.ReviewScope) ResumeAllowance {
	t.Helper()
	a, err := LoadResumeAllowance(context.Background(), path, p, s)
	if err != nil || a.Validate() != nil || a.ValidateProtected(p) != nil || a.Scope() != s {
		t.Fatal("real allowance loader rejected protected fixture", err)
	}
	return a
}
func raDeniedLoad(t *testing.T, ctx context.Context, path string, p ProtectedErasurePolicy, s audit.ReviewScope) {
	t.Helper()
	a, err := LoadResumeAllowance(ctx, path, p, s)
	if err == nil {
		t.Fatal("protected allowance refusal missing")
	}
	raZero(t, a)
	// No unfrozen exact error taxonomy is assumed, but diagnostics must not reveal paths or bytes.
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%f"} {
		message := fmt.Sprintf(format, err)
		for _, secret := range []string{path, raJSON, raIdentity, raScopeIdentity, "resume-authority-private", "tenant-auth", "repo-auth", "run-auth"} {
			if secret != "" && strings.Contains(message, secret) {
				t.Fatal("error disclosed authority input", format)
			}
		}
	}
}

func TestResumeAllowanceProtectedActualCandidateChain(t *testing.T) {
	p := raPolicy(t, nil)
	s := raMatchingScope(t)
	namespace, err := NewStorageNamespace(strings.Repeat("1", 64), "authorization-fixture/a_0-z", strings.Repeat("2", 64))
	if err != nil || namespace.Identity() != raNamespaceIdentity || namespace.Identity() != p.NamespaceIdentity() {
		t.Fatal("native namespace differs from frozen literal", err)
	}
	original, err := New(s, KindContextPacket, "text/plain", ClassificationRestricted, OriginHost, ProtectionEnvelopeEncrypted, []string{strings.Repeat("a", 64)}, []byte("synthetic authorization admission"), time.UnixMilli(100).UTC(), time.UnixMilli(1000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := Encode(original)
	if err != nil || string(artifactBytes) != raOriginalArtifactJSON {
		t.Fatal("historical artifact bytes changed", err)
	}
	admission, err := NewArtifactAdmission(original, namespace.Identity(), time.UnixMilli(500).UTC())
	if err != nil {
		t.Fatal(err)
	}
	admissionBytes, err := EncodeArtifactAdmission(admission)
	if err != nil || string(admissionBytes) != raAdmissionJSON {
		t.Fatal("historical admission bytes changed", err)
	}
	auth, err := NewErasureAuthorizationV2(ErasureAuthorizationV2Options{Scope: s, NamespaceIdentity: namespace.Identity(), ArtifactIdentity: original.Identity(), AdmissionIdentity: admission.Identity(), PolicyIdentity: p.ErasurePolicyIdentity(), PrincipalIdentity: strings.Repeat("8", 64), HoldClearanceIdentity: strings.Repeat("9", 64), FenceRetentionPolicyIdentity: p.FenceRetentionPolicyIdentity(), Reason: DeletionExpired, IssuedAt: time.UnixMilli(900).UTC(), ExpiresAt: time.UnixMilli(1500).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	grantBytes, err := EncodeErasureAuthorizationV2(auth)
	if err != nil || string(grantBytes) != raGrantJSON || auth.ProtectedDocumentDigest() != "" {
		t.Fatal("historical authorization bytes changed or constructor minted authority", err)
	}
	loadedAuth, err := LoadErasureAuthorizationV2(context.Background(), raFile(t, string(grantBytes)), p)
	if err != nil || loadedAuth.ValidateProtected(p) != nil || loadedAuth.ProtectedDocumentDigest() != raDocumentDigest {
		t.Fatal("real protected authorization fixture refused", err)
	}
	operation, err := NewErasureOperationCandidate(loadedAuth, admission, p, time.UnixMilli(1000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	operationBytes, err := EncodeErasureOperation(operation)
	if err != nil || string(operationBytes) != raOperationJSON || operation.Ref().Scope() != s {
		t.Fatal("candidate differs from literal or loses scope", err)
	}
	options := raOptions(t)
	options.Operation = operation
	shape := raNew(t, options)
	encoded, err := EncodeResumeAllowance(shape)
	if err != nil || string(encoded) != raJSON {
		t.Fatal("new allowance did not bind native chain", err)
	}
	path := raFile(t, string(encoded))
	document, err := erasureauthority.LoadDocument(context.Background(), path)
	if err != nil || document.Validate() != nil || document.Digest() != raHash(raJSON) || !bytes.Equal(document.Bytes(), encoded) {
		t.Fatal("actual Document differs from raw recipe", err)
	}
	loaded := raLoad(t, path, p, s)
	if loaded.Identity() != raIdentity || loaded.ProtectedDocumentDigest() != document.Digest() || loaded.ProtectedPolicyIdentity() != p.Identity() {
		t.Fatal("witness is not exact document/allowance/current-policy binding")
	}
	for _, unminted := range []ResumeAllowance{shape, raParse(t, raJSON, s)} {
		if unminted.ValidateProtected(p) == nil || unminted.ProtectedDocumentDigest() != "" {
			t.Fatal("New/Parse minted protected witness")
		}
		if !unminted.AllowsOperation(operation, time.UnixMilli(1000).UTC()) {
			t.Fatal("metadata predicate incorrectly requires witness")
		}
	}
	// This old fixture has expired relative to any present-day wall clock, and its
	// allowance extends beyond the policy window. Loading is purely structural.
	if !loaded.AllowsOperation(operation, time.UnixMilli(1400).UTC()) || p.AllowsAt(time.UnixMilli(1400).UTC()) {
		t.Fatal("fixture does not separate allowance predicate from current policy")
	}
	if !loaded.AllowsOperation(operation, time.UnixMilli(1500).UTC()) {
		t.Fatal("original authorization expiry incorrectly reapplied to Resume metadata")
	}
	futureWire := raChange(t, map[string]string{"not_before_milliseconds": "253402299899999", "not_after_milliseconds": "253402300799999"})
	future := raLoad(t, raFile(t, futureWire), p, s)
	if future.NotAfter() != time.UnixMilli(253402300799999).UTC() {
		t.Fatal("future structural load sampled wall clock or truncated time")
	}
	raw := document.Bytes()
	raw[0] = 'x'
	if document.Digest() != raHash(raJSON) || loaded.ValidateProtected(p) != nil {
		t.Fatal("Document copy mutation changed witness")
	}
	raRedaction(t, loaded)
	// The candidate above has NEVER been accepted by a database. No Resume, SQL,
	// reservation, dispatch, provider state, or erasure claim is made by this chain.
}

func TestResumeAllowanceProtectedPolicyAndScopeBindings(t *testing.T) {
	p := raPolicy(t, nil)
	s := raMatchingScope(t)
	path := raFile(t, raJSON)
	a := raLoad(t, path, p, s)
	raDeniedLoad(t, context.Background(), path, ProtectedErasurePolicy{}, s)
	var forgedPolicy ProtectedErasurePolicy
	if err := json.Unmarshal([]byte(raPolicyJSON), &forgedPolicy); err != nil {
		t.Fatal(err)
	}
	raDeniedLoad(t, context.Background(), path, forgedPolicy, s)
	for _, key := range []string{"recovery_policy_identity", "protected_policy_identity", "namespace_identity"} {
		bad := raChange(t, map[string]string{key: raQuote(raOther)})
		shape := raParse(t, bad, s)
		if shape.ValidateProtected(p) == nil {
			t.Fatal("unminted rebound metadata acquired authority")
		}
		raDeniedLoad(t, context.Background(), raFile(t, bad), p, s)
	}
	for _, change := range []map[string]string{{"recovery_policy_identity": raQuote(raOther)}, {"configuration_evidence_identity": raQuote(raOther)}, {"database_authority_identity": raQuote(raOther)}, {"not_before_milliseconds": "2000", "not_after_milliseconds": "3000"}} {
		other := raPolicy(t, change)
		if a.ValidateProtected(other) == nil {
			t.Fatal("witness rebound to a different current policy")
		}
		raDeniedLoad(t, context.Background(), path, other, s)
	}
	// A protected refresh changes only explicitly refreshable fields here. The
	// original operation stays byte-identical and keeps its original policy ID.
	fresh := raPolicy(t, map[string]string{"configuration_evidence_identity": raQuote(raOther), "not_before_milliseconds": "2000", "not_after_milliseconds": "3000"})
	freshWire := raChange(t, map[string]string{"protected_policy_identity": raQuote(fresh.Identity()), "issuance_identity": raQuote(raOther)})
	renewed := raLoad(t, raFile(t, freshWire), fresh, s)
	if renewed.ValidateProtected(p) == nil || a.ValidateProtected(fresh) == nil || !renewed.AllowsOperation(raOperation(t), time.UnixMilli(2000).UTC()) {
		t.Fatal("fresh loaded policy mixed with original operation binding")
	}
	// No scope is inferred from wire. Each different full scope must be supplied
	// explicitly; only then can its own deliberately protected metadata load.
	for _, foreign := range []audit.ReviewScope{raScope(t, "foreign-tenant", "repo-auth", "run-auth"), raScope(t, "tenant-auth", "foreign-repo", "run-auth"), raScope(t, "tenant-auth", "repo-auth", "foreign-run")} {
		raDeniedLoad(t, context.Background(), path, p, foreign)
		wire := raChange(t, map[string]string{"scope_identity": raQuote(foreign.Identity())})
		foreignPath := raFile(t, wire)
		raDeniedLoad(t, context.Background(), foreignPath, p, s)
		loaded := raLoad(t, foreignPath, p, foreign)
		if loaded.Scope() != foreign || loaded.AllowsOperation(raOperation(t), time.UnixMilli(1000).UTC()) {
			t.Fatal("foreign protected scope matched original operation")
		}
	}
	// The loader has no operation/admission input. A deliberate protected file
	// with other well-shaped original bindings is loaded metadata, not DB acceptance.
	for _, key := range []string{"operation_identity", "artifact_identity", "admission_identity", "original_authorization_identity", "authorization_document_digest"} {
		wire := raChange(t, map[string]string{key: raQuote(raOther)})
		foreign := raLoad(t, raFile(t, wire), p, s)
		if foreign.AllowsOperation(raOperation(t), time.UnixMilli(1000).UTC()) {
			t.Fatal("loaded foreign original binding matched", key)
		}
	}
	// No policy field carries expected owner or original principal. New valid
	// owner/principal values are identity-bound metadata; DB original-winner and
	// provider owner-header checks belong to separately admitted later work.
	for _, key := range []string{"expected_bucket_owner", "principal_identity", "issuance_identity"} {
		replacement := raQuote(raOther)
		if key == "expected_bucket_owner" {
			replacement = raQuote("000000000001")
		}
		wire := raChange(t, map[string]string{key: replacement})
		other := raLoad(t, raFile(t, wire), p, s)
		if other.Identity() == a.Identity() || other.ProtectedDocumentDigest() == a.ProtectedDocumentDigest() {
			t.Fatal("owner/principal/issuance omitted from exact document identity")
		}
	}
}

func TestResumeAllowanceProtectedSnapshotCopiesAndNoMint(t *testing.T) {
	policyPath := raFile(t, raPolicyJSON)
	p, err := LoadProtectedErasurePolicy(context.Background(), policyPath)
	if err != nil {
		t.Fatal(err)
	}
	path := raFile(t, raJSON)
	a := raLoad(t, path, p, raMatchingScope(t))
	copyA, copyP := a, p
	raw, err := EncodeResumeAllowance(a)
	if err != nil {
		t.Fatal(err)
	}
	parsed := raParse(t, string(raw), a.Scope())
	raw[0] = 'x'
	if parsed.ValidateProtected(p) == nil || parsed.ProtectedDocumentDigest() != "" || parsed.Identity() != a.Identity() {
		t.Fatal("canonical roundtrip retained witness or changed shape")
	}
	var forged ResumeAllowance
	for _, raw := range []string{raJSON, `{"witness":{"document":"` + raHash(raJSON) + `","allowanceIdentity":"` + raIdentity + `","policyIdentity":"` + p.Identity() + `"}}`} {
		if err := json.Unmarshal([]byte(raw), &forged); err != nil {
			t.Fatal(err)
		}
		raZero(t, forged)
	}
	// Ordinary reflection cannot set any allowance field or mint a loaded witness.
	rv := reflect.ValueOf(&forged).Elem()
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).CanSet() {
			t.Fatal("reflection exposes mutable allowance field")
		}
	}
	newWire := raChange(t, map[string]string{"issuance_identity": raQuote(raOther)})
	replacement := filepath.Join(filepath.Dir(path), "replacement.json")
	if err := os.WriteFile(replacement, []byte(newWire), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	next := raLoad(t, path, p, a.Scope())
	if next.Identity() == a.Identity() || next.ProtectedDocumentDigest() != raHash(newWire) {
		t.Fatal("reopen failed to bind replacement document")
	}
	if err := os.WriteFile(policyPath, []byte("not a policy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []ResumeAllowance{a, copyA} {
		b, err := EncodeResumeAllowance(snapshot)
		if err != nil || string(b) != raJSON || snapshot.ValidateProtected(copyP) != nil || snapshot.ProtectedDocumentDigest() != raHash(raJSON) {
			t.Fatal("sequential replacement/unlink changed immutable witness", err)
		}
		raRedaction(t, snapshot)
	}
	if next.ValidateProtected(copyP) != nil {
		t.Fatal("replacement snapshot changed after unlink")
	}
	raDeniedLoad(t, context.Background(), path, copyP, a.Scope())
	// This is sequential replacement evidence, NOT an atomic two-file snapshot,
	// inode-race exclusion theorem, hostile-kernel boundary, or continuous revocation.
}

func TestResumeAllowanceProtectedFileIntegrityAndBounds(t *testing.T) {
	p := raPolicy(t, nil)
	s := raMatchingScope(t)
	for _, mode := range []os.FileMode{0400, 0600, 0644} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			path := raFile(t, raJSON)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			raLoad(t, path, p, s)
		})
	}
	for _, mutation := range []string{"group-write", "world-write", "directory", "symlink", "dangling-symlink", "symlink-ancestor", "writable-parent", "writable-grandparent", "missing"} {
		t.Run(mutation, func(t *testing.T) {
			path := raFile(t, raJSON)
			parent := filepath.Dir(path)
			switch mutation {
			case "group-write":
				if err := os.Chmod(path, 0620); err != nil {
					t.Fatal(err)
				}
			case "world-write":
				if err := os.Chmod(path, 0602); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = parent
			case "symlink", "dangling-symlink":
				target := path
				if mutation == "dangling-symlink" {
					target += ".absent"
				}
				link := filepath.Join(parent, "link.json")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "symlink-ancestor":
				link := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, filepath.Base(path))
			case "writable-parent":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "writable-grandparent":
				child := filepath.Join(parent, "private")
				if err := os.Mkdir(child, 0700); err != nil {
					t.Fatal(err)
				}
				moved := filepath.Join(child, filepath.Base(path))
				if err := os.Rename(path, moved); err != nil {
					t.Fatal(err)
				}
				path = moved
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			raDeniedLoad(t, context.Background(), path, p, s)
		})
	}
	t.Run("owned-sticky-parent", func(t *testing.T) {
		path := raFile(t, raJSON)
		if err := os.Chmod(filepath.Dir(path), 0777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		raLoad(t, path, p, s)
	})
	path := raFile(t, raJSON)
	parent := filepath.Dir(path)
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"", "relative.json", parent + "/./" + filepath.Base(path), parent + "//" + filepath.Base(path), child + "/../" + filepath.Base(path), path + "/", path + "\x00private", "/" + strings.Repeat("x", 4096)} {
		raDeniedLoad(t, context.Background(), alias, p, s)
	}
	// The accepted raw Document has a 16384-byte cap, distinct from allowance4096.
	// Valid raw snapshots at/below that cap still MUST fail allowance parsing.
	for _, size := range []int{4095, 4096, 4097, 16384, 16385} {
		content := raJSON + strings.Repeat(" ", size-len(raJSON))
		path := raFile(t, content)
		document, err := erasureauthority.LoadDocument(context.Background(), path)
		if size <= 16384 {
			if err != nil || len(document.Bytes()) != size {
				t.Fatal("raw Document fixture control failed", err)
			}
		} else if err == nil {
			t.Fatal("raw Document bound not enforced")
		}
		raDeniedLoad(t, context.Background(), path, p, s)
	}
	for _, content := range []string{"", "null", raJSON + "\n", raJSON + "{}", strings.Replace(raJSON, `"123456789012"`, `"000000000000"`, 1), raChange(t, map[string]string{"expected_bucket_owner": raQuote("12345678901a")}), raChange(t, map[string]string{"not_after_milliseconds": "901001"}), "\xff\x00"} {
		raDeniedLoad(t, context.Background(), raFile(t, content), p, s)
	}
}

func TestResumeAllowanceLoadContextAndFullScopeRefusal(t *testing.T) {
	p := raPolicy(t, nil)
	s := raMatchingScope(t)
	path := raFile(t, raJSON)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		for _, candidate := range []string{path, path + ".absent"} {
			raDeniedLoad(t, ctx, candidate, p, s)
		}
	}
	for _, candidate := range []string{path, path + ".absent"} {
		raDeniedLoad(t, context.Background(), candidate, p, audit.ReviewScope{})
	}
	var forged audit.ReviewScope
	if err := json.Unmarshal([]byte(`{"identity":"`+raScopeIdentity+`"}`), &forged); err != nil {
		t.Fatal(err)
	}
	raDeniedLoad(t, context.Background(), path, p, forged)
	// Context/scope must be checked before file I/O. These black-box refusals do
	// not observe syscall ordering. No private filesystem seam is invented here;
	// root must read the later implementation's pre-I/O control flow explicitly.
	// No polling, process, goroutine, wall-clock sample, or external service fixture.
}
