//go:build unix

package artifact_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/erasureauthority"
)

var azPolicyOrder = strings.Fields("contract schema_version identity namespace_identity backend_configuration_identity prefix namespace_epoch_identity backend_kind database_authority_identity namespace_mode protocol ownership fence_retention_policy_identity erasure_policy_identity recovery_policy_identity configuration_evidence_identity not_before_milliseconds not_after_milliseconds")

func azProtectedFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "private-authority.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func azLoadPolicy(t *testing.T, wire string) artifact.ProtectedErasurePolicy {
	t.Helper()
	policy, err := artifact.LoadProtectedErasurePolicy(context.Background(), azProtectedFile(t, wire))
	if err != nil || policy.Validate() != nil || !bytes.Equal(policy.Bytes(), []byte(wire)) {
		t.Fatal("actual protected policy did not load", err)
	}
	return policy
}

func azPolicyVariant(t *testing.T, changes map[string]string, bindNamespace bool) string {
	t.Helper()
	fields := azFields(t, azPolicyJSON)
	for key, value := range changes {
		if _, ok := fields[key]; !ok {
			t.Fatal("unknown policy test field", key)
		}
		fields[key] = json.RawMessage(value)
	}
	if bindNamespace {
		unsigned := `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"backend_configuration_identity":` + string(fields["backend_configuration_identity"]) + `,"prefix":` + string(fields["prefix"]) + `,"namespace_epoch_identity":` + string(fields["namespace_epoch_identity"]) + `}`
		fields["namespace_identity"] = json.RawMessage(azQuote(azHash("open-trestle/artifact-storage-namespace/v1\x00" + unsigned)))
	}
	fields["identity"] = json.RawMessage(azQuote(azHash("open-trestle/protected-artifact-erasure-policy/v1\x00" + azOrdered(t, fields, azPolicyOrder, true))))
	return azOrdered(t, fields, azPolicyOrder, false)
}

func azLoadGrant(t *testing.T, wire string, policy artifact.ProtectedErasurePolicy) artifact.ErasureAuthorizationV2 {
	t.Helper()
	value, err := artifact.LoadErasureAuthorizationV2(context.Background(), azProtectedFile(t, wire), policy)
	if err != nil || value.Validate() != nil || value.ValidateProtected(policy) != nil {
		t.Fatal("actual protected matching grant did not load", err)
	}
	if value.ProtectedPolicyIdentity() != policy.Identity() || value.ProtectedDocumentDigest() != azHash(wire) {
		t.Fatal("witness not bound to exact policy and document")
	}
	encoded, err := artifact.EncodeErasureAuthorizationV2(value)
	if err != nil || string(encoded) != wire {
		t.Fatal("protected witness changed canonical encoding")
	}
	return value
}

func azDeniedGrant(t *testing.T, ctx context.Context, path string, policy artifact.ProtectedErasurePolicy, want error) {
	t.Helper()
	value, err := artifact.LoadErasureAuthorizationV2(ctx, path, policy)
	azError(t, err, want)
	azZero(t, value)
}

func azZeroPolicy(t *testing.T, policy artifact.ProtectedErasurePolicy) {
	t.Helper()
	if policy.Validate() == nil || len(policy.Bytes()) != 0 || !policy.NotBefore().IsZero() || !policy.NotAfter().IsZero() || policy.AllowsAt(time.UnixMilli(1)) {
		t.Fatal("unloaded policy retained authority")
	}
	for _, value := range []string{policy.Identity(), policy.NamespaceIdentity(), policy.BackendConfigurationIdentity(), policy.Prefix(), policy.NamespaceEpochIdentity(),
		policy.BackendKind(), policy.DatabaseAuthorityIdentity(), policy.NamespaceMode(), policy.Protocol(), policy.Ownership(), policy.FenceRetentionPolicyIdentity(),
		policy.ErasurePolicyIdentity(), policy.RecoveryPolicyIdentity(), policy.ConfigurationEvidenceIdentity()} {
		if value != "" {
			t.Fatal("unloaded policy retained getter")
		}
	}
}

func TestAuthorizationV2ProtectedLoadWitness(t *testing.T) {
	policy := azLoadPolicy(t, azPolicyJSON)
	value := azLoadGrant(t, azJSON, policy)
	if value.Identity() != azIdentity || value.ProtectedPolicyIdentity() != azPolicyIdentity || value.ProtectedDocumentDigest() != azDocumentDigest {
		t.Fatal("literal protected witness differs")
	}
	admission := azMatchingAdmission(t)
	if !value.AllowsAdmission(admission, time.UnixMilli(1000)) || policy.AllowsAt(time.UnixMilli(1000)) {
		t.Fatal("fixture must separate grant metadata from policy time")
	}
	// A future effect caller must also check policy.AllowsAt at its captured instant.
	for _, shape := range []artifact.ErasureAuthorizationV2{azNew(t, azOptions(t)), azParse(t, azJSON)} {
		if shape.Validate() != nil || !shape.AllowsAdmission(admission, time.UnixMilli(1000)) {
			t.Fatal("shape control was not eligible metadata")
		}
		azUnminted(t, shape, policy)
	}
	encoded, err := artifact.EncodeErasureAuthorizationV2(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded := azParse(t, string(encoded))
	if decoded.Identity() != value.Identity() || decoded.Scope() != value.Scope() || !decoded.AllowsAdmission(admission, time.UnixMilli(1000)) {
		t.Fatal("roundtrip lost more than protected witness")
	}
	azUnminted(t, decoded, policy)
	azError(t, value.ValidateProtected(artifact.ProtectedErasurePolicy{}), artifact.ErrErasureAuthorityRequired)
	azRedacted(t, value)
	for _, interval := range []struct {
		name       string
		start, end int64
	}{
		{"historical", 1, 2}, {"maximum lifetime", 1, 900001}, {"far future", 253402300799998, 253402300799999},
	} {
		t.Run(interval.name, func(t *testing.T) {
			wire := azVariant(t, map[string]string{"issued_at_milliseconds": fmt.Sprint(interval.start), "expires_at_milliseconds": fmt.Sprint(interval.end)})
			grant := azLoadGrant(t, wire, policy)
			if grant.IssuedAt() != time.UnixMilli(interval.start).UTC() || grant.ExpiresAt() != time.UnixMilli(interval.end).UTC() {
				t.Fatal("load changed structural times")
			}
		})
	}
	futurePolicy := azLoadPolicy(t, azPolicyVariant(t, map[string]string{"not_before_milliseconds": "253402300799998", "not_after_milliseconds": "253402300799999"}, true))
	azLoadGrant(t, azJSON, futurePolicy)
}

func TestAuthorizationV2ProtectedBindingsAndLegacy(t *testing.T) {
	policy := azLoadPolicy(t, azPolicyJSON)
	value := azLoadGrant(t, azJSON, policy)
	for _, field := range []string{"namespace_identity", "policy_identity", "fence_retention_policy_identity"} {
		t.Run("grant/"+field, func(t *testing.T) {
			wire := azVariant(t, map[string]string{field: azQuote(azOther)})
			azParse(t, wire)
			azDeniedGrant(t, context.Background(), azProtectedFile(t, wire), policy, artifact.ErrErasureBindingMismatch)
		})
	}
	for field, replacement := range map[string]string{
		"prefix": `"other-prefix"`, "backend_configuration_identity": azQuote(azOther), "namespace_epoch_identity": azQuote(azOther),
		"erasure_policy_identity": azQuote(azOther), "fence_retention_policy_identity": azQuote(azOther),
		"database_authority_identity": azQuote(azOther), "configuration_evidence_identity": azQuote(azOther),
		"recovery_policy_identity": azQuote(azOther), "not_before_milliseconds": "2", "not_after_milliseconds": "3",
	} {
		t.Run("policy/"+field, func(t *testing.T) {
			changes := map[string]string{field: replacement}
			if field == "not_before_milliseconds" {
				changes["not_after_milliseconds"] = "3"
			}
			other := azLoadPolicy(t, azPolicyVariant(t, changes, true))
			if other.Identity() == policy.Identity() {
				t.Fatal("different valid policy snapshot not identity-bound")
			}
			azError(t, value.ValidateProtected(other), artifact.ErrErasureBindingMismatch)
			if value.ValidateProtected(policy) != nil || value.ProtectedPolicyIdentity() != policy.Identity() {
				t.Fatal("failed validation rebound or destroyed witness")
			}
			if other.NamespaceIdentity() == policy.NamespaceIdentity() && other.ErasurePolicyIdentity() == policy.ErasurePolicyIdentity() && other.FenceRetentionPolicyIdentity() == policy.FenceRetentionPolicyIdentity() {
				fresh := azLoadGrant(t, azJSON, other)
				if fresh.Identity() != value.Identity() || fresh.ProtectedPolicyIdentity() == value.ProtectedPolicyIdentity() {
					t.Fatal("explicit second load did not bind new policy snapshot")
				}
				azError(t, fresh.ValidateProtected(policy), artifact.ErrErasureBindingMismatch)
			} else {
				azDeniedGrant(t, context.Background(), azProtectedFile(t, azJSON), other, artifact.ErrErasureBindingMismatch)
			}
		})
	}
	o := azOptions(t)
	o.LegacyReceiptIdentity = azOther
	shape := azNew(t, o)
	wire := azVariant(t, map[string]string{"legacy_receipt_identity": azQuote(azOther)})
	parsed := azParse(t, wire)
	for _, grant := range []artifact.ErasureAuthorizationV2{shape, parsed} {
		if grant.LegacyReceiptIdentity() != azOther || !grant.AllowsAdmission(azMatchingAdmission(t), time.UnixMilli(1000)) {
			t.Fatal("legacy lineage is valid metadata shape")
		}
		azUnminted(t, grant, policy)
	}
	azDeniedGrant(t, context.Background(), azProtectedFile(t, wire), policy, artifact.ErrErasureLegacyInventoryRequired)
	wire = azVariant(t, map[string]string{"legacy_receipt_identity": azQuote(azOther), "namespace_identity": azQuote(azOther)})
	azDeniedGrant(t, context.Background(), azProtectedFile(t, wire), policy, artifact.ErrErasureBindingMismatch)
}

func TestAuthorizationV2ProtectedSnapshotIsolation(t *testing.T) {
	policyPath, grantPath := azProtectedFile(t, azPolicyJSON), azProtectedFile(t, azJSON)
	policy, err := artifact.LoadProtectedErasurePolicy(context.Background(), policyPath)
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.LoadErasureAuthorizationV2(context.Background(), grantPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	copiedPolicy, copiedGrant := policy, value
	policyBytes := policy.Bytes()
	policyBytes[0] = 'x'
	grantBytes, err := artifact.EncodeErasureAuthorizationV2(value)
	if err != nil {
		t.Fatal(err)
	}
	grantBytes[0] = 'y'
	replacementGrant := azVariant(t, map[string]string{"reason": `"tenant_erasure"`})
	replacementPolicy := azPolicyVariant(t, map[string]string{"configuration_evidence_identity": azQuote(azOther)}, true)
	for path, content := range map[string]string{grantPath: replacementGrant, policyPath: replacementPolicy} {
		next := path + ".replacement"
		if err := os.WriteFile(next, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(next, path); err != nil {
			t.Fatal(err)
		}
	}
	freshPolicy, err := artifact.LoadProtectedErasurePolicy(context.Background(), policyPath)
	if err != nil {
		t.Fatal(err)
	}
	freshGrant, err := artifact.LoadErasureAuthorizationV2(context.Background(), grantPath, freshPolicy)
	if err != nil || freshGrant.ValidateProtected(freshPolicy) != nil || freshGrant.Identity() == value.Identity() || freshGrant.ProtectedDocumentDigest() != azHash(replacementGrant) {
		t.Fatal("explicit reload did not capture replacement")
	}
	azError(t, value.ValidateProtected(freshPolicy), artifact.ErrErasureBindingMismatch)
	azError(t, freshGrant.ValidateProtected(policy), artifact.ErrErasureBindingMismatch)
	for _, path := range []string{policyPath, grantPath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []artifact.ErasureAuthorizationV2{value, copiedGrant} {
		for _, p := range []artifact.ProtectedErasurePolicy{policy, copiedPolicy} {
			if p.Validate() != nil || !bytes.Equal(p.Bytes(), []byte(azPolicyJSON)) || grant.ValidateProtected(p) != nil || grant.ProtectedPolicyIdentity() != azPolicyIdentity || grant.ProtectedDocumentDigest() != azDocumentDigest {
				t.Fatal("copy/buffer/replacement/removal changed protected snapshot")
			}
		}
		wire, err := artifact.EncodeErasureAuthorizationV2(grant)
		if err != nil || string(wire) != azJSON {
			t.Fatal("snapshot canonical content changed")
		}
		azUnminted(t, azParse(t, string(wire)), copiedPolicy)
		azRedacted(t, grant, policyPath, grantPath)
	}
	azDeniedGrant(t, context.Background(), grantPath, copiedPolicy, artifact.ErrErasureAuthorityRequired)
}

func TestAuthorizationV2PolicyWrapperAndUnmintedRefusal(t *testing.T) {
	path := azProtectedFile(t, azPolicyJSON)
	wrapped, err := artifact.LoadProtectedErasurePolicy(context.Background(), path)
	if err != nil || wrapped.Validate() != nil {
		t.Fatal("public wrapper refused protected policy", err)
	}
	direct, err := erasureauthority.LoadPolicy(context.Background(), path)
	if err != nil || direct.Validate() != nil || direct.Identity() != wrapped.Identity() || !bytes.Equal(direct.Bytes(), wrapped.Bytes()) {
		t.Fatal("wrapper differs from accepted loader")
	}
	// Assignment pins the frozen alias rather than a new public mintable policy type.
	var alias artifact.ProtectedErasurePolicy = direct
	value := azLoadGrant(t, azJSON, wrapped)
	if value.ValidateProtected(alias) != nil {
		t.Fatal("identical policy snapshot from existing loader not recognized")
	}
	grantPath := azProtectedFile(t, azJSON)
	for _, wire := range []string{"{}", "null", azPolicyJSON, `{"Verified":true,"Identity":"` + azPolicyIdentity + `","Bytes":"eA=="}`} {
		var forged artifact.ProtectedErasurePolicy
		_ = json.Unmarshal([]byte(wire), &forged)
		azZeroPolicy(t, forged)
		azDeniedGrant(t, context.Background(), grantPath, forged, artifact.ErrErasureAuthorityRequired)
		azError(t, value.ValidateProtected(forged), artifact.ErrErasureAuthorityRequired)
	}
	for _, shape := range []artifact.ErasureAuthorizationV2{azNew(t, azOptions(t)), azParse(t, azJSON)} {
		azUnminted(t, shape, wrapped)
	}
	for _, wire := range []string{azJSON, "{}", azPolicyVariant(t, map[string]string{"namespace_identity": azQuote(azOther)}, false),
		azPolicyVariant(t, map[string]string{"backend_kind": `"generic_s3"`}, true),
		azPolicyVariant(t, map[string]string{"namespace_mode": `"legacy"`}, true),
		azPolicyVariant(t, map[string]string{"protocol": `"v1"`}, true),
		azPolicyVariant(t, map[string]string{"ownership": `"current_only"`}, true)} {
		policy, err := artifact.LoadProtectedErasurePolicy(context.Background(), azProtectedFile(t, wire))
		azError(t, err, artifact.ErrErasureAuthorityRequired)
		azZeroPolicy(t, policy)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		policy, err := artifact.LoadProtectedErasurePolicy(ctx, path)
		azError(t, err, artifact.ErrErasureAuthorityRequired)
		azZeroPolicy(t, policy)
		azDeniedGrant(t, ctx, grantPath, wrapped, artifact.ErrErasureAuthorityRequired)
	}
	for _, wire := range []string{"{}", azHistoricalV1, azJSON + "\n", strings.Replace(azJSON, azIdentity, azOther, 1),
		azVariant(t, map[string]string{"scope_identity": azQuote(azOther)})} {
		want := artifact.ErrInvalidErasureContract
		if wire == strings.Replace(azJSON, azIdentity, azOther, 1) || wire == azVariant(t, map[string]string{"scope_identity": azQuote(azOther)}) {
			want = artifact.ErrErasureIdentityMismatch
		}
		azDeniedGrant(t, context.Background(), azProtectedFile(t, wire), wrapped, want)
	}
	for _, size := range []int{0, 8192, 8193, 16384, 16385} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			want := artifact.ErrInvalidErasureContract
			if size == 0 || size > 16384 {
				want = artifact.ErrErasureAuthorityRequired
			}
			azDeniedGrant(t, context.Background(), azProtectedFile(t, strings.Repeat("x", size)), wrapped, want)
		})
	}
}

func TestAuthorizationV2ProtectedFileAuthorityDenials(t *testing.T) {
	policy := azLoadPolicy(t, azPolicyJSON)
	for _, mutation := range []string{"group writable", "world writable", "directory", "symlink file", "dangling symlink", "symlink ancestor", "writable parent", "writable grandparent", "missing"} {
		t.Run(mutation, func(t *testing.T) {
			// Policy JSON is also a valid raw document: both wrappers must refuse path authority first.
			path := azProtectedFile(t, azPolicyJSON)
			parent := filepath.Dir(path)
			switch mutation {
			case "group writable":
				if err := os.Chmod(path, 0620); err != nil {
					t.Fatal(err)
				}
			case "world writable":
				if err := os.Chmod(path, 0602); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = parent
			case "symlink file", "dangling symlink":
				target := path
				if mutation == "dangling symlink" {
					target += ".absent"
				}
				link := filepath.Join(parent, "link.json")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "symlink ancestor":
				link := filepath.Join(t.TempDir(), "link-parent")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, filepath.Base(path))
			case "writable parent":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "writable grandparent":
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
			denied, err := artifact.LoadProtectedErasurePolicy(context.Background(), path)
			azError(t, err, artifact.ErrErasureAuthorityRequired)
			azZeroPolicy(t, denied)
			azDeniedGrant(t, context.Background(), path, policy, artifact.ErrErasureAuthorityRequired)
		})
	}
	for _, mode := range []os.FileMode{0400, 0600, 0644} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			path := azProtectedFile(t, azJSON)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			grant, err := artifact.LoadErasureAuthorizationV2(context.Background(), path, policy)
			if err != nil || grant.ValidateProtected(policy) != nil {
				t.Fatal("existing protected mode semantics changed")
			}
		})
	}
	t.Run("owned sticky parent", func(t *testing.T) {
		path := azProtectedFile(t, azJSON)
		if err := os.Chmod(filepath.Dir(path), 0777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		grant, err := artifact.LoadErasureAuthorizationV2(context.Background(), path, policy)
		if err != nil || grant.ValidateProtected(policy) != nil {
			t.Fatal("existing owned sticky semantics changed")
		}
	})
	path := azProtectedFile(t, azJSON)
	parent := filepath.Dir(path)
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{parent + "/./" + filepath.Base(path), parent + "//" + filepath.Base(path), child + "/../" + filepath.Base(path), path + "/", path + "\x00private", "/" + strings.Repeat("x", 4096), "relative.json"} {
		azDeniedGrant(t, context.Background(), alias, policy, artifact.ErrErasureAuthorityRequired)
	}
}
