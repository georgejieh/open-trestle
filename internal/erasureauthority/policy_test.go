package erasureauthority_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/erasureauthority"
)

const protectedErrorText = "protected erasure authority unavailable or unstable"
const namespaceContract = "open-trestle/artifact-storage-namespace"
const policyContract = "open-trestle/protected-artifact-erasure-policy"
const namespaceIdentity = "720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121"
const policyIdentity = "ef7152f60a21cf21a3aa483d9728b471db76f41b5b64ad0590613671a4537b64"
const namespaceUnsigned = `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"fixture-se3/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222"}`
const namespaceJSON = `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"identity":"720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"fixture-se3/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222"}`
const policyUnsigned = `{"contract":"open-trestle/protected-artifact-erasure-policy","schema_version":1,"namespace_identity":"720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"fixture-se3/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222","backend_kind":"aws_s3_general_purpose","database_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333","namespace_mode":"protected_new_nonnull","protocol":"same-key-fence-v2","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","erasure_policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","configuration_evidence_identity":"7777777777777777777777777777777777777777777777777777777777777777","not_before_milliseconds":1700000000000,"not_after_milliseconds":1700000060000}`
const policyJSON = `{"contract":"open-trestle/protected-artifact-erasure-policy","schema_version":1,"identity":"ef7152f60a21cf21a3aa483d9728b471db76f41b5b64ad0590613671a4537b64","namespace_identity":"720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"fixture-se3/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222","backend_kind":"aws_s3_general_purpose","database_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333","namespace_mode":"protected_new_nonnull","protocol":"same-key-fence-v2","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","erasure_policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","configuration_evidence_identity":"7777777777777777777777777777777777777777777777777777777777777777","not_before_milliseconds":1700000000000,"not_after_milliseconds":1700000060000}`

func requireClosedError(t *testing.T, err error) {
	t.Helper()
	if err != erasureauthority.ErrProtectedAuthority || !errors.Is(err, erasureauthority.ErrProtectedAuthority) {
		t.Fatal("failure did not return the fixed protected-authority error")
	}
	if err.Error() != protectedErrorText || errors.Unwrap(err) != nil {
		t.Fatal("failure exposed a cause or noncanonical error text")
	}
}

func requireInvalidPolicy(t *testing.T, p erasureauthority.Policy) {
	t.Helper()
	requireClosedError(t, p.Validate())
	for name, value := range map[string]string{
		"identity": p.Identity(), "namespace": p.NamespaceIdentity(),
		"backend configuration": p.BackendConfigurationIdentity(), "prefix": p.Prefix(),
		"epoch": p.NamespaceEpochIdentity(), "backend kind": p.BackendKind(),
		"database": p.DatabaseAuthorityIdentity(), "mode": p.NamespaceMode(),
		"protocol": p.Protocol(), "ownership": p.Ownership(),
		"fence": p.FenceRetentionPolicyIdentity(), "erasure": p.ErasurePolicyIdentity(),
		"recovery": p.RecoveryPolicyIdentity(), "evidence": p.ConfigurationEvidenceIdentity(),
	} {
		if value != "" {
			t.Fatalf("invalid policy retained %s", name)
		}
	}
	if len(p.Bytes()) != 0 || !p.NotBefore().IsZero() || !p.NotAfter().IsZero() {
		t.Fatal("invalid policy retained content or time boundaries")
	}
	for _, instant := range []time.Time{{}, time.UnixMilli(1), time.UnixMilli(1700000000000), time.UnixMilli(253402300799999)} {
		if p.AllowsAt(instant) {
			t.Fatal("unminted policy authorized an instant")
		}
	}
}

func requireInvalidDocument(t *testing.T, d erasureauthority.Document) {
	t.Helper()
	requireClosedError(t, d.Validate())
	if len(d.Bytes()) != 0 || d.Digest() != "" {
		t.Fatal("invalid document retained bytes or digest")
	}
}

func requireDenied(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	p, err := erasureauthority.LoadPolicy(ctx, path)
	requireClosedError(t, err)
	requireInvalidPolicy(t, p)
	d, err := erasureauthority.LoadDocument(ctx, path)
	requireClosedError(t, err)
	requireInvalidDocument(t, d)
}

func TestUnmintedValuesCannotAuthorize(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		requireInvalidPolicy(t, erasureauthority.Policy{})
		requireInvalidDocument(t, erasureauthority.Document{})
	})
	for name, input := range map[string]string{
		"empty object":        `{}`,
		"null":                `null`,
		"canonical policy":    policyJSON,
		"exported lookalikes": `{"Identity":"` + policyIdentity + `","Bytes":"eA==","Digest":"` + policyIdentity + `","Verified":true,"verified":true,"not_before_milliseconds":1,"not_after_milliseconds":253402300799999}`,
	} {
		t.Run(name, func(t *testing.T) {
			var p erasureauthority.Policy
			var d erasureauthority.Document
			// Rejecting JSON or ignoring inaccessible fields are both safe outcomes.
			_ = json.Unmarshal([]byte(input), &p)
			_ = json.Unmarshal([]byte(input), &d)
			requireInvalidPolicy(t, p)
			requireInvalidDocument(t, d)
		})
	}
}

func TestLoadersRejectInvalidInputs(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "private-authority.json")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, ctx := range map[string]context.Context{"nil context": nil, "pre-canceled context": canceled} {
		t.Run(name, func(t *testing.T) { requireDenied(t, ctx, path) })
	}
	sep := string(filepath.Separator)
	for name, invalid := range map[string]string{
		"empty": "", "relative": "policy.json", "relative dot": "." + sep + "policy.json",
		"nul": path + "\x00private", "overlong": sep + strings.Repeat("x", 4096),
		"unclean dot":      base + sep + "." + sep + "policy.json",
		"unclean parent":   base + sep + "child" + sep + ".." + sep + "policy.json",
		"double separator": base + sep + sep + "policy.json", "trailing separator": path + sep,
		"missing": path,
	} {
		t.Run(name, func(t *testing.T) { requireDenied(t, context.Background(), invalid) })
	}
	// This matches the Go unix build tag used by fileauthority's ownership implementation.
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
	default:
		t.Run("unsupported ownership platform refuses existing file", func(t *testing.T) {
			if err := os.WriteFile(path, []byte(policyJSON), 0600); err != nil {
				t.Fatal(err)
			}
			requireDenied(t, context.Background(), path)
		})
	}
}

func TestIndependentLiteralIdentityVectors(t *testing.T) {
	for _, vector := range []struct{ name, contract, unsigned, wire, identity string }{
		{"namespace", namespaceContract, namespaceUnsigned, namespaceJSON, namespaceIdentity},
		{"policy", policyContract, policyUnsigned, policyJSON, policyIdentity},
	} {
		t.Run(vector.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(vector.contract + "/v1\x00" + vector.unsigned))
			if hex.EncodeToString(sum[:]) != vector.identity {
				t.Fatal("literal vector disagrees with the domain-separated SHA256 recipe")
			}
			if strings.Replace(vector.wire, `"identity":"`+vector.identity+`",`, "", 1) != vector.unsigned {
				t.Fatal("literal wire differs from the fixed ordered unsigned record")
			}
			wrong := sha256.Sum256([]byte(vector.contract + `/v1\x00` + vector.unsigned))
			if fmt.Sprintf("%x", wrong) == vector.identity {
				t.Fatal("literal backslash text was confused with an actual NUL")
			}
		})
	}
}
