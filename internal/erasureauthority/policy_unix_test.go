//go:build unix

package erasureauthority_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/erasureauthority"
)

func protectedFile(t *testing.T, content []byte) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "private-authority.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadPolicy(t *testing.T, content string) erasureauthority.Policy {
	t.Helper()
	p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(content)))
	if err != nil {
		t.Fatal("protected synthetic policy did not load", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal("loaded policy failed structural validation", err)
	}
	if !bytes.Equal(p.Bytes(), []byte(content)) {
		t.Fatal("loaded policy changed canonical bytes")
	}
	return p
}

func jsonString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// Mutations get fresh identities so field rejections do not rely on a stale policy hash.
func policyVariant(t *testing.T, changes map[string]string, bindNamespace bool) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(policyUnsigned), &fields); err != nil {
		t.Fatal(err)
	}
	unsigned := policyUnsigned
	for field, value := range changes {
		old, exists := fields[field]
		if !exists {
			t.Fatalf("unknown test mutation field %s", field)
		}
		unsigned = strings.Replace(unsigned, jsonString(field)+":"+string(old), jsonString(field)+":"+value, 1)
		fields[field] = json.RawMessage(value)
	}
	if bindNamespace {
		namespace := `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"backend_configuration_identity":` + string(fields["backend_configuration_identity"]) + `,"prefix":` + string(fields["prefix"]) + `,"namespace_epoch_identity":` + string(fields["namespace_epoch_identity"]) + `}`
		sum := sha256.Sum256([]byte(namespaceContract + "/v1\x00" + namespace))
		unsigned = strings.Replace(unsigned, `"namespace_identity":`+string(fields["namespace_identity"]), `"namespace_identity":"`+hex.EncodeToString(sum[:])+`"`, 1)
	}
	sum := sha256.Sum256([]byte(policyContract + "/v1\x00" + unsigned))
	return strings.Replace(unsigned, `"schema_version":`+string(fields["schema_version"]), `"schema_version":`+string(fields["schema_version"])+`,"identity":"`+hex.EncodeToString(sum[:])+`"`, 1)
}

func TestProtectedPolicyLoadsLiteralGetters(t *testing.T) {
	p := loadPolicy(t, policyJSON)
	for name, pair := range map[string][2]string{
		"identity":               {p.Identity(), policyIdentity},
		"namespace":              {p.NamespaceIdentity(), namespaceIdentity},
		"backend configuration":  {p.BackendConfigurationIdentity(), strings.Repeat("1", 64)},
		"prefix":                 {p.Prefix(), "fixture-se3/a_0-z"},
		"namespace epoch":        {p.NamespaceEpochIdentity(), strings.Repeat("2", 64)},
		"backend kind":           {p.BackendKind(), "aws_s3_general_purpose"},
		"database authority":     {p.DatabaseAuthorityIdentity(), strings.Repeat("3", 64)},
		"namespace mode":         {p.NamespaceMode(), "protected_new_nonnull"},
		"protocol":               {p.Protocol(), "same-key-fence-v2"},
		"ownership":              {p.Ownership(), "all_versions_at_exact_key"},
		"fence retention":        {p.FenceRetentionPolicyIdentity(), strings.Repeat("4", 64)},
		"erasure policy":         {p.ErasurePolicyIdentity(), strings.Repeat("5", 64)},
		"recovery policy":        {p.RecoveryPolicyIdentity(), strings.Repeat("6", 64)},
		"configuration evidence": {p.ConfigurationEvidenceIdentity(), strings.Repeat("7", 64)},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("wrong %s getter", name)
		}
	}
	if !p.NotBefore().Equal(time.UnixMilli(1700000000000)) || !p.NotAfter().Equal(time.UnixMilli(1700000060000)) || p.NotBefore().Location() != time.UTC || p.NotAfter().Location() != time.UTC {
		t.Fatal("boundary getters lost exact UTC milliseconds")
	}
}

func TestPolicyTimeStructureAndHalfOpenInterval(t *testing.T) {
	for _, interval := range []struct {
		name          string
		before, after int64
	}{
		{"historical", 1, 2},
		{"literal", 1700000000000, 1700000060000},
		{"far future", 253402300799998, 253402300799999},
		{"no invented lifetime cap", 1, 253402300799999},
	} {
		t.Run(interval.name, func(t *testing.T) {
			p := loadPolicy(t, policyVariant(t, map[string]string{
				"not_before_milliseconds": fmt.Sprint(interval.before),
				"not_after_milliseconds":  fmt.Sprint(interval.after),
			}, true))
			before, after := time.UnixMilli(interval.before).UTC(), time.UnixMilli(interval.after).UTC()
			if p.NotBefore() != before || p.NotAfter() != after {
				t.Fatal("loaded interval changed its structural boundaries")
			}
			for _, instant := range []struct {
				name    string
				at      time.Time
				allowed bool
			}{
				{"zero", time.Time{}, false},
				{"before by nanosecond", before.Add(-time.Nanosecond), false},
				{"inclusive start", before, true},
				{"fractional millisecond", before.Add(time.Nanosecond), true},
				{"before exclusive end", after.Add(-time.Nanosecond), true},
				{"exclusive end", after, false},
				{"after end", after.Add(time.Nanosecond), false},
				{"non UTC start", before.In(time.FixedZone("fixture", 5*3600+1800)), true},
				{"non UTC fractional", before.Add(time.Nanosecond).In(time.FixedZone("fixture", -7*3600)), true},
				{"non UTC end", after.In(time.FixedZone("fixture", 3600)), false},
			} {
				t.Run(instant.name, func(t *testing.T) {
					if p.AllowsAt(instant.at) != instant.allowed {
						t.Fatal("AllowsAt did not compare the caller instant with the half-open interval")
					}
				})
			}
			if err := p.Validate(); err != nil {
				t.Fatal("time queries changed structural validity")
			}
		})
	}
	for name, change := range map[string]map[string]string{
		"zero start":          {"not_before_milliseconds": "0"},
		"negative start":      {"not_before_milliseconds": "-1"},
		"zero end":            {"not_after_milliseconds": "0"},
		"negative end":        {"not_after_milliseconds": "-1"},
		"equal":               {"not_after_milliseconds": "1700000000000"},
		"reversed":            {"not_after_milliseconds": "1699999999999"},
		"start above maximum": {"not_before_milliseconds": "253402300800000"},
		"end above maximum":   {"not_after_milliseconds": "253402300800000"},
		"fractional start":    {"not_before_milliseconds": "1700000000000.5"},
		"fractional end":      {"not_after_milliseconds": "1700000060000.5"},
		"decimal integer":     {"not_before_milliseconds": "1700000000000.0"},
		"exponent":            {"not_before_milliseconds": "17e11"},
		"string":              {"not_before_milliseconds": `"1700000000000"`},
		"overflow":            {"not_after_milliseconds": "9223372036854775808"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(policyVariant(t, change, true))))
			requireClosedError(t, err)
			requireInvalidPolicy(t, p)
		})
	}
}

func TestPolicyFieldValidationAndNamespaceBinding(t *testing.T) {
	for _, prefix := range []string{"a", "0", "-", "_", "a/b_0-z", strings.Repeat("a", 128)} {
		t.Run("valid prefix "+fmt.Sprint(len(prefix))+" "+prefix[:1], func(t *testing.T) {
			p := loadPolicy(t, policyVariant(t, map[string]string{"prefix": jsonString(prefix)}, true))
			if p.Prefix() != prefix || !p.AllowsAt(time.UnixMilli(1700000000000)) {
				t.Fatal("valid prefix did not retain policy authority")
			}
		})
	}
	for name, prefix := range map[string]string{
		"empty": "", "overlong": strings.Repeat("a", 129), "leading slash": "/a", "trailing slash": "a/",
		"double slash": "a//b", "uppercase": "A", "dot": "a.b", "dot segment": "a/../b",
		"space": "a b", "backslash": `a\b`, "non ASCII": "caf\u00e9", "nul": "a\x00b", "newline": "a\nb",
	} {
		t.Run("bad prefix "+name, func(t *testing.T) {
			p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(policyVariant(t, map[string]string{"prefix": jsonString(prefix)}, true))))
			requireClosedError(t, err)
			requireInvalidPolicy(t, p)
		})
	}
	for field, valid := range map[string]string{
		"backend_kind": "aws_s3_general_purpose", "namespace_mode": "protected_new_nonnull",
		"protocol": "same-key-fence-v2", "ownership": "all_versions_at_exact_key",
	} {
		for name, value := range map[string]string{"empty": "", "uppercase": strings.ToUpper(valid), "suffix": valid + "x", "whitespace": valid + " ", "other": "unsupported"} {
			t.Run(field+"/"+name, func(t *testing.T) {
				p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(policyVariant(t, map[string]string{field: jsonString(value)}, true))))
				requireClosedError(t, err)
				requireInvalidPolicy(t, p)
			})
		}
	}
	for _, field := range []string{"namespace_identity", "backend_configuration_identity", "namespace_epoch_identity", "database_authority_identity", "fence_retention_policy_identity", "erasure_policy_identity", "recovery_policy_identity", "configuration_evidence_identity"} {
		for name, value := range map[string]string{"empty": "", "zero": strings.Repeat("0", 64), "short": strings.Repeat("a", 63), "long": strings.Repeat("a", 65), "uppercase": strings.Repeat("A", 64), "nonhex": strings.Repeat("g", 64)} {
			t.Run(field+"/"+name, func(t *testing.T) {
				p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(policyVariant(t, map[string]string{field: jsonString(value)}, field != "namespace_identity"))))
				requireClosedError(t, err)
				requireInvalidPolicy(t, p)
			})
		}
	}
	for field, value := range map[string]string{
		"namespace_identity": strings.Repeat("a", 64), "backend_configuration_identity": strings.Repeat("b", 64),
		"namespace_epoch_identity": strings.Repeat("c", 64), "prefix": "other-prefix",
	} {
		t.Run("unbound "+field, func(t *testing.T) {
			p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(policyVariant(t, map[string]string{field: jsonString(value)}, false))))
			requireClosedError(t, err)
			requireInvalidPolicy(t, p)
		})
	}
	for _, field := range []string{"backend_configuration_identity", "namespace_epoch_identity", "database_authority_identity", "fence_retention_policy_identity", "erasure_policy_identity", "recovery_policy_identity", "configuration_evidence_identity"} {
		t.Run("valid lowercase digest "+field, func(t *testing.T) {
			loadPolicy(t, policyVariant(t, map[string]string{field: jsonString(strings.Repeat("abcdef0123456789", 4))}, true))
		})
	}
}

func TestPolicyRejectsNoncanonicalRecords(t *testing.T) {
	cases := map[string]string{
		"duplicate":          strings.Replace(policyJSON, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"escaped duplicate":  strings.Replace(policyJSON, `"schema_version":1`, `"schema_version":1,"schema_\u0076ersion":1`, 1),
		"unknown":            strings.Replace(policyJSON, `"schema_version":1`, `"schema_version":1,"private_unknown":true`, 1),
		"case alias":         strings.Replace(policyJSON, `"namespace_identity":`, `"Namespace_Identity":`, 1),
		"escaped key":        strings.Replace(policyJSON, `"namespace_identity":`, `"namespace_\u0069dentity":`, 1),
		"escaped string":     strings.Replace(policyJSON, `"fixture-se3/a_0-z"`, `"\u0066ixture-se3/a_0-z"`, 1),
		"escaped slash":      strings.Replace(policyJSON, `fixture-se3/a_0-z`, `fixture-se3\/a_0-z`, 1),
		"leading whitespace": " " + policyJSON, "trailing newline": policyJSON + "\n",
		"internal whitespace": strings.Replace(policyJSON, `,"schema_version"`, `, "schema_version"`, 1),
		"trailing object":     policyJSON + `{}`, "trailing null": policyJSON + `null`, "trailing junk": policyJSON + `x`,
		"field order":        strings.Replace(policyJSON, `"contract":"`+policyContract+`","schema_version":1`, `"schema_version":1,"contract":"`+policyContract+`"`, 1),
		"wrong identity":     strings.Replace(policyJSON, policyIdentity, strings.Repeat("a", 64), 1),
		"uppercase identity": strings.Replace(policyJSON, policyIdentity, strings.ToUpper(policyIdentity), 1),
		"zero identity":      strings.Replace(policyJSON, policyIdentity, strings.Repeat("0", 64), 1),
		"short identity":     strings.Replace(policyJSON, policyIdentity, policyIdentity[:63], 1),
		"long identity":      strings.Replace(policyJSON, policyIdentity, policyIdentity+"a", 1),
		"nonhex identity":    strings.Replace(policyJSON, policyIdentity, strings.Repeat("z", 64), 1),
		"empty identity":     strings.Replace(policyJSON, policyIdentity, "", 1),
		"wrong contract":     policyVariant(t, map[string]string{"contract": `"other-contract"`}, true),
		"wrong version":      policyVariant(t, map[string]string{"schema_version": "2"}, true),
		"string version":     policyVariant(t, map[string]string{"schema_version": `"1"`}, true),
		"decimal version":    policyVariant(t, map[string]string{"schema_version": "1.0"}, true),
		"null record":        "null", "array": "[]", "empty object": "{}", "empty file": "",
		"invalid UTF8": string([]byte{0xff}), "BOM": "\xef\xbb\xbf" + policyJSON,
		"cap nonpolicy": strings.Repeat("x", 16384), "cap plus one": strings.Repeat("x", 16385),
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(policyJSON), &fields); err != nil {
		t.Fatal(err)
	}
	for field, value := range fields {
		token := jsonString(field) + ":" + string(value)
		cases["null "+field] = strings.Replace(policyJSON, token, jsonString(field)+":null", 1)
		without := strings.Replace(policyJSON, token+",", "", 1)
		if without == policyJSON {
			without = strings.Replace(policyJSON, ","+token, "", 1)
		}
		cases["missing "+field] = without
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := erasureauthority.LoadPolicy(context.Background(), protectedFile(t, []byte(content)))
			requireClosedError(t, err)
			requireInvalidPolicy(t, p)
		})
	}
}

func TestDocumentIsBoundedRawSnapshotNotPolicyGrant(t *testing.T) {
	for _, sample := range []struct {
		name    string
		content []byte
		valid   bool
	}{
		{"empty", nil, false}, {"one byte", []byte{0xff}, true},
		{"binary and NUL", []byte{0, 0xff, '\n', 0xc0, 0x80}, true},
		{"noncanonical JSON", []byte(" {\"arbitrary\":true}\n"), true},
		{"exact cap", bytes.Repeat([]byte{0x00}, 16384), true},
		{"cap plus one", bytes.Repeat([]byte{'x'}, 16385), false},
		{"canonical policy bytes", []byte(policyJSON), true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			path := protectedFile(t, sample.content)
			d, err := erasureauthority.LoadDocument(context.Background(), path)
			if !sample.valid {
				requireClosedError(t, err)
				requireInvalidDocument(t, d)
				return
			}
			sum := sha256.Sum256(sample.content)
			if err != nil || d.Validate() != nil || !bytes.Equal(d.Bytes(), sample.content) || d.Digest() != hex.EncodeToString(sum[:]) {
				t.Fatal("raw protected document changed bytes or digest")
			}
			if sample.name != "canonical policy bytes" {
				p, policyErr := erasureauthority.LoadPolicy(context.Background(), path)
				requireClosedError(t, policyErr)
				requireInvalidPolicy(t, p)
			}
			var forged erasureauthority.Policy
			_ = json.Unmarshal(d.Bytes(), &forged)
			requireInvalidPolicy(t, forged)
		})
	}
}

func TestProtectedLoadersRejectUnsafeFilesystemAuthority(t *testing.T) {
	for _, mutation := range []string{"group writable file", "world writable file", "directory", "symlink file", "dangling symlink", "symlink ancestor", "writable parent", "writable grandparent", "missing file"} {
		t.Run(mutation, func(t *testing.T) {
			path := protectedFile(t, []byte(policyJSON))
			parent := filepath.Dir(path)
			switch mutation {
			case "group writable file", "world writable file":
				mode := os.FileMode(0620)
				if mutation == "world writable file" {
					mode = 0602
				}
				if err := os.Chmod(path, mode); err != nil {
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
				link := filepath.Join(t.TempDir(), "linked-parent")
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
			case "missing file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			requireDenied(t, context.Background(), path)
		})
	}
	t.Run("owned sticky parent preserves fileauthority semantics", func(t *testing.T) {
		path := protectedFile(t, []byte(policyJSON))
		if err := os.Chmod(filepath.Dir(path), 0777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		p, err := erasureauthority.LoadPolicy(context.Background(), path)
		if err != nil || p.Validate() != nil || p.Identity() != policyIdentity {
			t.Fatal("owned sticky parent refused")
		}
		d, err := erasureauthority.LoadDocument(context.Background(), path)
		if err != nil || d.Validate() != nil || !bytes.Equal(d.Bytes(), []byte(policyJSON)) {
			t.Fatal("owned sticky document refused")
		}
	})
	for name, mode := range map[string]os.FileMode{"owner writable": 0600, "owner read only": 0400, "world readable not writable": 0644} {
		t.Run(name, func(t *testing.T) {
			path := protectedFile(t, []byte(policyJSON))
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			p, err := erasureauthority.LoadPolicy(context.Background(), path)
			if err != nil || p.Validate() != nil || p.Identity() != policyIdentity {
				t.Fatal("protected permission mode refused")
			}
			d, err := erasureauthority.LoadDocument(context.Background(), path)
			if err != nil || d.Validate() != nil || !bytes.Equal(d.Bytes(), []byte(policyJSON)) {
				t.Fatal("protected document permission mode refused")
			}
		})
	}
	t.Run("canceled contexts with existing authority", func(t *testing.T) {
		path := protectedFile(t, []byte(policyJSON))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		requireDenied(t, nil, path)
		requireDenied(t, ctx, path)
	})
	t.Run("unclean aliases of existing authority", func(t *testing.T) {
		path := protectedFile(t, []byte(policyJSON))
		parent := filepath.Dir(path)
		child := filepath.Join(parent, "child")
		if err := os.Mkdir(child, 0700); err != nil {
			t.Fatal(err)
		}
		for _, alias := range []string{parent + "/./" + filepath.Base(path), child + "/../" + filepath.Base(path), parent + "//" + filepath.Base(path)} {
			requireDenied(t, context.Background(), alias)
		}
	})
}

func TestLoadedSnapshotsAreImmutableAndFormattingIsRedacted(t *testing.T) {
	path := protectedFile(t, []byte(policyJSON))
	p, err := erasureauthority.LoadPolicy(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := erasureauthority.LoadDocument(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	policyCopy, documentCopy := p, d
	policyBytes, documentBytes := p.Bytes(), d.Bytes()
	if len(policyBytes) == 0 || len(documentBytes) == 0 {
		t.Fatal("loaded snapshot is empty")
	}
	policyBytes[0], documentBytes[0] = 'x', 'y'
	if !bytes.Equal(p.Bytes(), []byte(policyJSON)) || !bytes.Equal(d.Bytes(), []byte(policyJSON)) || !bytes.Equal(policyCopy.Bytes(), []byte(policyJSON)) || !bytes.Equal(documentCopy.Bytes(), []byte(policyJSON)) {
		t.Fatal("byte getters exposed mutable authority storage")
	}
	// Sequential replacement proves snapshot semantics, not a race barrier during loading.
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, []byte("replacement-private-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if policyCopy.Validate() != nil || documentCopy.Validate() != nil || policyCopy.Identity() != policyIdentity || !policyCopy.AllowsAt(time.UnixMilli(1700000000000)) || !bytes.Equal(documentCopy.Bytes(), []byte(policyJSON)) {
		t.Fatal("replacement invalidated the previously minted immutable snapshot")
	}
	newDocument, err := erasureauthority.LoadDocument(context.Background(), path)
	if err != nil || !bytes.Equal(newDocument.Bytes(), []byte("replacement-private-marker")) {
		t.Fatal("new load did not capture replacement")
	}
	newPolicy, err := erasureauthority.LoadPolicy(context.Background(), path)
	requireClosedError(t, err)
	requireInvalidPolicy(t, newPolicy)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if p.Validate() != nil || d.Validate() != nil || !bytes.Equal(p.Bytes(), []byte(policyJSON)) || !bytes.Equal(d.Bytes(), []byte(policyJSON)) {
		t.Fatal("removed path changed snapshot")
	}
	formatValue := func(format string, value any) string { return fmt.Sprintf(format, value) }
	for name, rendered := range map[string]string{
		"policy integer":             formatValue("%d", p),
		"policy boolean":             formatValue("%t", p),
		"policy character":           formatValue("%c", p),
		"policy float":               formatValue("%f", p),
		"policy pointer integer":     formatValue("%d", &p),
		"raw document integer":       formatValue("%d", newDocument),
		"raw document boolean":       formatValue("%t", newDocument),
		"raw document pointer float": formatValue("%f", &newDocument),
		"policy String":              p.String(), "policy GoString": p.GoString(), "policy percent v": fmt.Sprintf("%v", p),
		"policy plus v": fmt.Sprintf("%+v", p), "policy sharp v": fmt.Sprintf("%#v", p),
		"document String": d.String(), "document GoString": d.GoString(), "document percent v": fmt.Sprintf("%v", d),
		"document plus v": fmt.Sprintf("%+v", d), "document sharp v": fmt.Sprintf("%#v", d),
		"raw document String": newDocument.String(), "raw document GoString": newDocument.GoString(),
		"raw document sharp v": fmt.Sprintf("%#v", newDocument),
	} {
		t.Run(name, func(t *testing.T) {
			for _, private := range []string{path, policyJSON, "fixture-se3/a_0-z", "replacement-private-marker", fmt.Sprint([]byte("replacement-private-marker")), fmt.Sprintf("%#v", []byte("replacement-private-marker"))} {
				if strings.Contains(rendered, private) {
					t.Fatal("formatting disclosed protected content or path")
				}
			}
		})
	}
}
