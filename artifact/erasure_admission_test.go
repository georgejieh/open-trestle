package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

// These are metadata SHAPE tests. No value below is a journal acceptance,
// dispatch permit, protected authority, custody statement, or erasure proof.
const avNamespaceContract = "open-trestle/artifact-storage-namespace"
const avAdmissionContract = "open-trestle/artifact-admission"
const avBackend = "1111111111111111111111111111111111111111111111111111111111111111"
const avEpoch = "2222222222222222222222222222222222222222222222222222222222222222"
const avOther = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const avPrefix = "fixture-se3/a_0-z"
const avNamespaceIdentity = "720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121"
const avScopeIdentity = "4e312004e9f66d49d7588b1dfa09ae3ce15bab29f02ad302aa0ec1e21d7dd39e"
const avArtifactIdentity = "a56b573345b57d1ff8dce1c5cfb9df629ff44750b820ee4ffff1809318a3c450"
const avAdmissionIdentity = "67bc36ff5ccacc7919c80d8321f2710c210be304fbf1504d652272bb86ef2834"
const avPayloadDigest = "16563eafaeeeaaee8cf12c0eb67c8362a72c9f4f6083da3717113bab642eac25"
const avNamespaceUnsigned = `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"fixture-se3/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222"}`
const avNamespaceJSON = `{"contract":"open-trestle/artifact-storage-namespace","schema_version":1,"identity":"720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"fixture-se3/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222"}`
const avScopePreimage = `{"contract":"open-trestle/audit-review-scope","version":1,"tenant":"tenant-h0","repository":"repo-h0","review_run":"run-remote-h0"}`
const avArtifactPreimage = `{"scope_identity":"4e312004e9f66d49d7588b1dfa09ae3ce15bab29f02ad302aa0ec1e21d7dd39e","kind":"context_packet","media_type":"application/json","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"16563eafaeeeaaee8cf12c0eb67c8362a72c9f4f6083da3717113bab642eac25","created_at_milliseconds":100,"expires_at_milliseconds":1000}`
const avAdmissionUnsigned = `{"contract":"open-trestle/artifact-admission","schema_version":1,"namespace_identity":"720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121","scope_identity":"4e312004e9f66d49d7588b1dfa09ae3ce15bab29f02ad302aa0ec1e21d7dd39e","tenant_id":"tenant-h0","repository_id":"repo-h0","review_run_id":"run-remote-h0","artifact_identity":"a56b573345b57d1ff8dce1c5cfb9df629ff44750b820ee4ffff1809318a3c450","kind":"context_packet","media_type":"application/json","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"16563eafaeeeaaee8cf12c0eb67c8362a72c9f4f6083da3717113bab642eac25","created_at_milliseconds":100,"expires_at_milliseconds":1000,"admitted_at_milliseconds":500}`
const avAdmissionJSON = `{"contract":"open-trestle/artifact-admission","schema_version":1,"identity":"67bc36ff5ccacc7919c80d8321f2710c210be304fbf1504d652272bb86ef2834","namespace_identity":"720e7507a2e02e8c09cdbc4fe1469291403c467f375271853acc3982aa719121","scope_identity":"4e312004e9f66d49d7588b1dfa09ae3ce15bab29f02ad302aa0ec1e21d7dd39e","tenant_id":"tenant-h0","repository_id":"repo-h0","review_run_id":"run-remote-h0","artifact_identity":"a56b573345b57d1ff8dce1c5cfb9df629ff44750b820ee4ffff1809318a3c450","kind":"context_packet","media_type":"application/json","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"16563eafaeeeaaee8cf12c0eb67c8362a72c9f4f6083da3717113bab642eac25","created_at_milliseconds":100,"expires_at_milliseconds":1000,"admitted_at_milliseconds":500}`
const avHistoricalArtifactJSON = `{"contract":"open-trestle/runtime-artifact","schema_version":1,"identity":"a56b573345b57d1ff8dce1c5cfb9df629ff44750b820ee4ffff1809318a3c450","tenant_id":"tenant-h0","repository_id":"repo-h0","review_run_id":"run-remote-h0","kind":"context_packet","media_type":"application/json","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"16563eafaeeeaaee8cf12c0eb67c8362a72c9f4f6083da3717113bab642eac25","payload":"eyJwdWJsaWMiOiJzZTMtaDAtc3ludGhldGljLWhpc3RvcnkifQ==","created_at_milliseconds":100,"expires_at_milliseconds":1000}`

var avNamespaceOrder = strings.Fields("contract schema_version identity backend_configuration_identity prefix namespace_epoch_identity")
var avAdmissionOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity tenant_id repository_id review_run_id artifact_identity kind media_type classification origin protection provenance payload_digest created_at_milliseconds expires_at_milliseconds admitted_at_milliseconds")
var avOriginalOrder = strings.Fields("scope_identity kind media_type classification origin protection provenance payload_digest created_at_milliseconds expires_at_milliseconds")

func avHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func avFields(t *testing.T, wire string) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(wire), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

// Independent ordered JSON recipe, not either production encoder.
func avOrdered(t *testing.T, fields map[string]any, order []string, unsigned bool) string {
	t.Helper()
	var members []string
	for _, key := range order {
		if unsigned && key == "identity" {
			continue
		}
		value, err := json.Marshal(fields[key])
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, `"`+key+`":`+string(value))
	}
	return "{" + strings.Join(members, ",") + "}"
}

func avRehash(t *testing.T, fields map[string]any, order []string) string {
	t.Helper()
	fields["identity"] = avHash(fields["contract"].(string) + "/v1\x00" + avOrdered(t, fields, order, true))
	return avOrdered(t, fields, order, false)
}

func avRebindOriginal(t *testing.T, fields map[string]any) {
	t.Helper()
	fields["artifact_identity"] = avHash(avOrdered(t, fields, avOriginalOrder, false))
}

func avRebindScope(t *testing.T, fields map[string]any) {
	t.Helper()
	scope := map[string]any{"contract": "open-trestle/audit-review-scope", "version": 1,
		"tenant": fields["tenant_id"], "repository": fields["repository_id"], "review_run": fields["review_run_id"]}
	fields["scope_identity"] = avHash(avOrdered(t, scope, strings.Fields("contract version tenant repository review_run"), false))
}

func avError(t *testing.T, got, want error) {
	t.Helper()
	if got != want || !errors.Is(got, want) {
		t.Fatal("wrong closed error classification")
	}
	text := ""
	switch want {
	case artifact.ErrInvalidErasureContract:
		text = "invalid erasure contract"
	case artifact.ErrErasureIdentityMismatch:
		text = "erasure identity mismatch"
	case artifact.ErrInvalidArtifact:
		text = "invalid runtime artifact"
	default:
		t.Fatal("unexpected test error oracle")
	}
	if got.Error() != text || errors.Unwrap(got) != nil {
		t.Fatal("error leaked a cause or noncanonical text")
	}
}

func avNamespace(t *testing.T) artifact.StorageNamespace {
	t.Helper()
	value, err := artifact.NewStorageNamespace(avBackend, avPrefix, avEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func avHistoricalArtifact(t *testing.T) artifact.Artifact {
	t.Helper()
	// Exact readable, synthetic H0 fixture. Only this old codec creates an Artifact.
	value, err := artifact.Parse([]byte(avHistoricalArtifactJSON))
	if err != nil || value.Validate() != nil {
		t.Fatal("historical actual Artifact is invalid")
	}
	return value
}

func avAdmission(t *testing.T) artifact.ArtifactAdmission {
	t.Helper()
	value, err := artifact.NewArtifactAdmission(avHistoricalArtifact(t), avNamespaceIdentity, time.UnixMilli(500).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func avZeroNamespace(t *testing.T, value artifact.StorageNamespace) {
	t.Helper()
	avError(t, value.Validate(), artifact.ErrInvalidErasureContract)
	if value.Identity() != "" || value.BackendConfigurationIdentity() != "" || value.Prefix() != "" || value.NamespaceEpochIdentity() != "" {
		t.Fatal("invalid namespace retained metadata")
	}
}

func avZeroAdmission(t *testing.T, value artifact.ArtifactAdmission) {
	t.Helper()
	avError(t, value.Validate(), artifact.ErrInvalidErasureContract)
	scope := value.Scope()
	if value.Identity() != "" || value.NamespaceIdentity() != "" || value.ArtifactIdentity() != "" || value.MediaType() != "" || value.PayloadDigest() != "" ||
		value.Kind() != 0 || value.Classification() != 0 || value.Origin() != 0 || value.Protection() != 0 || len(value.Provenance()) != 0 ||
		scope.Identity() != "" || scope.TenantID() != "" || scope.RepositoryID() != "" || scope.ReviewRunID() != "" || scope.Validate() == nil ||
		!value.CreatedAt().IsZero() || !value.ExpiresAt().IsZero() || !value.AdmittedAt().IsZero() {
		t.Fatal("invalid admission retained metadata")
	}
}

func avDenyAdmission(t *testing.T, wire string, want error) {
	t.Helper()
	value, err := artifact.ParseArtifactAdmission([]byte(wire))
	avError(t, err, want)
	avZeroAdmission(t, value)
}

func avDenyNamespace(t *testing.T, wire string, want error) {
	t.Helper()
	value, err := artifact.ParseStorageNamespace([]byte(wire))
	avError(t, err, want)
	avZeroNamespace(t, value)
}

func avAdmissionMatches(t *testing.T, got artifact.ArtifactAdmission, original artifact.Artifact, at time.Time) {
	t.Helper()
	if got.Validate() != nil || got.NamespaceIdentity() != avNamespaceIdentity || got.ArtifactIdentity() != original.Identity() ||
		got.Scope() != original.Scope() || got.Kind() != original.Kind() || got.MediaType() != original.MediaType() ||
		got.Classification() != original.Classification() || got.Origin() != original.Origin() || got.Protection() != original.Protection() ||
		!reflect.DeepEqual(got.Provenance(), original.Provenance()) || got.PayloadDigest() != original.PayloadDigest() ||
		!got.CreatedAt().Equal(original.CreatedAt()) || !got.ExpiresAt().Equal(original.ExpiresAt()) || !got.AdmittedAt().Equal(at) {
		t.Fatal("admission did not preserve actual artifact metadata")
	}
	for _, stamp := range []time.Time{got.CreatedAt(), got.ExpiresAt(), got.AdmittedAt()} {
		if stamp.Location() != time.UTC || stamp.Nanosecond()%int(time.Millisecond) != 0 {
			t.Fatal("getter is not UTC exact milliseconds")
		}
	}
}

func TestAdmissionValuesLiteralVectors(t *testing.T) {
	for _, vector := range []struct{ name, contract, unsigned, wire, identity string }{
		{"namespace", avNamespaceContract, avNamespaceUnsigned, avNamespaceJSON, avNamespaceIdentity},
		{"admission", avAdmissionContract, avAdmissionUnsigned, avAdmissionJSON, avAdmissionIdentity},
	} {
		t.Run(vector.name, func(t *testing.T) {
			if avHash(vector.contract+"/v1\x00"+vector.unsigned) != vector.identity ||
				strings.Replace(vector.wire, `"identity":"`+vector.identity+`",`, "", 1) != vector.unsigned {
				t.Fatal("independent canonical identity vector differs")
			}
			if avHash(vector.unsigned) == vector.identity || avHash(vector.contract+`/v1\x00`+vector.unsigned) == vector.identity {
				t.Fatal("missing domain or printable NUL was accepted as the hash recipe")
			}
		})
	}
	for _, vector := range []struct {
		contract, unsigned, wire string
		order                    []string
		deny                     func(*testing.T, string, error)
	}{
		{avNamespaceContract, avNamespaceUnsigned, avNamespaceJSON, avNamespaceOrder, avDenyNamespace},
		{avAdmissionContract, avAdmissionUnsigned, avAdmissionJSON, avAdmissionOrder, avDenyAdmission},
	} {
		for _, preimage := range []string{vector.unsigned, vector.contract + `/v1\x00` + vector.unsigned, vector.contract + "/v2\x00" + vector.unsigned} {
			fields := avFields(t, vector.wire)
			fields["identity"] = avHash(preimage)
			vector.deny(t, avOrdered(t, fields, vector.order, false), artifact.ErrErasureIdentityMismatch)
		}
	}
	if avHash(avScopePreimage) != avScopeIdentity || avHash(avArtifactPreimage) != avArtifactIdentity {
		t.Fatal("literal historical v1 hash changed")
	}
	if avHash(`{"public":"se3-h0-synthetic-history"}`) != avPayloadDigest {
		t.Fatal("literal synthetic payload digest differs")
	}
}

func TestStorageNamespaceShape(t *testing.T) {
	for _, value := range []artifact.StorageNamespace{avNamespace(t), func() artifact.StorageNamespace {
		parsed, err := artifact.ParseStorageNamespace([]byte(avNamespaceJSON))
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}()} {
		if value.Validate() != nil || value.Identity() != avNamespaceIdentity || value.BackendConfigurationIdentity() != avBackend || value.Prefix() != avPrefix || value.NamespaceEpochIdentity() != avEpoch {
			t.Fatal("protected-loader namespace vector/getters differ")
		}
		encoded, err := artifact.EncodeStorageNamespace(value)
		if err != nil || string(encoded) != avNamespaceJSON {
			t.Fatal("namespace encoding differs from literal")
		}
	}
	for field, replacement := range map[string]string{"backend_configuration_identity": avOther, "prefix": "different/prefix", "namespace_epoch_identity": avOther} {
		t.Run(field, func(t *testing.T) {
			fields := avFields(t, avNamespaceJSON)
			fields[field] = replacement
			avDenyNamespace(t, avOrdered(t, fields, avNamespaceOrder, false), artifact.ErrErasureIdentityMismatch)
			wire := avRehash(t, fields, avNamespaceOrder)
			value, err := artifact.NewStorageNamespace(fields["backend_configuration_identity"].(string), fields["prefix"].(string), fields["namespace_epoch_identity"].(string))
			if err != nil || value.Identity() == avNamespaceIdentity {
				t.Fatal("namespace field not bound")
			}
			encoded, err := artifact.EncodeStorageNamespace(value)
			if err != nil || string(encoded) != wire {
				t.Fatal("namespace constructor hash differs")
			}
			parsed, err := artifact.ParseStorageNamespace([]byte(wire))
			if err != nil || parsed.Identity() != value.Identity() {
				t.Fatal("valid changed namespace shape rejected")
			}
		})
	}
}

func TestStorageNamespaceRejectsMalformed(t *testing.T) {
	badDigests := []string{"", "a", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("0", 64), strings.Repeat("g", 64), " " + avBackend, avBackend + "\n"}
	for _, field := range []string{"backend_configuration_identity", "namespace_epoch_identity", "identity"} {
		for index, bad := range badDigests {
			t.Run(fmt.Sprintf("%s/%d", field, index), func(t *testing.T) {
				fields := avFields(t, avNamespaceJSON)
				fields[field] = bad
				wire := avOrdered(t, fields, avNamespaceOrder, false)
				if field != "identity" {
					wire = avRehash(t, fields, avNamespaceOrder)
					value, err := artifact.NewStorageNamespace(fields["backend_configuration_identity"].(string), avPrefix, fields["namespace_epoch_identity"].(string))
					avError(t, err, artifact.ErrInvalidErasureContract)
					avZeroNamespace(t, value)
				}
				avDenyNamespace(t, wire, artifact.ErrInvalidErasureContract)
			})
		}
	}
	for index, prefix := range []string{"", "/a", "a/", "a//b", "a/../b", "a.b", "a:b", "A", " a", "a ", "a\\b", "a\x00b", "a\nb", "é", string([]byte{0xff}), strings.Repeat("a", 129)} {
		t.Run(fmt.Sprintf("prefix/%d", index), func(t *testing.T) {
			value, err := artifact.NewStorageNamespace(avBackend, prefix, avEpoch)
			avError(t, err, artifact.ErrInvalidErasureContract)
			avZeroNamespace(t, value)
			fields := avFields(t, avNamespaceJSON)
			fields["prefix"] = prefix
			avDenyNamespace(t, avRehash(t, fields, avNamespaceOrder), artifact.ErrInvalidErasureContract)
		})
	}
	for _, prefix := range []string{"a", "0", "-", "_", "-/_", "a-b_c/0", strings.Repeat("a", 128)} {
		value, err := artifact.NewStorageNamespace(avBackend, prefix, avEpoch)
		if err != nil || value.Validate() != nil {
			t.Fatal("valid prefix rejected")
		}
	}
	fields := avFields(t, avNamespaceJSON)
	fields["identity"] = avOther
	avDenyNamespace(t, avOrdered(t, fields, avNamespaceOrder, false), artifact.ErrErasureIdentityMismatch)
}

func TestArtifactAdmissionLiteralShape(t *testing.T) {
	original := avHistoricalArtifact(t)
	legacy, err := artifact.Encode(original)
	if err != nil || string(legacy) != avHistoricalArtifactJSON {
		t.Fatal("old v1 codec changed")
	}
	parsed, err := artifact.ParseArtifactAdmission([]byte(avAdmissionJSON))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []artifact.ArtifactAdmission{avAdmission(t), parsed} {
		avAdmissionMatches(t, value, original, time.UnixMilli(500).UTC())
		if value.Identity() != avAdmissionIdentity {
			t.Fatal("literal admission identity differs")
		}
		encoded, err := artifact.EncodeArtifactAdmission(value)
		if err != nil || string(encoded) != avAdmissionJSON {
			t.Fatal("literal admission bytes differ")
		}
		fields := avFields(t, string(encoded))
		if avOrdered(t, fields, avOriginalOrder, false) != avArtifactPreimage || avHash(avOrdered(t, fields, avOriginalOrder, false)) != value.ArtifactIdentity() {
			t.Fatal("admission cannot reproduce original undomained metadata identity")
		}
		// Historical validity is a persisted relationship, not a wall-clock lease.
		if value.Validate() != nil {
			t.Fatal("historical shape sampled current time")
		}
	}
}

func TestArtifactAdmissionAllValidMetadata(t *testing.T) {
	original := avHistoricalArtifact(t)
	kinds := []artifact.Kind{artifact.KindSourceSnapshot, artifact.KindChangeModel, artifact.KindDeterministicEvidence, artifact.KindRetrievalResult, artifact.KindContextPacket, artifact.KindCandidateBatch, artifact.KindVerificationBatch, artifact.KindVerifiedFindingSet, artifact.KindPublicationPlan, artifact.KindRunExport, artifact.KindTaskInput, artifact.KindWebhookDelivery, artifact.KindSourceFile, artifact.KindPublicationReceipt, artifact.KindInvestigationTurn, artifact.KindInvestigationToolResult}
	classes := []artifact.Classification{artifact.ClassificationPublic, artifact.ClassificationInternal, artifact.ClassificationConfidential, artifact.ClassificationRestricted}
	origins := []artifact.Origin{artifact.OriginHost, artifact.OriginRepository, artifact.OriginDeterministicTool, artifact.OriginModel, artifact.OriginIndependentVerifier, artifact.OriginPolicy, artifact.OriginMemory}
	for _, kind := range kinds {
		for _, class := range classes {
			for _, origin := range origins {
				for _, protection := range []artifact.Protection{artifact.ProtectionProcessPrivate, artifact.ProtectionEnvelopeEncrypted} {
					t.Run(kind.String()+"/"+class.String()+"/"+origin.String()+"/"+protection.String(), func(t *testing.T) {
						actual, err := artifact.New(original.Scope(), kind, "text/plain", class, origin, protection, original.Provenance(), []byte("synthetic shape"), original.CreatedAt(), original.ExpiresAt())
						if err != nil {
							t.Fatal("actual Artifact fixture rejected")
						}
						value, err := artifact.NewArtifactAdmission(actual, avNamespaceIdentity, time.UnixMilli(500).UTC())
						if err != nil {
							t.Fatal("otherwise valid metadata rejected by shape constructor")
						}
						avAdmissionMatches(t, value, actual, time.UnixMilli(500).UTC())
						encoded, err := artifact.EncodeArtifactAdmission(value)
						if err != nil {
							t.Fatal(err)
						}
						parsed, err := artifact.ParseArtifactAdmission(encoded)
						if err != nil || parsed.Identity() != value.Identity() {
							t.Fatal("valid metadata parse failed")
						}
						avAdmissionMatches(t, parsed, actual, time.UnixMilli(500).UTC())
						// Process-private protection is valid SHAPE, not remote permission.
					})
				}
			}
		}
	}
	var provenance []string
	for index := 1; index <= 32; index++ {
		provenance = append(provenance, fmt.Sprintf("%064x", index))
	}
	scope, err := audit.NewReviewScope(strings.Repeat("a", 128), "r._:-0", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []struct {
		name, media          string
		created, expires, at int64
	}{
		{"maximum metadata and retention", "application/" + strings.Repeat("x", 116), 1, 315360000001, 1},
		{"maximum timestamp", "application/json", 253402300799997, 253402300799999, 253402300799998},
		{"minimum interval", "text/plain", 1, 2, 1},
		{"HTML escaped valid media", "application/x&y", 100, 1000, 500},
	} {
		t.Run(limits.name, func(t *testing.T) {
			actual, err := artifact.New(scope, artifact.KindSourceFile, limits.media, artifact.ClassificationPublic, artifact.OriginRepository, artifact.ProtectionProcessPrivate, provenance, []byte("bounded"), time.UnixMilli(limits.created).UTC(), time.UnixMilli(limits.expires).UTC())
			if err != nil {
				t.Fatal("valid boundary Artifact rejected")
			}
			value, err := artifact.NewArtifactAdmission(actual, avNamespaceIdentity, time.UnixMilli(limits.at).UTC())
			if err != nil {
				t.Fatal("valid admission boundary rejected")
			}
			avAdmissionMatches(t, value, actual, time.UnixMilli(limits.at).UTC())
			wire, err := artifact.EncodeArtifactAdmission(value)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := artifact.ParseArtifactAdmission(wire)
			if err != nil {
				t.Fatal(err)
			}
			avAdmissionMatches(t, parsed, actual, time.UnixMilli(limits.at).UTC())
		})
	}
}

func TestArtifactAdmissionRejectsConstructorInputs(t *testing.T) {
	actual := avHistoricalArtifact(t)
	invalid, err := artifact.New(actual.Scope(), actual.Kind(), actual.MediaType(), actual.Classification(), actual.Origin(), actual.Protection(), actual.Provenance(), nil, actual.CreatedAt(), actual.ExpiresAt())
	avError(t, err, artifact.ErrInvalidArtifact)
	for _, value := range []artifact.Artifact{{}, invalid} {
		for _, namespace := range []string{avNamespaceIdentity, "bad namespace"} {
			got, err := artifact.NewArtifactAdmission(value, namespace, time.Time{})
			avError(t, err, artifact.ErrInvalidArtifact) // Actual Artifact validation has priority.
			avZeroAdmission(t, got)
		}
	}
	for index, namespace := range []string{"", "a", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("z", 64), avNamespaceIdentity + "\n"} {
		t.Run(fmt.Sprintf("namespace/%d", index), func(t *testing.T) {
			got, err := artifact.NewArtifactAdmission(actual, namespace, time.UnixMilli(500).UTC())
			avError(t, err, artifact.ErrInvalidErasureContract)
			avZeroAdmission(t, got)
		})
	}
	for name, at := range map[string]time.Time{
		"zero": {}, "negative": time.UnixMilli(-1).UTC(), "epoch": time.UnixMilli(0).UTC(),
		"before creation": time.UnixMilli(99).UTC(), "at expiry": time.UnixMilli(1000).UTC(), "after expiry": time.UnixMilli(1001).UTC(),
		"sub millisecond": time.UnixMilli(500).UTC().Add(time.Nanosecond), "above maximum": time.UnixMilli(253402300800000).UTC(),
		"positive offset": time.UnixMilli(500).In(time.FixedZone("east", 3600)), "negative offset": time.UnixMilli(500).In(time.FixedZone("west", -3600)),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := artifact.NewArtifactAdmission(actual, avNamespaceIdentity, at)
			avError(t, err, artifact.ErrInvalidErasureContract)
			avZeroAdmission(t, got)
		})
	}
	otherNamespace, err := artifact.NewArtifactAdmission(actual, avOther, time.UnixMilli(500).UTC())
	if err != nil || otherNamespace.NamespaceIdentity() != avOther || otherNamespace.Validate() != nil {
		t.Fatal("shape constructor required external namespace authority")
	}
	for _, at := range []time.Time{time.UnixMilli(100).UTC(), time.UnixMilli(999).UTC(), time.UnixMilli(500).In(time.FixedZone("alias", 0))} {
		got, err := artifact.NewArtifactAdmission(actual, avNamespaceIdentity, at)
		if err != nil {
			t.Fatal("valid exact UTC-offset boundary rejected")
		}
		avAdmissionMatches(t, got, actual, at)
	}
}

func TestArtifactAdmissionOriginalV1Bindings(t *testing.T) {
	for field, replacement := range map[string]any{
		"kind": "source_file", "media_type": "text/plain", "classification": "public", "origin": "repository", "protection": "process_private",
		"provenance": []string{avOther}, "payload_digest": avOther, "created_at_milliseconds": 99, "expires_at_milliseconds": 1001,
		"tenant_id": "tenant-other", "repository_id": "repo-other", "review_run_id": "run-other",
	} {
		t.Run(field, func(t *testing.T) {
			fields := avFields(t, avAdmissionJSON)
			fields[field] = replacement
			if field == "tenant_id" || field == "repository_id" || field == "review_run_id" {
				// First isolate scope binding; then repair scope but leave old artifact identity.
				avDenyAdmission(t, avRehash(t, fields, avAdmissionOrder), artifact.ErrErasureIdentityMismatch)
				avRebindScope(t, fields)
			}
			// Outer identity is fresh: this denial must bind original v1 metadata.
			avDenyAdmission(t, avRehash(t, fields, avAdmissionOrder), artifact.ErrErasureIdentityMismatch)
			avRebindOriginal(t, fields)
			wire := avRehash(t, fields, avAdmissionOrder)
			parsed, err := artifact.ParseArtifactAdmission([]byte(wire))
			if err != nil || parsed.Validate() != nil || parsed.ArtifactIdentity() == avArtifactIdentity || parsed.Identity() == avAdmissionIdentity {
				t.Fatal("fully rebound valid shape rejected")
			}
			encoded, err := artifact.EncodeArtifactAdmission(parsed)
			if err != nil || string(encoded) != wire {
				t.Fatal("rebound shape encoding differs")
			}
			// No Artifact or payload is created to verify parsed metadata.
		})
	}
	for _, field := range []string{"scope_identity", "artifact_identity", "identity"} {
		t.Run(field, func(t *testing.T) {
			fields := avFields(t, avAdmissionJSON)
			fields[field] = avOther
			wire := avOrdered(t, fields, avAdmissionOrder, false)
			if field != "identity" {
				wire = avRehash(t, fields, avAdmissionOrder)
			}
			avDenyAdmission(t, wire, artifact.ErrErasureIdentityMismatch)
		})
	}
	for field, replacement := range map[string]any{"namespace_identity": avOther, "admitted_at_milliseconds": 501} {
		t.Run(field, func(t *testing.T) {
			fields := avFields(t, avAdmissionJSON)
			fields[field] = replacement
			avDenyAdmission(t, avOrdered(t, fields, avAdmissionOrder, false), artifact.ErrErasureIdentityMismatch)
			wire := avRehash(t, fields, avAdmissionOrder)
			parsed, err := artifact.ParseArtifactAdmission([]byte(wire))
			if err != nil || parsed.Identity() == avAdmissionIdentity || parsed.ArtifactIdentity() != avArtifactIdentity {
				t.Fatal("admission-only field binding differs")
			}
			if field == "namespace_identity" && parsed.NamespaceIdentity() != avOther {
				t.Fatal("namespace not preserved")
			}
			if field == "admitted_at_milliseconds" && parsed.AdmittedAt().UnixMilli() != 501 {
				t.Fatal("admitted time not preserved")
			}
			// An arbitrary well-shaped namespace digest needs no journal lookup here.
		})
	}
}

func TestArtifactAdmissionRejectsMalformedMetadata(t *testing.T) {
	var tooMany []string
	for index := 1; index <= 33; index++ {
		tooMany = append(tooMany, fmt.Sprintf("%064x", index))
	}
	cases := map[string][]any{
		"media_type": {"", "Text/Plain", "text/plain; charset=utf-8", "text", " text/plain", "text/plain ", "application/" + strings.Repeat("x", 117), "text/é", string([]byte{0xff})},
		"kind":       {"", "unknown", "CONTEXT_PACKET", 5}, "classification": {"", "secret", "Restricted", 4},
		"origin": {"", "remote", "Host", 1}, "protection": {"", "unencrypted", "Envelope_Encrypted", 2},
		"provenance":               {nil, []string{}, []string{avOther, avOther}, []string{avOther, avBackend}, tooMany, []string{""}, []string{strings.Repeat("0", 64)}, []string{strings.Repeat("A", 64)}, "not an array"},
		"payload_digest":           {"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64)},
		"created_at_milliseconds":  {0, -1, 500.5, 1000, 253402300800000, "100"},
		"expires_at_milliseconds":  {0, -1, 100, 499, 1000.5, 253402300800000, 315360000101, "1000"},
		"admitted_at_milliseconds": {0, -1, 99, 1000, 1001, 500.5, 253402300800000, "500"},
	}
	for _, field := range []string{"tenant_id", "repository_id", "review_run_id"} {
		cases[field] = []any{"", "Upper", "a/b", ".a", "a-", "a b", "é", strings.Repeat("a", 129)}
	}
	for _, field := range []string{"namespace_identity", "scope_identity", "artifact_identity", "identity"} {
		cases[field] = []any{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64)}
	}
	for field, values := range cases {
		for index, bad := range values {
			t.Run(fmt.Sprintf("%s/%d", field, index), func(t *testing.T) {
				fields := avFields(t, avAdmissionJSON)
				fields[field] = bad
				if field == "tenant_id" || field == "repository_id" || field == "review_run_id" {
					avRebindScope(t, fields)
				}
				if field != "artifact_identity" {
					avRebindOriginal(t, fields)
				}
				wire := avOrdered(t, fields, avAdmissionOrder, false)
				if field != "identity" {
					wire = avRehash(t, fields, avAdmissionOrder)
				}
				// All possible enclosing hashes are repaired, even for malformed metadata.
				avDenyAdmission(t, wire, artifact.ErrInvalidErasureContract)
			})
		}
	}
}

func TestAdmissionValuesStrictCanonicalBytes(t *testing.T) {
	for _, codec := range []struct {
		name, wire string
		order      []string
		limit      int
		deny       func(*testing.T, string, error)
	}{
		{"namespace", avNamespaceJSON, avNamespaceOrder, 4096, avDenyNamespace},
		{"admission", avAdmissionJSON, avAdmissionOrder, 16384, avDenyAdmission},
	} {
		t.Run(codec.name, func(t *testing.T) {
			bad := map[string]string{
				"empty": "", "null root": "null", "empty object": "{}", "array": "[]", "truncated": codec.wire[:len(codec.wire)-1],
				"leading whitespace": " " + codec.wire, "trailing newline": codec.wire + "\n", "interior whitespace": strings.Replace(codec.wire, `,"schema_version"`, `, "schema_version"`, 1),
				"trailing value": codec.wire + "{}", "trailing garbage": codec.wire + "x", "BOM": "\xef\xbb\xbf" + codec.wire,
				"unknown":                 strings.TrimSuffix(codec.wire, "}") + `,"extra":"private content"}`,
				"payload forbidden":       strings.TrimSuffix(codec.wire, "}") + `,"payload":"c2VjcmV0"}`,
				"float schema":            strings.Replace(codec.wire, `"schema_version":1`, `"schema_version":1.0`, 1),
				"exponent schema":         strings.Replace(codec.wire, `"schema_version":1`, `"schema_version":1e0`, 1),
				"escaped slash":           strings.Replace(codec.wire, "open-trestle/", `open-trestle\/`, 1),
				"escaped key":             strings.Replace(codec.wire, `"contract"`, `"\u0063ontract"`, 1),
				"at byte bound":           codec.wire + strings.Repeat(" ", codec.limit-len(codec.wire)),
				"over byte bound":         codec.wire + strings.Repeat(" ", codec.limit+1-len(codec.wire)),
				"over bound unstructured": strings.Repeat("x", codec.limit+1),
			}
			fields := avFields(t, codec.wire)
			reversed := append([]string(nil), codec.order...)
			reversed[0], reversed[1] = reversed[1], reversed[0]
			bad["reordered"] = avOrdered(t, fields, reversed, false)
			for _, field := range codec.order {
				encoded, err := json.Marshal(fields[field])
				if err != nil {
					t.Fatal(err)
				}
				member := `"` + field + `":` + string(encoded)
				bad["duplicate/"+field] = strings.Replace(codec.wire, member, member+","+member, 1)
				bad["null/"+field] = strings.Replace(codec.wire, member, `"`+field+`":null`, 1)
				bad["case alias/"+field] = strings.Replace(codec.wire, `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1)
				bad["missing/"+field] = strings.Replace(codec.wire, member+",", "", 1)
				if field == codec.order[len(codec.order)-1] {
					bad["missing/"+field] = strings.Replace(codec.wire, ","+member, "", 1)
				}
			}
			for name, wire := range bad {
				t.Run(name, func(t *testing.T) { codec.deny(t, wire, artifact.ErrInvalidErasureContract) })
			}
			for _, change := range []struct {
				field string
				value any
			}{{"contract", "open-trestle/wrong"}, {"schema_version", 0}, {"schema_version", 2}, {"schema_version", "1"}} {
				fields := avFields(t, codec.wire)
				fields[change.field] = change.value
				codec.deny(t, avRehash(t, fields, codec.order), artifact.ErrInvalidErasureContract)
			}
		})
	}
	fields := avFields(t, avAdmissionJSON)
	fields["media_type"] = "application/x&y"
	avRebindOriginal(t, fields)
	escaped := avRehash(t, fields, avAdmissionOrder)
	parsed, err := artifact.ParseArtifactAdmission([]byte(escaped))
	if err != nil || parsed.MediaType() != "application/x&y" {
		t.Fatal("valid HTML-escaped media rejected")
	}
	encoded, err := artifact.EncodeArtifactAdmission(parsed)
	if err != nil || string(encoded) != escaped || !strings.Contains(escaped, `\u0026`) {
		t.Fatal("Go JSON HTML escaping changed")
	}
	avDenyAdmission(t, strings.ReplaceAll(escaped, `\u0026`, "&"), artifact.ErrInvalidErasureContract)
	avDenyAdmission(t, strings.Replace(avAdmissionJSON, `"created_at_milliseconds":100`, `"created_at_milliseconds":1e2`, 1), artifact.ErrInvalidErasureContract)
	avDenyAdmission(t, strings.Replace(avAdmissionJSON, `"admitted_at_milliseconds":500`, `"admitted_at_milliseconds":500.0`, 1), artifact.ErrInvalidErasureContract)
}

func TestAdmissionValuesImmutableZeroAndCopies(t *testing.T) {
	avZeroNamespace(t, artifact.StorageNamespace{})
	avZeroAdmission(t, artifact.ArtifactAdmission{})
	nsBytes, err := artifact.EncodeStorageNamespace(artifact.StorageNamespace{})
	avError(t, err, artifact.ErrInvalidErasureContract)
	if len(nsBytes) != 0 {
		t.Fatal("zero namespace encoded data")
	}
	adBytes, err := artifact.EncodeArtifactAdmission(artifact.ArtifactAdmission{})
	avError(t, err, artifact.ErrInvalidErasureContract)
	if len(adBytes) != 0 {
		t.Fatal("zero admission encoded data")
	}
	for _, input := range []string{"{}", "null", avNamespaceJSON, avAdmissionJSON, `{"Identity":"` + avAdmissionIdentity + `","Provenance":["` + avOther + `"],"Payload":"c2VjcmV0","Verified":true}`} {
		var namespace artifact.StorageNamespace
		var admission artifact.ArtifactAdmission
		_ = json.Unmarshal([]byte(input), &namespace)
		_ = json.Unmarshal([]byte(input), &admission)
		avZeroNamespace(t, namespace)
		avZeroAdmission(t, admission)
	}
	nsInput, adInput := []byte(avNamespaceJSON), []byte(avAdmissionJSON)
	namespace, err := artifact.ParseStorageNamespace(nsInput)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := artifact.ParseArtifactAdmission(adInput)
	if err != nil {
		t.Fatal(err)
	}
	nsCopy, adCopy := namespace, admission
	for index := range nsInput {
		nsInput[index] = 'x'
	}
	for index := range adInput {
		adInput[index] = 'x'
	}
	for _, value := range []artifact.StorageNamespace{namespace, nsCopy} {
		first, err := artifact.EncodeStorageNamespace(value)
		if err != nil || string(first) != avNamespaceJSON {
			t.Fatal("namespace retained parser input")
		}
		first[0] = 'x'
		second, err := artifact.EncodeStorageNamespace(value)
		if err != nil || string(second) != avNamespaceJSON || value.Validate() != nil {
			t.Fatal("namespace encoding aliased value")
		}
	}
	for _, value := range []artifact.ArtifactAdmission{admission, adCopy} {
		provenance := value.Provenance()
		provenance[0] = avOther
		first, err := artifact.EncodeArtifactAdmission(value)
		if err != nil || string(first) != avAdmissionJSON {
			t.Fatal("admission aliased parser input or getter")
		}
		first[0] = 'x'
		second, err := artifact.EncodeArtifactAdmission(value)
		if err != nil || string(second) != avAdmissionJSON || value.Validate() != nil {
			t.Fatal("admission encoding aliased value")
		}
	}
	actual := avHistoricalArtifact(t)
	provenance := []string{avOther, avBackend}
	payload := []byte("independent synthetic payload")
	actual, err = artifact.New(actual.Scope(), actual.Kind(), actual.MediaType(), actual.Classification(), actual.Origin(), actual.Protection(), provenance, payload, actual.CreatedAt(), actual.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	one, err := artifact.NewArtifactAdmission(actual, avNamespaceIdentity, time.UnixMilli(500).UTC())
	if err != nil {
		t.Fatal(err)
	}
	two, err := artifact.NewArtifactAdmission(actual, avNamespaceIdentity, time.UnixMilli(500).UTC())
	if err != nil {
		t.Fatal(err)
	}
	before, err := artifact.EncodeArtifactAdmission(one)
	if err != nil {
		t.Fatal(err)
	}
	provenance[0], payload[0] = avEpoch, 'x'
	actual.Provenance()[0] = avEpoch
	actual.Payload()[0] = 'x'
	one.Provenance()[0] = avEpoch
	for _, value := range []artifact.ArtifactAdmission{one, two} {
		avAdmissionMatches(t, value, actual, time.UnixMilli(500).UTC())
		after, err := artifact.EncodeArtifactAdmission(value)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("independent admissions shared mutable metadata")
		}
		if !reflect.DeepEqual(value.Provenance(), []string{avBackend, avOther}) {
			t.Fatal("canonical provenance copy differs")
		}
		for _, shapeType := range []reflect.Type{reflect.TypeOf(value), reflect.TypeOf(&value)} {
			if _, exists := shapeType.MethodByName("Payload"); exists {
				t.Fatal("metadata-only admission exposes Payload")
			}
		}
		if _, exists := avFields(t, string(after))["payload"]; exists {
			t.Fatal("admission wire retained payload")
		}
	}
	// Exported behavior cannot prove universal payload nonretention or the number
	// of Artifact.Validate calls. The implementation representation needs source review.
}

func TestAdmissionValuesFormattingRedacted(t *testing.T) {
	var _ fmt.Stringer = artifact.StorageNamespace{}
	var _ fmt.GoStringer = artifact.StorageNamespace{}
	var _ fmt.Formatter = artifact.StorageNamespace{}
	var _ fmt.Stringer = artifact.ArtifactAdmission{}
	var _ fmt.GoStringer = artifact.ArtifactAdmission{}
	var _ fmt.Formatter = artifact.ArtifactAdmission{}
	namespace, admission := avNamespace(t), avAdmission(t)
	secrets := []string{avNamespaceIdentity, avBackend, avEpoch, avPrefix, avAdmissionIdentity, avArtifactIdentity, avScopeIdentity, avPayloadDigest,
		"tenant-h0", "repo-h0", "run-remote-h0", "context_packet", "application/json", "restricted", "host", "envelope_encrypted", strings.Repeat("a", 64), "se3-h0-synthetic-history",
		"namespace_identity", "payload_digest", "created_at_milliseconds", "100", "1000", "500"}
	check := func(text string) {
		t.Helper()
		if text == "" || strings.Contains(text, "%!") {
			t.Fatal("formatting is empty or used a mismatch fallback")
		}
		for _, secret := range secrets {
			if strings.Contains(text, secret) {
				t.Fatal("formatting exposed metadata")
			}
		}
	}
	for _, text := range []string{namespace.String(), namespace.GoString(), admission.String(), admission.GoString()} {
		check(text)
	}
	for _, value := range []any{namespace, &namespace, admission, &admission} {
		// Runtime strings intentionally exercise mismatched verbs without disabling vet.
		for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%f", "%t", "%c", "%e", "%20.8v", "%#q"} {
			check(fmt.Sprintf(format, value))
		}
	}
}
