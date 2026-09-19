package artifact

// All values and predicates below are metadata, not durable acceptance or effect permission.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const raOperationContract = `open-trestle/artifact-erasure-operation`
const raOther = `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
const raScopeIdentity = `4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa`
const raNamespaceIdentity = `84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80`
const raArtifactIdentity = `cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5`
const raAdmissionIdentity = `968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3`
const raAuthorizationIdentity = `86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992`
const raDocumentDigest = `6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8`
const raPolicyIdentity = `debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca`
const raOperationIdentity = `c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050`
const raOperationUnsigned = `{"contract":"open-trestle/artifact-erasure-operation","schema_version":2,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","ownership":"all_versions_at_exact_key","prepared_at_milliseconds":1000,"erasure_protocol":"same-key-fence-v2","legacy_receipt_identity":""}`
const raOperationJSON = `{"contract":"open-trestle/artifact-erasure-operation","schema_version":2,"identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","ownership":"all_versions_at_exact_key","prepared_at_milliseconds":1000,"erasure_protocol":"same-key-fence-v2","legacy_receipt_identity":""}`
const raPolicyJSON = `{"contract":"open-trestle/protected-artifact-erasure-policy","schema_version":1,"identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","backend_configuration_identity":"1111111111111111111111111111111111111111111111111111111111111111","prefix":"authorization-fixture/a_0-z","namespace_epoch_identity":"2222222222222222222222222222222222222222222222222222222222222222","backend_kind":"aws_s3_general_purpose","database_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333","namespace_mode":"protected_new_nonnull","protocol":"same-key-fence-v2","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","erasure_policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","configuration_evidence_identity":"7777777777777777777777777777777777777777777777777777777777777777","not_before_milliseconds":900,"not_after_milliseconds":1400}`
const raGrantJSON = `{"contract":"open-trestle/artifact-erasure-authorization","schema_version":2,"identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","hold_clearance_identity":"9999999999999999999999999999999999999999999999999999999999999999","ownership":"all_versions_at_exact_key","fence_retention_policy_identity":"4444444444444444444444444444444444444444444444444444444444444444","reason":"expired","issued_at_milliseconds":900,"expires_at_milliseconds":1500,"legacy_receipt_identity":""}`
const raAdmissionJSON = `{"contract":"open-trestle/artifact-admission","schema_version":1,"identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","created_at_milliseconds":100,"expires_at_milliseconds":1000,"admitted_at_milliseconds":500}`
const raScopeUnsigned = `{"contract":"open-trestle/audit-review-scope","version":1,"tenant":"tenant-auth","repository":"repo-auth","review_run":"run-auth"}`
const raOriginalArtifactJSON = `{"contract":"open-trestle/runtime-artifact","schema_version":1,"identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth","kind":"context_packet","media_type":"text/plain","classification":"restricted","origin":"host","protection":"envelope_encrypted","provenance":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"payload_digest":"6008784e659160eb6caf5eb1fe2f622090c2f3fac3a81018a9547e767ba8540b","payload":"c3ludGhldGljIGF1dGhvcml6YXRpb24gYWRtaXNzaW9u","created_at_milliseconds":100,"expires_at_milliseconds":1000}`
const raContract = "open-trestle/artifact-erasure-resume-allowance"
const raIdentity = "d80b25139104bf19c2f63f61c906bc5cd5546325983a5a65a92672238b1c3352"
const raUnsigned = `{"contract":"open-trestle/artifact-erasure-resume-allowance","schema_version":1,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","issuance_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_bucket_owner":"123456789012","not_before_milliseconds":1000,"not_after_milliseconds":901000,"maximum":{"requests":4096,"mutations":2048,"reads":2048,"lists":1024,"creates":128,"deletes":2048,"pages":1024,"versions":262144,"response_bytes":1073741824,"list_bytes":67108864,"write_bytes":2097152}}`
const raJSON = `{"contract":"open-trestle/artifact-erasure-resume-allowance","schema_version":1,"identity":"d80b25139104bf19c2f63f61c906bc5cd5546325983a5a65a92672238b1c3352","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","issuance_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_bucket_owner":"123456789012","not_before_milliseconds":1000,"not_after_milliseconds":901000,"maximum":{"requests":4096,"mutations":2048,"reads":2048,"lists":1024,"creates":128,"deletes":2048,"pages":1024,"versions":262144,"response_bytes":1073741824,"list_bytes":67108864,"write_bytes":2097152}}`

var raOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest recovery_policy_identity protected_policy_identity principal_identity issuance_identity expected_bucket_owner not_before_milliseconds not_after_milliseconds maximum")
var raBudgetOrder = strings.Fields("requests mutations reads lists creates deletes pages versions response_bytes list_bytes write_bytes")
var raOperationOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity original_authorization_identity authorization_document_digest policy_identity protected_policy_identity ownership prepared_at_milliseconds erasure_protocol legacy_receipt_identity")
var raPolicyOrder = strings.Fields("contract schema_version identity namespace_identity backend_configuration_identity prefix namespace_epoch_identity backend_kind database_authority_identity namespace_mode protocol ownership fence_retention_policy_identity erasure_policy_identity recovery_policy_identity configuration_evidence_identity not_before_milliseconds not_after_milliseconds")

func raHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func raQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func raFields(t *testing.T, wire string) map[string]json.RawMessage {
	t.Helper()
	var f map[string]json.RawMessage
	if err := json.Unmarshal([]byte(wire), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// Independent ordered raw-member recipe. Never calls a product encoder or identity helper.
func raOrdered(t *testing.T, f map[string]json.RawMessage, order []string, unsigned bool) string {
	t.Helper()
	var members []string
	for _, key := range order {
		if unsigned && key == "identity" {
			continue
		}
		v, ok := f[key]
		if !ok {
			t.Fatal("missing recipe member", key)
		}
		members = append(members, raQuote(key)+":"+string(v))
	}
	return "{" + strings.Join(members, ",") + "}"
}
func raVariant(t *testing.T, wire string, order []string, domain string, changes map[string]string) string {
	t.Helper()
	f := raFields(t, wire)
	for k, v := range changes {
		if _, ok := f[k]; !ok {
			t.Fatal("unknown recipe member", k)
		}
		f[k] = json.RawMessage(v)
	}
	f["identity"] = json.RawMessage(raQuote(raHash(domain + raOrdered(t, f, order, true))))
	return raOrdered(t, f, order, false)
}
func raChange(t *testing.T, changes map[string]string) string {
	return raVariant(t, raJSON, raOrder, raContract+"/v1\x00", changes)
}
func raScope(t *testing.T, tenant, repository, run string) audit.ReviewScope {
	t.Helper()
	s, err := audit.NewReviewScope(tenant, repository, run)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func raMatchingScope(t *testing.T) audit.ReviewScope {
	return raScope(t, "tenant-auth", "repo-auth", "run-auth")
}
func raOperation(t *testing.T) ErasureOperation {
	t.Helper()
	o, err := ParseErasureOperation([]byte(raOperationJSON), raMatchingScope(t))
	if err != nil || o.Validate() != nil {
		t.Fatal("existing explicit-scope operation fixture", err)
	}
	return o
}
func raMaximum() ResumeBudget {
	return ResumeBudget{Requests: 4096, Mutations: 2048, Reads: 2048, Lists: 1024, Creates: 128, Deletes: 2048, Pages: 1024, Versions: 262144, ResponseBytes: 1073741824, ListBytes: 67108864, WriteBytes: 2097152}
}
func raOptions(t *testing.T) ResumeAllowanceOptions {
	return ResumeAllowanceOptions{Operation: raOperation(t), RecoveryPolicyIdentity: strings.Repeat("6", 64), ProtectedPolicyIdentity: raPolicyIdentity, PrincipalIdentity: strings.Repeat("8", 64), IssuanceIdentity: strings.Repeat("a", 64), ExpectedBucketOwner: "123456789012", NotBefore: time.UnixMilli(1000).UTC(), NotAfter: time.UnixMilli(901000).UTC(), Maximum: raMaximum()}
}
func raNew(t *testing.T, o ResumeAllowanceOptions) ResumeAllowance {
	t.Helper()
	a, err := NewResumeAllowance(o)
	if err != nil || a.Validate() != nil {
		t.Fatal("valid allowance shape rejected", err)
	}
	return a
}
func raParse(t *testing.T, wire string, scope audit.ReviewScope) ResumeAllowance {
	t.Helper()
	a, err := ParseResumeAllowance([]byte(wire), scope)
	if err != nil || a.Validate() != nil || a.Scope() != scope {
		t.Fatal("explicit-scope allowance parse rejected", err)
	}
	b, err := EncodeResumeAllowance(a)
	if err != nil || string(b) != wire {
		t.Fatal("canonical bytes changed", err)
	}
	return a
}
func raZero(t *testing.T, a ResumeAllowance) {
	t.Helper()
	if !reflect.DeepEqual(a, ResumeAllowance{}) || a.Validate() == nil || a.ProtectedDocumentDigest() != "" || a.ValidateProtected(ProtectedErasurePolicy{}) == nil {
		t.Fatal("failure published usable allowance")
	}
	if !a.NotBefore().IsZero() || !a.NotAfter().IsZero() || a.Maximum() != (ResumeBudget{}) || a.Scope() != (audit.ReviewScope{}) {
		t.Fatal("zero getters retained state")
	}
	for _, v := range []string{a.Identity(), a.NamespaceIdentity(), a.OperationIdentity(), a.ArtifactIdentity(), a.AdmissionIdentity(), a.OriginalAuthorizationIdentity(), a.AuthorizationDocumentDigest(), a.RecoveryPolicyIdentity(), a.ProtectedPolicyIdentity(), a.PrincipalIdentity(), a.IssuanceIdentity(), a.ExpectedBucketOwner()} {
		if v != "" {
			t.Fatal("zero string getter retained data")
		}
	}
}
func raBad(t *testing.T, wire string, scope audit.ReviewScope) {
	t.Helper()
	a, err := ParseResumeAllowance([]byte(wire), scope)
	if err == nil {
		t.Fatal("invalid allowance accepted")
	}
	raZero(t, a)
}
func raBadNew(t *testing.T, o ResumeAllowanceOptions) {
	t.Helper()
	a, err := NewResumeAllowance(o)
	if err == nil {
		t.Fatal("invalid options accepted")
	}
	raZero(t, a)
}

func TestResumeAllowanceLiteralRecipeAndGetters(t *testing.T) {
	if raHash(raContract+"/v1\x00"+raUnsigned) != raIdentity || strings.Replace(raJSON, `"identity":"`+raIdentity+`",`, "", 1) != raUnsigned || raHash(raScopeUnsigned) != raScopeIdentity {
		t.Fatal("literal recipe mismatch")
	}
	if raHash(raOperationContract+"/v2\x00"+raOperationUnsigned) != raOperationIdentity || raHash(raGrantJSON) != raDocumentDigest {
		t.Fatal("historical operation or authorization-document hash changed")
	}
	for _, wrong := range []string{raUnsigned, raContract + "/v1" + raUnsigned, raContract + `/v1\x00` + raUnsigned, raContract + "/v1\x00" + raJSON} {
		if raHash(wrong) == raIdentity {
			t.Fatal("hash recipe not discriminating")
		}
	}
	scope := raMatchingScope(t)
	if scope.Identity() != raScopeIdentity {
		t.Fatal("native scope differs from independent vector")
	}
	for _, a := range []ResumeAllowance{raNew(t, raOptions(t)), raParse(t, raJSON, scope)} {
		b, err := EncodeResumeAllowance(a)
		if err != nil || string(b) != raJSON || len(b) > 4096 {
			t.Fatal("independent exact wire differs", err)
		}
		if a.Identity() != raIdentity || a.Scope() != scope || a.NamespaceIdentity() != raNamespaceIdentity || a.OperationIdentity() != raOperationIdentity || a.ArtifactIdentity() != raArtifactIdentity || a.AdmissionIdentity() != raAdmissionIdentity || a.OriginalAuthorizationIdentity() != raAuthorizationIdentity || a.AuthorizationDocumentDigest() != raDocumentDigest || a.RecoveryPolicyIdentity() != strings.Repeat("6", 64) || a.ProtectedPolicyIdentity() != raPolicyIdentity || a.PrincipalIdentity() != strings.Repeat("8", 64) || a.IssuanceIdentity() != strings.Repeat("a", 64) || a.ExpectedBucketOwner() != "123456789012" || a.NotBefore() != time.UnixMilli(1000).UTC() || a.NotAfter() != time.UnixMilli(901000).UTC() || a.Maximum() != raMaximum() {
			t.Fatal("exact getter projection differs")
		}
		if a.ProtectedDocumentDigest() != "" || a.ValidateProtected(ProtectedErasurePolicy{}) == nil {
			t.Fatal("constructor/parser minted authority")
		}
		for _, raw := range []string{"tenant-auth", "repo-auth", "run-auth", "tenant_id", "repository_id", "review_run_id", `"witness"`, `"accepted"`} {
			if strings.Contains(string(b), raw) {
				t.Fatal("wire includes noncanonical authority or raw scope")
			}
		}
	}
}

func TestResumeAllowanceIndependentBudgetCeilings(t *testing.T) {
	names := []string{"Requests", "Mutations", "Reads", "Lists", "Creates", "Deletes", "Pages", "Versions", "ResponseBytes", "ListBytes", "WriteBytes"}
	limits := []uint64{4096, 2048, 2048, 1024, 128, 2048, 1024, 262144, 1073741824, 67108864, 2097152}
	typ := reflect.TypeOf(ResumeBudget{})
	if typ.NumField() != 11 {
		t.Fatal("budget must expose exactly eleven dimensions")
	}
	for i, name := range names {
		field, ok := typ.FieldByName(name)
		want := reflect.Uint32
		if i >= 8 {
			want = reflect.Uint64
		}
		if !ok || field.PkgPath != "" || field.Type.Kind() != want {
			t.Fatal("frozen exported budget dimension changed", name)
		}
	}
	for _, change := range []map[string]string{{"requests": "0"}, {"requests": "1", "mutations": "2"}} {
		f := raFields(t, string(raFields(t, raJSON)["maximum"]))
		for k, v := range change {
			f[k] = json.RawMessage(v)
		}
		raBad(t, raChange(t, map[string]string{"maximum": raOrdered(t, f, raBudgetOrder, false)}), raMatchingScope(t))
	}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			// Reflection touches ONLY the explicitly exported budget fields, never a witness.
			for _, n := range []uint64{0, 1, limits[i]} {
				o := raOptions(t)
				o.Maximum = ResumeBudget{Requests: 4096}
				reflect.ValueOf(&o.Maximum).Elem().FieldByName(name).SetUint(n)
				if i == 0 && n == 0 {
					raBadNew(t, o)
					continue
				}
				a := raNew(t, o)
				if a.Maximum() != o.Maximum {
					t.Fatal("independent zero dimensions filled or dropped")
				}
				b, err := EncodeResumeAllowance(a)
				if err != nil {
					t.Fatal(err)
				}
				if raParse(t, string(b), a.Scope()).Maximum() != o.Maximum {
					t.Fatal("budget roundtrip differs")
				}
			}
			extreme := uint64(4294967295)
			if i >= 8 {
				extreme = ^uint64(0)
			}
			for _, n := range []uint64{limits[i] + 1, extreme} {
				o := raOptions(t)
				reflect.ValueOf(&o.Maximum).Elem().FieldByName(name).SetUint(n)
				raBadNew(t, o)
				f := raFields(t, string(raFields(t, raJSON)["maximum"]))
				f[raBudgetOrder[i]] = json.RawMessage(fmt.Sprint(n))
				raBad(t, raChange(t, map[string]string{"maximum": raOrdered(t, f, raBudgetOrder, false)}), raMatchingScope(t))
			}
		})
	}
	for _, b := range []ResumeBudget{{}, {Requests: 1, Mutations: 2}} {
		o := raOptions(t)
		o.Maximum = b
		raBadNew(t, o)
	}
	for _, b := range []ResumeBudget{{Requests: 1}, {Requests: 4096}, {Requests: 1, Reads: 2048}, {Requests: 1, Creates: 128}, {Requests: 1, Deletes: 2048}, {Requests: 1, Lists: 1024, Pages: 0, Versions: 0}, {Requests: 1, ResponseBytes: 1073741824, ListBytes: 67108864, WriteBytes: 2097152}} {
		o := raOptions(t)
		o.Maximum = b
		a := raNew(t, o)
		if a.Maximum() != b {
			t.Fatal("inferred missing permission from another ceiling")
		}
		fields := raFields(t, string(raFields(t, raJSON)["maximum"]))
		rv := reflect.ValueOf(b)
		for i, name := range names {
			fields[raBudgetOrder[i]] = json.RawMessage(fmt.Sprint(rv.FieldByName(name).Uint()))
		}
		want := raChange(t, map[string]string{"maximum": raOrdered(t, fields, raBudgetOrder, false)})
		encoded, err := EncodeResumeAllowance(a)
		if err != nil || string(encoded) != want {
			t.Fatal("zero partial dimensions omitted from canonical wire", err)
		}
	}
	// No sum-of-subdimensions >= requests rule and no sum arithmetic as validation.
	o := raOptions(t)
	o.Maximum = ResumeBudget{Requests: 4096}
	raNew(t, o)
}

// Finite per-member strictness matrix, also applied inside maximum.
func raNoncanonical(t *testing.T, wire string, order []string) map[string]string {
	t.Helper()
	f := raFields(t, wire)
	cases := map[string]string{"empty": "", "null": "null", "array": "[]", "leading": " " + wire, "trailing": wire + "\n", "second": wire + "{}", "bom": "\xef\xbb\xbf" + wire, "utf8": wire + "\xff", "nul": wire + "\x00", "truncated": wire[:len(wire)-1], "unknown": strings.TrimSuffix(wire, "}") + `,"unknown":1}`}
	for i, k := range order {
		member := raQuote(k) + ":" + string(f[k])
		without := strings.Replace(wire, member+",", "", 1)
		if without == wire {
			without = strings.Replace(wire, ","+member, "", 1)
		}
		cases["missing/"+k] = without
		for label, replacement := range map[string]string{"null": raQuote(k) + ":null", "duplicate": member + "," + member, "conflicting-duplicate": raQuote(k) + ":null," + member, "alias": raQuote(strings.ToUpper(k)) + ":" + string(f[k]), "alias-duplicate": raQuote(strings.ToUpper(k)) + ":" + string(f[k]) + "," + member, "wrong-type": raQuote(k) + ":[]", "escaped-key": `"\u` + fmt.Sprintf("%04x", k[0]) + k[1:] + `":` + string(f[k])} {
			cases[label+"/"+k] = strings.Replace(wire, member, replacement, 1)
		}
		if i+1 < len(order) {
			swapped := append([]string(nil), order...)
			swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
			cases["order/"+k] = raOrdered(t, f, swapped, false)
		}
	}
	return cases
}
func TestResumeAllowanceStrictBoundedCanonicalCodec(t *testing.T) {
	s := raMatchingScope(t)
	for name, wire := range raNoncanonical(t, raJSON, raOrder) {
		t.Run(name, func(t *testing.T) { raBad(t, wire, s) })
	}
	maximum := string(raFields(t, raJSON)["maximum"])
	for name, bad := range raNoncanonical(t, maximum, raBudgetOrder) {
		t.Run("maximum/"+name, func(t *testing.T) { raBad(t, strings.Replace(raJSON, maximum, bad, 1), s) })
	}
	for _, size := range []int{4095, 4096, 4097, 16384, 16385} {
		raBad(t, raJSON+strings.Repeat(" ", size-len(raJSON)), s)
	}
	for _, k := range raBudgetOrder {
		for _, n := range []string{"-1", "-0", "01", "1.0", "1e0", `"1"`, "true", "18446744073709551616"} {
			f := raFields(t, maximum)
			f[k] = json.RawMessage(n)
			raBad(t, raChange(t, map[string]string{"maximum": raOrdered(t, f, raBudgetOrder, false)}), s)
		}
	}
	for _, bad := range []string{"0", "2", "-1", "1.0", "1e0", `"1"`} {
		raBad(t, raChange(t, map[string]string{"schema_version": bad}), s)
	}
	for _, bad := range []string{`"wrong"`, `""`, `"open-trestle/artifact-erasure-resume-allowance/v1"`} {
		raBad(t, raChange(t, map[string]string{"contract": bad}), s)
	}
	for _, bad := range []string{strings.Replace(raJSON, "open-trestle/", `open-trestle\/`, 1), strings.Replace(raJSON, `"123456789012"`, `"\u003123456789012"`, 1), strings.Replace(raJSON, `"123456789012"`, "\"12345678901\xff\"", 1)} {
		raBad(t, bad, s)
	}
	// A changed valid field without a new identity must be refused separately from shape.
	raBad(t, strings.Replace(raJSON, `"123456789012"`, `"123456789013"`, 1), s)
	raBad(t, strings.Replace(raJSON, raIdentity, raOther, 1), s)
}

func TestResumeAllowanceIdentityOwnerAndTimeShape(t *testing.T) {
	s := raMatchingScope(t)
	for _, k := range raOrder {
		if k != "identity" && !strings.HasSuffix(k, "_identity") && k != "authorization_document_digest" {
			continue
		}
		for _, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), " " + raOther, raOther + "\x00", strings.Repeat("é", 32)} {
			wire := raChange(t, map[string]string{k: raQuote(bad)})
			if k == "identity" {
				wire = strings.Replace(raJSON, raIdentity, bad, 1)
			}
			raBad(t, wire, s)
		}
	}
	for _, field := range []string{"RecoveryPolicyIdentity", "ProtectedPolicyIdentity", "PrincipalIdentity", "IssuanceIdentity"} {
		for _, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), raOther + "\x00"} {
			o := raOptions(t)
			reflect.ValueOf(&o).Elem().FieldByName(field).SetString(bad)
			raBadNew(t, o)
		}
	}
	for _, owner := range []string{"", "000000000000", "12345678901", "1234567890123", "12345678901a", "+12345678901", " 12345678901", "12345678901\n", "１２３４５６７８９０１２", "12345678901\x00"} {
		o := raOptions(t)
		o.ExpectedBucketOwner = owner
		raBadNew(t, o)
		raBad(t, raChange(t, map[string]string{"expected_bucket_owner": raQuote(owner)}), s)
	}
	for _, owner := range []string{"000000000001", "999999999999"} {
		o := raOptions(t)
		o.ExpectedBucketOwner = owner
		a := raNew(t, o)
		if a.ExpectedBucketOwner() != owner {
			t.Fatal("owner digits normalized")
		}
		raParse(t, raChange(t, map[string]string{"expected_bucket_owner": raQuote(owner)}), s)
	}
	for _, bounds := range [][2]int64{{1, 2}, {1000, 901000}, {253402299899999, 253402300799999}} {
		o := raOptions(t)
		o.NotBefore = time.UnixMilli(bounds[0]).UTC()
		o.NotAfter = time.UnixMilli(bounds[1]).UTC()
		raNew(t, o)
		raParse(t, raChange(t, map[string]string{"not_before_milliseconds": fmt.Sprint(bounds[0]), "not_after_milliseconds": fmt.Sprint(bounds[1])}), s)
	}
	for _, bounds := range [][2]int64{{0, 1}, {-1, 1}, {1000, 1000}, {1001, 1000}, {1000, 901001}, {253402300799999, 253402300800000}} {
		o := raOptions(t)
		o.NotBefore = time.UnixMilli(bounds[0]).UTC()
		o.NotAfter = time.UnixMilli(bounds[1]).UTC()
		raBadNew(t, o)
		raBad(t, raChange(t, map[string]string{"not_before_milliseconds": fmt.Sprint(bounds[0]), "not_after_milliseconds": fmt.Sprint(bounds[1])}), s)
	}
	for _, field := range []string{"not_before_milliseconds", "not_after_milliseconds"} {
		for _, bad := range []string{"0", "-1", "253402300800000", "9223372036854775807", "9223372036854775808", "18446744073709551616", "1000.0", "1e3", `"1000"`, "null"} {
			raBad(t, raChange(t, map[string]string{field: bad}), s)
		}
	}
	for _, bad := range []time.Time{time.Time{}, time.UnixMilli(1000).UTC().Add(time.Nanosecond), time.UnixMilli(1000).In(time.FixedZone("offset", 3600)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1000000000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(-1000000000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		for _, first := range []bool{true, false} {
			o := raOptions(t)
			if first {
				o.NotBefore = bad
			} else {
				o.NotAfter = bad
			}
			raBadNew(t, o)
		}
	}
	o := raOptions(t)
	o.NotBefore = o.NotBefore.In(time.FixedZone("UTC-alias", 0))
	o.NotAfter = o.NotAfter.In(time.FixedZone("UTC-alias", 0))
	a := raNew(t, o)
	if a.Identity() != raIdentity || a.NotBefore().Location() != time.UTC || a.NotAfter().Location() != time.UTC {
		t.Fatal("exact zero-offset alias not normalized to UTC getters")
	}
}

func TestResumeAllowanceExplicitScopeAndOperationPredicate(t *testing.T) {
	op := raOperation(t)
	a := raParse(t, raJSON, op.Scope())
	ref, err := NewErasureOperationRef(op.Scope(), op.NamespaceIdentity(), op.Identity())
	if err != nil || ref.Validate() != nil || ref.Scope() != op.Scope() {
		t.Fatal("actual operation ref lost full scope", err)
	}
	for _, tc := range []struct {
		ms int64
		ok bool
	}{{999, false}, {1000, true}, {900999, true}, {901000, false}} {
		if a.AllowsOperation(op, time.UnixMilli(tc.ms).UTC()) != tc.ok {
			t.Fatal("half-open metadata window differs", tc.ms)
		}
	}
	for _, at := range []time.Time{time.Time{}, time.UnixMilli(1000).UTC().Add(time.Nanosecond), time.UnixMilli(1000).In(time.FixedZone("offset", 1)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if a.AllowsOperation(op, at) {
			t.Fatal("invalid decision instant allowed")
		}
	}
	if !a.AllowsOperation(op, time.UnixMilli(1000).In(time.FixedZone("zero-alias", 0))) {
		t.Fatal("zero-offset decision alias refused")
	}
	early := raParse(t, raChange(t, map[string]string{"not_before_milliseconds": "1", "not_after_milliseconds": "2000"}), op.Scope())
	if early.AllowsOperation(op, time.UnixMilli(999).UTC()) {
		t.Fatal("decision before operation preparation allowed")
	}
	if a.AllowsOperation(ErasureOperation{}, time.UnixMilli(1000).UTC()) {
		t.Fatal("zero operation allowed")
	}
	o := raOptions(t)
	o.Operation = ErasureOperation{}
	raBadNew(t, o)
	raBad(t, raJSON, audit.ReviewScope{})
	for _, scope := range []audit.ReviewScope{raScope(t, "other-tenant", "repo-auth", "run-auth"), raScope(t, "tenant-auth", "other-repo", "run-auth"), raScope(t, "tenant-auth", "repo-auth", "other-run"), raScope(t, strings.Repeat("a", 128), strings.Repeat("b", 128), strings.Repeat("c", 128))} {
		raBad(t, raJSON, scope)
		foreignWire := raChange(t, map[string]string{"scope_identity": raQuote(scope.Identity())})
		foreign := raParse(t, foreignWire, scope)
		if foreign.AllowsOperation(op, time.UnixMilli(1000).UTC()) {
			t.Fatal("foreign explicit scope matched operation")
		}
		raBad(t, foreignWire, op.Scope())
	}
	// Ordinary JSON cannot make even a full scope. No digest-only reconstruction.
	var forged audit.ReviewScope
	if err := json.Unmarshal([]byte(`{"identity":"`+raScopeIdentity+`","tenant_id":"tenant-auth","repository_id":"repo-auth","review_run_id":"run-auth"}`), &forged); err != nil {
		t.Fatal(err)
	}
	raBad(t, raJSON, forged)
	for _, key := range []string{"namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "original_authorization_identity", "authorization_document_digest"} {
		foreign := raParse(t, raChange(t, map[string]string{key: raQuote(raOther)}), op.Scope())
		if foreign.Identity() == a.Identity() || foreign.AllowsOperation(op, time.UnixMilli(1000).UTC()) {
			t.Fatal("allowance original binding omitted", key)
		}
	}
	for _, key := range []string{"namespace_identity", "artifact_identity", "admission_identity", "original_authorization_identity", "authorization_document_digest", "prepared_at_milliseconds"} {
		replacement := raQuote(raOther)
		if key == "prepared_at_milliseconds" {
			replacement = "1001"
		}
		wire := raVariant(t, raOperationJSON, raOperationOrder, raOperationContract+"/v2\x00", map[string]string{key: replacement})
		foreign, err := ParseErasureOperation([]byte(wire), op.Scope())
		if err != nil {
			t.Fatal("rehashed existing metadata fixture", err)
		}
		if a.AllowsOperation(foreign, time.UnixMilli(1001).UTC()) {
			t.Fatal("foreign operation accepted", key)
		}
		o := raOptions(t)
		o.Operation = foreign
		made := raNew(t, o)
		if made.OperationIdentity() != foreign.Identity() || made.AdmissionIdentity() != foreign.AdmissionIdentity() || made.AuthorizationDocumentDigest() != foreign.AuthorizationDocumentDigest() {
			t.Fatal("constructor did not derive supplied operation bindings")
		}
	}
	// A true result above deliberately occurs for PARSED/unprotected metadata.
	// It is not durable original-winner acceptance, a budget spend, or current policy authority.
	if a.ProtectedDocumentDigest() != "" || a.ValidateProtected(ProtectedErasurePolicy{}) == nil {
		t.Fatal("metadata predicate minted authority")
	}
}

func raRedaction(t *testing.T, a ResumeAllowance) {
	t.Helper()
	zero := ResumeAllowance{}
	if a.String() == "" || a.String() != zero.String() || a.GoString() == "" || a.GoString() != zero.GoString() {
		t.Fatal("nonconstant redaction")
	}
	typ := reflect.TypeOf(a)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).PkgPath == "" {
			t.Fatal("exported mutable allowance field", typ.Field(i).Name)
		}
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%c", "%f", "%T", "%10000v", "%10000.10000q", "%#10000x", "%0.1s"} {
		// Dynamic verbs intentionally exercise fmt mismatches without a vet literal diagnostic.
		got, want := fmt.Sprintf(format, a), fmt.Sprintf(format, zero)
		if got == "" || got != want || len(got) > 160 || strings.Contains(got, "%!") {
			t.Fatal("unbounded/nonconstant formatter", format)
		}
		pgot, pwant := fmt.Sprintf(format, &a), fmt.Sprintf(format, &zero)
		if pgot == "" || pgot != pwant || len(pgot) > 160 || strings.Contains(pgot, "%!") {
			t.Fatal("pointer formatter leaks", format)
		}
	}
}
func TestResumeAllowanceZeroCopiesAndNoJSONMint(t *testing.T) {
	raZero(t, ResumeAllowance{})
	if b, err := EncodeResumeAllowance(ResumeAllowance{}); err == nil || len(b) != 0 {
		t.Fatal("zero allowance encoded")
	}
	var forged ResumeAllowance
	if err := json.Unmarshal([]byte(raJSON), &forged); err != nil {
		t.Fatal(err)
	}
	raZero(t, forged)
	raw := []byte(raJSON)
	a, err := ParseResumeAllowance(raw, raMatchingScope(t))
	if err != nil {
		t.Fatal(err)
	}
	copied := a
	for i := range raw {
		raw[i] = 'x'
	}
	o := raOptions(t)
	made := raNew(t, o)
	o.Maximum.Requests = 1
	o.ExpectedBucketOwner = "999999999999"
	max := made.Maximum()
	max.Requests = 2
	for _, value := range []ResumeAllowance{a, copied, made} {
		first, err := EncodeResumeAllowance(value)
		if err != nil || string(first) != raJSON {
			t.Fatal("caller/input copy changed value", err)
		}
		second, err := EncodeResumeAllowance(value)
		if err != nil {
			t.Fatal(err)
		}
		first[0] = 'x'
		third, err := EncodeResumeAllowance(value)
		if err != nil || !bytes.Equal(second, third) || string(third) != raJSON {
			t.Fatal("encoder output aliases state")
		}
		if value.Maximum() != raMaximum() {
			t.Fatal("exported budget was not copied")
		}
		raRedaction(t, value)
	}
}
