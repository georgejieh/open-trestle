package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

const avAttemptMetaRequestContract = `open-trestle/artifact-erasure-attempt-request`
const avAttemptMetaAttemptContract = `open-trestle/artifact-erasure-attempt`
const avAttemptMetaOther = `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
const avAttemptMetaOperationJSON = `{"contract":"open-trestle/artifact-erasure-operation","schema_version":2,"identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","policy_identity":"5555555555555555555555555555555555555555555555555555555555555555","protected_policy_identity":"debbe1b161903f90e4fc58a77bc07c46302f9a5106bc4ed098b31a76816335ca","ownership":"all_versions_at_exact_key","prepared_at_milliseconds":1000,"erasure_protocol":"same-key-fence-v2","legacy_receipt_identity":""}`
const avAttemptMetaFenceBytes = `OTAF0001{"contract":"open-trestle/artifact-erasure-fence","schema_version":1,"identity":"188c587e4605df05ea58ef7ab5baa0f0ecfacc197207d4cbf26df299ef447096","erasure_protocol":"same-key-fence-v2","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","prepared_at_milliseconds":1000}`
const avAttemptMetaAllowanceUnsigned = `{"contract":"open-trestle/artifact-erasure-resume-allowance","schema_version":1,"namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","issuance_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_bucket_owner":"123456789012","not_before_milliseconds":1000,"not_after_milliseconds":2000,"maximum":{"requests":1,"mutations":0,"reads":0,"lists":0,"creates":0,"deletes":0,"pages":0,"versions":0,"response_bytes":0,"list_bytes":0,"write_bytes":0}}`
const avAttemptMetaAllowanceJSON = `{"contract":"open-trestle/artifact-erasure-resume-allowance","schema_version":1,"identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","recovery_policy_identity":"6666666666666666666666666666666666666666666666666666666666666666","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","principal_identity":"8888888888888888888888888888888888888888888888888888888888888888","issuance_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_bucket_owner":"123456789012","not_before_milliseconds":1000,"not_after_milliseconds":2000,"maximum":{"requests":1,"mutations":0,"reads":0,"lists":0,"creates":0,"deletes":0,"pages":0,"versions":0,"response_bytes":0,"list_bytes":0,"write_bytes":0}}`
const avAttemptMetaAllowanceIdentity = `66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c`
const avAttemptMetaAllowanceDigest = `0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5`
const avAttemptMetaScopeUnsigned = `{"contract":"open-trestle/audit-review-scope","version":1,"tenant":"tenant-auth","repository":"repo-auth","review_run":"run-auth"}`
const avAttemptMetaScopeIdentity = `4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa`
const avAttemptMetaNamespaceIdentity = `84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80`

var avAttemptMetaRequestOrder = strings.Fields("contract schema_version identity reservation_identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest allowance_identity allowance_document_digest protected_policy_identity expected_bucket_owner kind key version_kind version_id key_marker version_id_marker page_limit maximum_response_bytes body_digest body_bytes condition observation_identity")
var avAttemptMetaAllowanceOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest recovery_policy_identity protected_policy_identity principal_identity issuance_identity expected_bucket_owner not_before_milliseconds not_after_milliseconds maximum")
var avAttemptMetaOperationOrder = strings.Fields("contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity original_authorization_identity authorization_document_digest policy_identity protected_policy_identity ownership prepared_at_milliseconds erasure_protocol legacy_receipt_identity")

var avAttemptMetaRequestVectors = []struct{ name, unsigned, identity, wire string }{
	{"current_read", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"current_read","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`, "328f6330284e5c6c1233382d1ef7be17c3bfce91d425b270466e98b34bce5833", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"328f6330284e5c6c1233382d1ef7be17c3bfce91d425b270466e98b34bce5833","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"current_read","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`},
	{"intent_read", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"intent_read","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.intent-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`, "0542544836a9d518deb3d00e574b32703134d34151b1fab0242c11f5bc98aed0", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"0542544836a9d518deb3d00e574b32703134d34151b1fab0242c11f5bc98aed0","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"intent_read","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.intent-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`},
	{"attestation_read", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"attestation_read","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.attestation-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`, "2474b8ca4400e4419ec00203c00b93788e049056e480c22595548bdb3a23bdca", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"2474b8ca4400e4419ec00203c00b93788e049056e480c22595548bdb3a23bdca","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"attestation_read","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.attestation-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`},
	{"version_list", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_list","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":2,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`, "2ef758aac8e195c5637b57f52b6a0d92ac4a2ccf8c94b3256d2211b99584d442", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"2ef758aac8e195c5637b57f52b6a0d92ac4a2ccf8c94b3256d2211b99584d442","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_list","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":2,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`},
	{"intent_create", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"intent_create","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.intent-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"3701591f41646674ace373f76645db080d6dd8ea9d0914777c081391d090b625","body_bytes":1018,"condition":"if_none_match_star","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, "409dca1fa266028430e3bae2fc32ad52e2918e61633990938247a316d18b7867", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"409dca1fa266028430e3bae2fc32ad52e2918e61633990938247a316d18b7867","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"intent_create","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.intent-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"3701591f41646674ace373f76645db080d6dd8ea9d0914777c081391d090b625","body_bytes":1018,"condition":"if_none_match_star","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`},
	{"fence_create", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"fence_create","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"b02c6f55236b8476209bf421250674a2e75b0950982d8e8e3fb683e42205ebdc","body_bytes":573,"condition":"if_none_match_star","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, "589b3a9ae5856ac0eec14567d99ed87af345d6199a19820721fc04b59aa81747", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"589b3a9ae5856ac0eec14567d99ed87af345d6199a19820721fc04b59aa81747","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"fence_create","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"b02c6f55236b8476209bf421250674a2e75b0950982d8e8e3fb683e42205ebdc","body_bytes":573,"condition":"if_none_match_star","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`},
	{"version_delete", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_delete","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"data","version_id":"v1","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, "465359c8cebaab354e6867767271f0177048fb69814783fc12cf6531b2b36303", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"465359c8cebaab354e6867767271f0177048fb69814783fc12cf6531b2b36303","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_delete","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"data","version_id":"v1","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`},
	{"attestation_create", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"attestation_create","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.attestation-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","body_bytes":1,"condition":"if_none_match_star","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, "5684cc255fed1c08e3de921d9ac526b4cb37f0061989eb7632ede5d324accb50", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"5684cc255fed1c08e3de921d9ac526b4cb37f0061989eb7632ede5d324accb50","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"attestation_create","key":"authorization-fixture/a_0-z/deletions/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5.attestation-v2","version_kind":"","version_id":"","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","body_bytes":1,"condition":"if_none_match_star","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`},
	{"delete_marker", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_delete","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"delete_marker","version_id":"v1","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, "8561b6536e0c55745de04c9942783595d356769986b5db53d9a62039a163baa4", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"8561b6536e0c55745de04c9942783595d356769986b5db53d9a62039a163baa4","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_delete","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"delete_marker","version_id":"v1","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`},
	{"continuation", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_list","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_id_marker":"Next+/=","page_limit":2,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`, "386664706d5189ed43a622a2441b1fc2ba357e3de24da8fb0989612ea56ee1bb", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"386664706d5189ed43a622a2441b1fc2ba357e3de24da8fb0989612ea56ee1bb","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_list","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"","version_id":"","key_marker":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_id_marker":"Next+/=","page_limit":2,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":""}`},
	{"opaque_utf8_html", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_delete","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"data","version_id":"\u003c\u003e\u0026é東京","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`, "ba3d83e8f7fd88f09a70ff93aadf038c426c0bc9a990360b268c6867ccae0dbc", `{"contract":"open-trestle/artifact-erasure-attempt-request","schema_version":1,"identity":"ba3d83e8f7fd88f09a70ff93aadf038c426c0bc9a990360b268c6867ccae0dbc","reservation_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","namespace_identity":"84e499b15a0f75074752c2198e16d4dda8c26e9ed012b8208fe6e139c15fcc80","scope_identity":"4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa","artifact_identity":"cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","admission_identity":"968f125324a3a1a366b33a18cbc43de8cade268f6da30b767f20764d5694faa3","operation_identity":"c39fc99eff0a95c9e4a99aeda1270445e6981b333de43e6ca6bc3b52b0215050","original_authorization_identity":"86cf67bf5a7062f81cc8c167924565b6ea6b9bb20570c64303eacfad4966b992","authorization_document_digest":"6377dc73dcd32a6e1c192718df223cf6467fdf28581aeb7c554d6a5e8c74d7f8","allowance_identity":"66dfe09bdb27d6a71ab77331b1366f141b65dc8bf8579fbd620ce9b3b96e2a8c","allowance_document_digest":"0ac61aaf0260150d6d7bff31e797fceb7201eab045365369897474b83c4cbff5","protected_policy_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_bucket_owner":"123456789012","kind":"version_delete","key":"authorization-fixture/a_0-z/artifacts/4d780d90a7303af1d6b61fa73ef74d6245ebafaf310258374604257f896925aa/cee4062c8b5e132643652b7a71b972979c514e5203407bf8f890fa1b633fc4c5","version_kind":"data","version_id":"\u003c\u003e\u0026é東京","key_marker":"","version_id_marker":"","page_limit":0,"maximum_response_bytes":4096,"body_digest":"","body_bytes":0,"condition":"","observation_identity":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`},
}

type avAttemptMetaRequestAPI interface {
	Validate() error
	Identity() string
	ReservationIdentity() string
	NamespaceIdentity() string
	ScopeIdentity() string
	Scope() audit.ReviewScope
	ArtifactIdentity() string
	AdmissionIdentity() string
	OperationIdentity() string
	OriginalAuthorizationIdentity() string
	AuthorizationDocumentDigest() string
	AllowanceIdentity() string
	AllowanceDocumentDigest() string
	ProtectedPolicyIdentity() string
	ExpectedBucketOwner() string
	Kind() artifact.AttemptKind
	Key() string
	VersionKind() artifact.ObjectVersionKind
	VersionID() string
	KeyMarker() string
	VersionIDMarker() string
	PageLimit() uint16
	MaximumResponseBytes() uint32
	BodyDigest() string
	BodyBytes() uint32
	Condition() string
	ObservationIdentity() string
	String() string
	GoString() string
	fmt.Formatter
}

var _ avAttemptMetaRequestAPI = artifact.AttemptRequest{}
var _ avAttemptMetaRequestAPI = (*artifact.AttemptRequest)(nil)
var _ func(artifact.AttemptRequestOptions) (artifact.AttemptRequest, error) = artifact.NewAttemptRequest
var _ func([]byte, audit.ReviewScope) (artifact.AttemptRequest, error) = artifact.ParseAttemptRequest
var _ func(artifact.AttemptRequest) ([]byte, error) = artifact.EncodeAttemptRequest

func avAttemptMetaHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func avAttemptMetaQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func avAttemptMetaFields(t *testing.T, wire string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(wire), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func avAttemptMetaText(t *testing.T, fields map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	if err := json.Unmarshal(fields[key], &value); err != nil {
		t.Fatal(key, err)
	}
	return value
}

func avAttemptMetaNumber(t *testing.T, fields map[string]json.RawMessage, key string) uint64 {
	t.Helper()
	value, err := strconv.ParseUint(string(fields[key]), 10, 64)
	if err != nil {
		t.Fatal(key, err)
	}
	return value
}

func avAttemptMetaOrdered(t *testing.T, fields map[string]json.RawMessage, order []string, unsigned bool) string {
	t.Helper()
	members := make([]string, 0, len(order))
	for _, key := range order {
		if unsigned && key == "identity" {
			continue
		}
		value, ok := fields[key]
		if !ok {
			t.Fatal("missing literal member", key)
		}
		members = append(members, avAttemptMetaQuote(key)+":"+string(value))
	}
	return "{" + strings.Join(members, ",") + "}"
}

// Rehash ordered raw members without using a product codec.
func avAttemptMetaVariant(t *testing.T, wire string, order []string, domain string, changes map[string]string) string {
	t.Helper()
	fields := avAttemptMetaFields(t, wire)
	for key, value := range changes {
		if _, ok := fields[key]; !ok {
			t.Fatal("unknown literal member", key)
		}
		fields[key] = json.RawMessage(value)
	}
	fields["identity"] = json.RawMessage(avAttemptMetaQuote(avAttemptMetaHash(domain + avAttemptMetaOrdered(t, fields, order, true))))
	return avAttemptMetaOrdered(t, fields, order, false)
}

func avAttemptMetaRequestVariant(t *testing.T, index int, changes map[string]string) string {
	return avAttemptMetaVariant(t, avAttemptMetaRequestVectors[index].wire, avAttemptMetaRequestOrder, avAttemptMetaRequestContract+"/v1\x00", changes)
}

func avAttemptMetaScope(t *testing.T) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-auth", "repo-auth", "run-auth")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func avAttemptMetaDifferentScope(t *testing.T) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-other", "repo-auth", "run-auth")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func avAttemptMetaError(t *testing.T, got, want error) {
	t.Helper()
	if got != want {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func avAttemptMetaRequestStrings(value artifact.AttemptRequest) map[string]string {
	return map[string]string{
		"identity": value.Identity(), "reservation_identity": value.ReservationIdentity(),
		"namespace_identity": value.NamespaceIdentity(), "scope_identity": value.ScopeIdentity(),
		"artifact_identity": value.ArtifactIdentity(), "admission_identity": value.AdmissionIdentity(),
		"operation_identity": value.OperationIdentity(), "original_authorization_identity": value.OriginalAuthorizationIdentity(),
		"authorization_document_digest": value.AuthorizationDocumentDigest(), "allowance_identity": value.AllowanceIdentity(),
		"allowance_document_digest": value.AllowanceDocumentDigest(), "protected_policy_identity": value.ProtectedPolicyIdentity(),
		"expected_bucket_owner": value.ExpectedBucketOwner(), "key": value.Key(), "version_id": value.VersionID(),
		"key_marker": value.KeyMarker(), "version_id_marker": value.VersionIDMarker(), "body_digest": value.BodyDigest(),
		"condition": value.Condition(), "observation_identity": value.ObservationIdentity(),
	}
}

func avAttemptMetaZeroRequest(t *testing.T, value artifact.AttemptRequest) {
	t.Helper()
	if !reflect.DeepEqual(value, artifact.AttemptRequest{}) {
		t.Fatal("nonzero failed request")
	}
	avAttemptMetaError(t, value.Validate(), artifact.ErrInvalidErasureContract)
	for key, text := range avAttemptMetaRequestStrings(value) {
		if text != "" {
			t.Fatal("zero getter", key)
		}
	}
	if value.Kind() != 0 || value.VersionKind() != 0 || value.PageLimit() != 0 || value.MaximumResponseBytes() != 0 || value.BodyBytes() != 0 || value.Scope() != (audit.ReviewScope{}) || value.Scope().Validate() == nil {
		t.Fatal("nonzero scalar or scope")
	}
	encoded, err := artifact.EncodeAttemptRequest(value)
	avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
	if encoded != nil {
		t.Fatal("failed encode must return nil")
	}
}

func avAttemptMetaBadRequest(t *testing.T, wire []byte, scope audit.ReviewScope, want error) {
	t.Helper()
	value, err := artifact.ParseAttemptRequest(wire, scope)
	avAttemptMetaError(t, err, want)
	avAttemptMetaZeroRequest(t, value)
}

func avAttemptMetaBadNewRequest(t *testing.T, options artifact.AttemptRequestOptions, want error) {
	t.Helper()
	value, err := artifact.NewAttemptRequest(options)
	avAttemptMetaError(t, err, want)
	avAttemptMetaZeroRequest(t, value)
}

func avAttemptMetaParseRequest(t *testing.T, wire string, scope audit.ReviewScope) artifact.AttemptRequest {
	t.Helper()
	value, err := artifact.ParseAttemptRequest([]byte(wire), scope)
	if err != nil {
		t.Fatal("parse request", err)
	}
	avAttemptMetaError(t, value.Validate(), nil)
	encoded, err := artifact.EncodeAttemptRequest(value)
	if err != nil || string(encoded) != wire {
		t.Fatal("canonical request changed", err)
	}
	avAttemptMetaRequestGetters(t, value, wire, scope)
	return value
}

func avAttemptMetaRequestGetters(t *testing.T, value artifact.AttemptRequest, wire string, scope audit.ReviewScope) {
	t.Helper()
	fields := avAttemptMetaFields(t, wire)
	for key, got := range avAttemptMetaRequestStrings(value) {
		if got != avAttemptMetaText(t, fields, key) {
			t.Fatal("request getter", key)
		}
	}
	wantVersion := artifact.ObjectVersionKind(0)
	switch avAttemptMetaText(t, fields, "version_kind") {
	case "data":
		wantVersion = artifact.ObjectVersionData
	case "delete_marker":
		wantVersion = artifact.ObjectVersionDeleteMarker
	}
	if value.Scope() != scope || value.Scope().TenantID() != scope.TenantID() || value.Scope().RepositoryID() != scope.RepositoryID() || value.Scope().ReviewRunID() != scope.ReviewRunID() || value.Kind().String() != avAttemptMetaText(t, fields, "kind") || value.VersionKind() != wantVersion || uint64(value.PageLimit()) != avAttemptMetaNumber(t, fields, "page_limit") || uint64(value.MaximumResponseBytes()) != avAttemptMetaNumber(t, fields, "maximum_response_bytes") || uint64(value.BodyBytes()) != avAttemptMetaNumber(t, fields, "body_bytes") {
		t.Fatal("request scalar getter differs")
	}
}

func avAttemptMetaKey(t *testing.T, namespace, key string) artifact.ExactObjectKey {
	t.Helper()
	value, err := artifact.NewExactObjectKey(namespace, key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func avAttemptMetaVersion(t *testing.T, namespace, key string, kind artifact.ObjectVersionKind, id string) artifact.ObjectVersion {
	t.Helper()
	value, err := artifact.NewObjectVersion(namespace, key, kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func avAttemptMetaOptions(t *testing.T, index int) artifact.AttemptRequestOptions {
	t.Helper()
	operation, err := artifact.ParseErasureOperation([]byte(avAttemptMetaOperationJSON), avAttemptMetaScope(t))
	if err != nil {
		t.Fatal(err)
	}
	allowance, err := artifact.ParseResumeAllowance([]byte(avAttemptMetaAllowanceJSON), avAttemptMetaScope(t))
	if err != nil {
		t.Fatal(err)
	}
	f := avAttemptMetaFields(t, avAttemptMetaRequestVectors[index].wire)
	kind := artifact.AttemptKind(0)
	for candidate := artifact.AttemptKind(1); candidate <= 8; candidate++ {
		if candidate.String() == avAttemptMetaText(t, f, "kind") {
			kind = candidate
		}
	}
	options := artifact.AttemptRequestOptions{
		ReservationIdentity: avAttemptMetaText(t, f, "reservation_identity"), Operation: operation, Allowance: allowance,
		Kind: kind, Key: avAttemptMetaKey(t, operation.NamespaceIdentity(), avAttemptMetaText(t, f, "key")),
		Cursor:    artifact.VersionCursor{KeyMarker: avAttemptMetaText(t, f, "key_marker"), VersionIDMarker: avAttemptMetaText(t, f, "version_id_marker")},
		PageLimit: uint16(avAttemptMetaNumber(t, f, "page_limit")), MaximumResponseBytes: uint32(avAttemptMetaNumber(t, f, "maximum_response_bytes")),
		BodyDigest: avAttemptMetaText(t, f, "body_digest"), BodyBytes: uint32(avAttemptMetaNumber(t, f, "body_bytes")), ObservationIdentity: avAttemptMetaText(t, f, "observation_identity"),
	}
	if versionKind := avAttemptMetaText(t, f, "version_kind"); versionKind != "" {
		k := artifact.ObjectVersionData
		if versionKind == "delete_marker" {
			k = artifact.ObjectVersionDeleteMarker
		}
		options.Version = avAttemptMetaVersion(t, options.Key.NamespaceIdentity(), options.Key.Key(), k, avAttemptMetaText(t, f, "version_id"))
	}
	return options
}

func avAttemptMetaNewRequest(t *testing.T, options artifact.AttemptRequestOptions) artifact.AttemptRequest {
	t.Helper()
	value, err := artifact.NewAttemptRequest(options)
	if err != nil {
		t.Fatal("new request", err)
	}
	avAttemptMetaError(t, value.Validate(), nil)
	wire, err := artifact.EncodeAttemptRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	parsed := avAttemptMetaParseRequest(t, string(wire), options.Operation.Scope())
	if !reflect.DeepEqual(parsed, value) {
		t.Fatal("constructed and parsed metadata differ")
	}
	return value
}

func avAttemptMetaCheckLiteral(t *testing.T, domain, unsigned, identity, wire string, order []string) {
	t.Helper()
	if avAttemptMetaHash(domain+unsigned) != identity || strings.Replace(wire, `"identity":"`+identity+`",`, "", 1) != unsigned {
		t.Fatal("literal identity recipe")
	}
	if avAttemptMetaOrdered(t, avAttemptMetaFields(t, wire), order, true) != unsigned {
		t.Fatal("literal order")
	}
	emptyID := strings.Replace(wire, identity, "", 1)
	reordered := append([]string(nil), order...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	for _, preimage := range []string{
		unsigned, strings.TrimSuffix(domain, "\x00") + unsigned, strings.ReplaceAll(domain, "\x00", `\x00`) + unsigned,
		strings.Replace(domain, "/v1", "/v2", 1) + unsigned, domain + wire, domain + emptyID, domain + unsigned + "\n",
		domain + avAttemptMetaOrdered(t, avAttemptMetaFields(t, wire), reordered, true),
	} {
		if avAttemptMetaHash(preimage) == identity {
			t.Fatal("identity recipe is not discriminating")
		}
	}
}

func TestAttemptValuesEnumAndLiteralRequests(t *testing.T) {
	names := []string{"current_read", "intent_read", "attestation_read", "version_list", "intent_create", "fence_create", "version_delete", "attestation_create"}
	kinds := []artifact.AttemptKind{artifact.AttemptCurrentRead, artifact.AttemptIntentRead, artifact.AttemptAttestationRead, artifact.AttemptVersionList, artifact.AttemptIntentCreate, artifact.AttemptFenceCreate, artifact.AttemptVersionDelete, artifact.AttemptAttestationCreate}
	for index, kind := range kinds {
		if uint8(kind) != uint8(index+1) || kind.String() != names[index] {
			t.Fatal("enum changed", index)
		}
	}
	for n := 0; n <= 255; n++ {
		if n >= 1 && n <= 8 {
			continue
		}
		if artifact.AttemptKind(n).String() != "" {
			t.Fatal("unknown enum string", n)
		}
		options := avAttemptMetaOptions(t, 0)
		options.Kind = artifact.AttemptKind(n)
		avAttemptMetaBadNewRequest(t, options, artifact.ErrInvalidErasureContract)
	}
	if avAttemptMetaHash(avAttemptMetaScopeUnsigned) != avAttemptMetaScopeIdentity || avAttemptMetaScope(t).Identity() != avAttemptMetaScopeIdentity {
		t.Fatal("scope identity recipe changed")
	}
	for index, vector := range avAttemptMetaRequestVectors {
		t.Run(vector.name, func(t *testing.T) {
			avAttemptMetaCheckLiteral(t, avAttemptMetaRequestContract+"/v1\x00", vector.unsigned, vector.identity, vector.wire, avAttemptMetaRequestOrder)
			if avAttemptMetaHash(avAttemptMetaRequestContract+"/v1\x00"+strings.Replace(vector.unsigned, `,"condition":""`, "", 1)) == vector.identity && index < 4 {
				t.Fatal("optional omission not discriminated")
			}
			parsed := avAttemptMetaParseRequest(t, vector.wire, avAttemptMetaScope(t))
			value := avAttemptMetaNewRequest(t, avAttemptMetaOptions(t, index))
			if !reflect.DeepEqual(parsed, value) || value.Identity() != vector.identity {
				t.Fatal("constructor differs from literal")
			}
			encoded, err := artifact.EncodeAttemptRequest(value)
			if err != nil || string(encoded) != vector.wire {
				t.Fatal("constructor canonical bytes", err)
			}
		})
	}
}

func TestAttemptValuesSuppliedDependencies(t *testing.T) {
	options := avAttemptMetaOptions(t, 0)
	if options.Allowance.ProtectedDocumentDigest() != "" || options.Operation.ProtectedPolicyIdentity() == options.Allowance.ProtectedPolicyIdentity() {
		t.Fatal("fixture must have refreshed metadata policy without witness")
	}
	if avAttemptMetaHash(avAttemptMetaAllowanceUnsigned) == avAttemptMetaAllowanceIdentity || avAttemptMetaHash("open-trestle/artifact-erasure-resume-allowance/v1\x00"+avAttemptMetaAllowanceUnsigned) != avAttemptMetaAllowanceIdentity || avAttemptMetaHash(avAttemptMetaAllowanceJSON) != avAttemptMetaAllowanceDigest {
		t.Fatal("allowance literal digest")
	}
	encoded, err := artifact.EncodeResumeAllowance(options.Allowance)
	if err != nil || string(encoded) != avAttemptMetaAllowanceJSON {
		t.Fatal("allowance bytes changed", err)
	}
	value := avAttemptMetaNewRequest(t, options)
	if value.AllowanceDocumentDigest() != avAttemptMetaAllowanceDigest || value.ProtectedPolicyIdentity() != avAttemptMetaOther {
		t.Fatal("allowance projection")
	}
	constructed, err := artifact.NewResumeAllowance(artifact.ResumeAllowanceOptions{
		Operation: options.Operation, RecoveryPolicyIdentity: strings.Repeat("6", 64), ProtectedPolicyIdentity: avAttemptMetaOther,
		PrincipalIdentity: strings.Repeat("8", 64), IssuanceIdentity: strings.Repeat("a", 64), ExpectedBucketOwner: "123456789012",
		NotBefore: time.UnixMilli(1000).UTC(), NotAfter: time.UnixMilli(2000).UTC(), Maximum: artifact.ResumeBudget{Requests: 1},
	})
	if err != nil || constructed.ProtectedDocumentDigest() != "" {
		t.Fatal("metadata allowance constructor", err)
	}
	options.Allowance = constructed
	if avAttemptMetaNewRequest(t, options).Identity() != value.Identity() {
		t.Fatal("constructed allowance metadata differs")
	}
	for _, key := range []string{"namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "original_authorization_identity", "authorization_document_digest", "scope_identity"} {
		t.Run("lineage/"+key, func(t *testing.T) {
			scope := avAttemptMetaScope(t)
			changed := avAttemptMetaOther
			if key == "scope_identity" {
				scope = avAttemptMetaDifferentScope(t)
				changed = scope.Identity()
			}
			wire := avAttemptMetaVariant(t, avAttemptMetaAllowanceJSON, avAttemptMetaAllowanceOrder, "open-trestle/artifact-erasure-resume-allowance/v1\x00", map[string]string{key: avAttemptMetaQuote(changed)})
			allowance, err := artifact.ParseResumeAllowance([]byte(wire), scope)
			if err != nil || allowance.Validate() != nil {
				t.Fatal("individually valid allowance", err)
			}
			o := options
			o.Allowance = allowance
			avAttemptMetaBadNewRequest(t, o, artifact.ErrErasureBindingMismatch)
		})
	}
	operationWire := avAttemptMetaVariant(t, avAttemptMetaOperationJSON, avAttemptMetaOperationOrder, "open-trestle/artifact-erasure-operation/v2\x00", map[string]string{"prepared_at_milliseconds": "1001"})
	changedOperation, err := artifact.ParseErasureOperation([]byte(operationWire), avAttemptMetaScope(t))
	if err != nil {
		t.Fatal(err)
	}
	o := options
	o.Operation = changedOperation
	avAttemptMetaBadNewRequest(t, o, artifact.ErrErasureBindingMismatch)
	changedAllowanceWire := avAttemptMetaVariant(t, avAttemptMetaAllowanceJSON, avAttemptMetaAllowanceOrder, "open-trestle/artifact-erasure-resume-allowance/v1\x00", map[string]string{"issuance_identity": avAttemptMetaQuote(strings.Repeat("f", 64))})
	changedAllowance, err := artifact.ParseResumeAllowance([]byte(changedAllowanceWire), avAttemptMetaScope(t))
	if err != nil {
		t.Fatal(err)
	}
	o = options
	o.Allowance = changedAllowance
	changed := avAttemptMetaNewRequest(t, o)
	if changed.Identity() == value.Identity() || changed.AllowanceDocumentDigest() != avAttemptMetaHash(changedAllowanceWire) {
		t.Fatal("issuance sensitivity")
	}
	for _, change := range []func(*artifact.AttemptRequestOptions){
		func(o *artifact.AttemptRequestOptions) { o.Operation = artifact.ErasureOperation{} },
		func(o *artifact.AttemptRequestOptions) { o.Allowance = artifact.ResumeAllowance{} },
		func(o *artifact.AttemptRequestOptions) { o.Key = artifact.ExactObjectKey{} },
	} {
		o := options
		change(&o)
		avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
	}
	avAttemptMetaBadNewRequest(t, artifact.AttemptRequestOptions{}, artifact.ErrInvalidErasureContract)
}

func TestAttemptValuesIrrelevantFields(t *testing.T) {
	for index := 0; index < 8; index++ {
		t.Run(avAttemptMetaRequestVectors[index].name, func(t *testing.T) {
			options := avAttemptMetaOptions(t, index)
			create := index == 4 || index == 5 || index == 7
			irrelevant := map[string]string{}
			if index != 6 {
				irrelevant["version_kind"] = avAttemptMetaQuote("data")
				irrelevant["version_id"] = avAttemptMetaQuote("v")
			}
			if index != 3 {
				irrelevant["key_marker"] = avAttemptMetaQuote(options.Key.Key())
				irrelevant["version_id_marker"] = avAttemptMetaQuote("v")
				irrelevant["page_limit"] = "1"
			}
			if !create {
				irrelevant["body_digest"] = avAttemptMetaQuote(avAttemptMetaOther)
				irrelevant["body_bytes"] = "1"
				irrelevant["condition"] = avAttemptMetaQuote("if_none_match_star")
			}
			if index < 4 {
				irrelevant["observation_identity"] = avAttemptMetaQuote(avAttemptMetaOther)
			}
			for field, raw := range irrelevant {
				t.Run("parse/"+field, func(t *testing.T) {
					wire := avAttemptMetaRequestVariant(t, index, map[string]string{field: raw})
					avAttemptMetaBadRequest(t, []byte(wire), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
				})
				if field == "condition" || field == "version_id" {
					continue
				}
				t.Run("new/"+field, func(t *testing.T) {
					o := options
					switch field {
					case "version_kind":
						o.Version = avAttemptMetaVersion(t, o.Key.NamespaceIdentity(), o.Key.Key(), artifact.ObjectVersionData, "v")
					case "key_marker":
						o.Cursor.KeyMarker = o.Key.Key()
					case "version_id_marker":
						o.Cursor.VersionIDMarker = "v"
					case "page_limit":
						o.PageLimit = 1
					case "body_digest":
						o.BodyDigest = avAttemptMetaOther
					case "body_bytes":
						o.BodyBytes = 1
					case "observation_identity":
						o.ObservationIdentity = avAttemptMetaOther
					}
					avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
				})
			}
			if create {
				for _, condition := range []string{"", "if_match", "IF_NONE_MATCH_STAR", "if_none_match_star "} {
					avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{"condition": avAttemptMetaQuote(condition)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
				}
			}
		})
	}
	o := avAttemptMetaOptions(t, 6)
	o.Version = artifact.ObjectVersion{}
	avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
	for _, kind := range []string{"", "delete", "DATA", "null"} {
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 6, map[string]string{"version_kind": avAttemptMetaQuote(kind)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
	for _, kind := range []string{`""`, `"unknown"`, `"CURRENT_READ"`, `1`, `0`, `9`, `255`} {
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 0, map[string]string{"kind": kind})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
}

func TestAttemptValuesCreateCountsAndDigests(t *testing.T) {
	for _, index := range []int{4, 5} {
		t.Run(avAttemptMetaRequestVectors[index].name, func(t *testing.T) {
			o := avAttemptMetaOptions(t, index)
			body, err := artifact.EncodeErasureOperation(o.Operation)
			want := avAttemptMetaOperationJSON
			if index == 5 {
				fence, fenceErr := artifact.NewErasureFence(o.Operation)
				if fenceErr != nil {
					t.Fatal(fenceErr)
				}
				body, err = artifact.EncodeErasureFence(fence)
				want = avAttemptMetaFenceBytes
				if !bytes.HasPrefix(body, []byte("OTAF0001")) || o.BodyDigest == avAttemptMetaHash(strings.TrimPrefix(avAttemptMetaFenceBytes, "OTAF0001")) {
					t.Fatal("fence framing excluded from claim")
				}
			}
			if err != nil || string(body) != want || o.BodyBytes != uint32(len(want)) || o.BodyDigest != avAttemptMetaHash(want) {
				t.Fatal("actual body claim differs", err)
			}
			avAttemptMetaNewRequest(t, o)
			changed := o
			changed.BodyBytes++
			avAttemptMetaBadNewRequest(t, changed, artifact.ErrErasureBindingMismatch)
			changed = o
			changed.BodyDigest = avAttemptMetaOther
			avAttemptMetaBadNewRequest(t, changed, artifact.ErrErasureBindingMismatch)
			// Parsing has no operation or fence preimage.
			avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, index, map[string]string{"body_bytes": "1", "body_digest": avAttemptMetaQuote(avAttemptMetaOther)}), avAttemptMetaScope(t))
		})
	}
	for _, count := range []uint32{1, 16384} {
		o := avAttemptMetaOptions(t, 7)
		o.BodyBytes = count
		avAttemptMetaNewRequest(t, o)
		avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, 7, map[string]string{"body_bytes": strconv.FormatUint(uint64(count), 10)}), avAttemptMetaScope(t))
	}
	for _, index := range []int{4, 5, 7} {
		for _, count := range []uint32{0, 16385, ^uint32(0)} {
			o := avAttemptMetaOptions(t, index)
			o.BodyBytes = count
			avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{"body_bytes": strconv.FormatUint(uint64(count), 10)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		}
	}
}

func TestAttemptValuesResponseAndPageBounds(t *testing.T) {
	for index := 0; index < 8; index++ {
		maximum := uint32(4096)
		if index < 3 {
			maximum = 33554432
		}
		if index == 3 {
			maximum = 1048576
		}
		for _, n := range []uint32{4096, maximum} {
			o := avAttemptMetaOptions(t, index)
			o.MaximumResponseBytes = n
			avAttemptMetaNewRequest(t, o)
			avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, index, map[string]string{"maximum_response_bytes": strconv.FormatUint(uint64(n), 10)}), avAttemptMetaScope(t))
		}
		for _, n := range []uint32{0, 4095, maximum + 1, ^uint32(0)} {
			o := avAttemptMetaOptions(t, index)
			o.MaximumResponseBytes = n
			avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{"maximum_response_bytes": strconv.FormatUint(uint64(n), 10)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		}
	}
	for _, n := range []uint16{1, 2, 256} {
		o := avAttemptMetaOptions(t, 3)
		o.PageLimit = n
		avAttemptMetaNewRequest(t, o)
		avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, 3, map[string]string{"page_limit": strconv.FormatUint(uint64(n), 10)}), avAttemptMetaScope(t))
	}
	for _, n := range []uint16{0, 257, 65535} {
		o := avAttemptMetaOptions(t, 3)
		o.PageLimit = n
		avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 3, map[string]string{"page_limit": strconv.FormatUint(uint64(n), 10)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
}

func TestAttemptValuesDigestAndOwnerGrammar(t *testing.T) {
	malformed := []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("0", 64), " " + strings.Repeat("a", 63), strings.Repeat("a", 63) + "\n"}
	fields := []string{"reservation_identity", "namespace_identity", "scope_identity", "artifact_identity", "admission_identity", "operation_identity", "original_authorization_identity", "authorization_document_digest", "allowance_identity", "allowance_document_digest", "protected_policy_identity", "body_digest", "observation_identity"}
	for _, field := range fields {
		for index, text := range malformed {
			t.Run(field+"/"+strconv.Itoa(index), func(t *testing.T) {
				wire := avAttemptMetaRequestVariant(t, 7, map[string]string{field: avAttemptMetaQuote(text)})
				avAttemptMetaBadRequest(t, []byte(wire), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
			})
		}
	}
	for _, text := range malformed {
		for _, field := range []string{"reservation", "body", "observation"} {
			o := avAttemptMetaOptions(t, 7)
			switch field {
			case "reservation":
				o.ReservationIdentity = text
			case "body":
				o.BodyDigest = text
			case "observation":
				o.ObservationIdentity = text
			}
			avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
		}
		for _, index := range []int{4, 5, 6} {
			o := avAttemptMetaOptions(t, index)
			o.ObservationIdentity = text
			avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{"observation_identity": avAttemptMetaQuote(text)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
			if index != 6 {
				o = avAttemptMetaOptions(t, index)
				o.BodyDigest = text
				avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
				avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{"body_digest": avAttemptMetaQuote(text)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
			}
		}
	}
	for _, owner := range []string{"", "12345678901", "1234567890123", "12345678901a", "000000000000", "１２３４", " 23456789012"} {
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 0, map[string]string{"expected_bucket_owner": avAttemptMetaQuote(owner)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
	for _, owner := range []string{"000000000001", "999999999999"} {
		avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, 0, map[string]string{"expected_bucket_owner": avAttemptMetaQuote(owner)}), avAttemptMetaScope(t))
	}
}

func TestAttemptValuesKeyAndVersionConsistency(t *testing.T) {
	for _, key := range []string{"x", strings.Repeat("x", 1024), "different-prefix/a.intent-v2", "different-prefix/a.attestation-v2"} {
		o := avAttemptMetaOptions(t, 0)
		o.Key = avAttemptMetaKey(t, avAttemptMetaNamespaceIdentity, key)
		avAttemptMetaNewRequest(t, o)
		avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, 0, map[string]string{"key": avAttemptMetaQuote(key)}), avAttemptMetaScope(t))
	}
	for _, key := range []string{"", strings.Repeat("x", 1025), "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "A", "a\\b", "a%2fb", "a b", "a\nb", "a\x00b", "é", "a\t"} {
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 0, map[string]string{"key": avAttemptMetaQuote(key)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		keyValue, err := artifact.NewExactObjectKey(avAttemptMetaNamespaceIdentity, key)
		avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
		if !reflect.DeepEqual(keyValue, artifact.ExactObjectKey{}) {
			t.Fatal("bad key retained metadata")
		}
	}
	o := avAttemptMetaOptions(t, 0)
	o.Key = avAttemptMetaKey(t, avAttemptMetaOther, o.Key.Key())
	avAttemptMetaBadNewRequest(t, o, artifact.ErrErasureBindingMismatch)
	for _, changes := range []struct{ namespace, key string }{{avAttemptMetaOther, "same"}, {avAttemptMetaNamespaceIdentity, "different"}} {
		o := avAttemptMetaOptions(t, 6)
		key := o.Key.Key()
		if changes.key == "different" {
			key = "other/key"
		}
		o.Version = avAttemptMetaVersion(t, changes.namespace, key, artifact.ObjectVersionData, "v")
		avAttemptMetaBadNewRequest(t, o, artifact.ErrErasureBindingMismatch)
	}
	for _, id := range []string{"v", strings.Repeat("v", 504), strings.Repeat("é", 252), "<>&é東京", "NULL", "a+/=%"} {
		for _, kind := range []artifact.ObjectVersionKind{artifact.ObjectVersionData, artifact.ObjectVersionDeleteMarker} {
			o := avAttemptMetaOptions(t, 6)
			o.Version = avAttemptMetaVersion(t, avAttemptMetaNamespaceIdentity, o.Key.Key(), kind, id)
			avAttemptMetaNewRequest(t, o)
			wireKind := "data"
			if kind == artifact.ObjectVersionDeleteMarker {
				wireKind = "delete_marker"
			}
			avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, 6, map[string]string{"version_kind": avAttemptMetaQuote(wireKind), "version_id": avAttemptMetaQuote(id)}), avAttemptMetaScope(t))
		}
		o := avAttemptMetaOptions(t, 3)
		o.Cursor = artifact.VersionCursor{KeyMarker: o.Key.Key(), VersionIDMarker: id}
		avAttemptMetaNewRequest(t, o)
		avAttemptMetaParseRequest(t, avAttemptMetaRequestVariant(t, 3, map[string]string{"key_marker": avAttemptMetaQuote(o.Key.Key()), "version_id_marker": avAttemptMetaQuote(id)}), avAttemptMetaScope(t))
	}
	badIDs := []string{"", "null", strings.Repeat("v", 505), strings.Repeat("é", 252) + "x", "v v", "v\tv", "v\nv", "v\x00v", "v\u0085v", "v\u00a0v", "v\u2003v", string([]byte{0xff})}
	for _, id := range badIDs {
		version, err := artifact.NewObjectVersion(avAttemptMetaNamespaceIdentity, "key", artifact.ObjectVersionData, id)
		avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
		if !reflect.DeepEqual(version, artifact.ObjectVersion{}) {
			t.Fatal("bad version retained metadata")
		}
		if id != string([]byte{0xff}) {
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 6, map[string]string{"version_id": avAttemptMetaQuote(id)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 3, map[string]string{"key_marker": avAttemptMetaQuote(avAttemptMetaOptions(t, 3).Key.Key()), "version_id_marker": avAttemptMetaQuote(id)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		}
		o := avAttemptMetaOptions(t, 3)
		o.Cursor = artifact.VersionCursor{KeyMarker: o.Key.Key(), VersionIDMarker: id}
		avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
	}
	for _, cursor := range []artifact.VersionCursor{
		{KeyMarker: avAttemptMetaOptions(t, 3).Key.Key()}, {VersionIDMarker: "v"}, {KeyMarker: "sibling", VersionIDMarker: "v"},
		{KeyMarker: avAttemptMetaOptions(t, 3).Key.Key() + "x", VersionIDMarker: "v"},
	} {
		o := avAttemptMetaOptions(t, 3)
		o.Cursor = cursor
		avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 3, map[string]string{"key_marker": avAttemptMetaQuote(cursor.KeyMarker), "version_id_marker": avAttemptMetaQuote(cursor.VersionIDMarker)})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
}

// Exercise canonical rejection independently for every fixed member.
func avAttemptMetaStrictVariants(t *testing.T, wire string, order []string, reject func([]byte)) {
	t.Helper()
	fields := avAttemptMetaFields(t, wire)
	for _, key := range order {
		member := avAttemptMetaQuote(key) + ":" + string(fields[key])
		t.Run(key, func(t *testing.T) {
			reject([]byte(strings.Replace(wire, member, member+","+member, 1)))
			reject([]byte(strings.Replace(wire, avAttemptMetaQuote(key)+":", avAttemptMetaQuote(strings.ToUpper(key))+":", 1)))
			reject([]byte(strings.Replace(wire, member, avAttemptMetaQuote(key)+":null", 1)))
			missing := strings.Replace(wire, member+",", "", 1)
			if missing == wire {
				missing = strings.Replace(wire, ","+member, "", 1)
			}
			reject([]byte(missing))
			reject([]byte(strings.Replace(wire, avAttemptMetaQuote(key)+":", `"`+fmt.Sprintf(`\u%04x`, key[0])+key[1:]+`":`, 1)))
		})
	}
	reverse := append([]string(nil), order...)
	reverse[0], reverse[1] = reverse[1], reverse[0]
	for _, altered := range []string{
		avAttemptMetaOrdered(t, fields, reverse, false), " " + wire, wire + " ", wire + "\n", "\n" + wire, "\ufeff" + wire, wire + "x", wire + wire,
		strings.TrimSuffix(wire, "}") + `,"unknown":0}`, strings.Replace(wire, `"contract":`, `"Contract":`+string(fields["contract"])+`,"contract":`, 1),
		strings.Replace(wire, "open-trestle/", `open-trestle\/`, 1),
		strings.Replace(wire, `"schema_version":1`, `"schema_version":1.0`, 1),
		strings.Replace(wire, `"schema_version":1`, `"schema_version":1e0`, 1),
		strings.Replace(wire, `"schema_version":1`, `"schema_version":01`, 1),
		strings.Replace(wire, `"schema_version":1`, `"schema_version":+1`, 1),
		strings.Replace(wire, `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(wire, `"schema_version":1`, `"schema_version":"1"`, 1),
		strings.Replace(wire, "open-trestle/", "closed-trestle/", 1),
		strings.Replace(wire, `"contract":`, `"contract" :`, 1),
		strings.Replace(wire, "open-trestle", string([]byte{0xff}), 1),
	} {
		reject([]byte(altered))
	}
}

func TestAttemptValuesStrictRequestParser(t *testing.T) {
	scope := avAttemptMetaScope(t)
	for _, index := range []int{0, 3, 6, 7, 10} {
		t.Run(avAttemptMetaRequestVectors[index].name, func(t *testing.T) {
			avAttemptMetaStrictVariants(t, avAttemptMetaRequestVectors[index].wire, avAttemptMetaRequestOrder, func(wire []byte) { avAttemptMetaBadRequest(t, wire, scope, artifact.ErrInvalidErasureContract) })
		})
	}
	for _, field := range []string{"page_limit", "maximum_response_bytes", "body_bytes"} {
		for _, number := range []string{"-1", "-0", "0.0", "1e0", "01", "+1", `"1"`, "18446744073709551616", "4294967296"} {
			index := 3
			if field == "body_bytes" {
				index = 7
			}
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{field: number})), scope, artifact.ErrInvalidErasureContract)
		}
	}
	avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 3, map[string]string{"page_limit": "65536"})), scope, artifact.ErrInvalidErasureContract)
	html := avAttemptMetaRequestVectors[10].wire
	for _, wire := range []string{
		strings.Replace(html, `\u003c`, "<", 1), strings.Replace(html, `\u003e`, ">", 1), strings.Replace(html, `\u0026`, "&", 1),
		strings.Replace(html, `\u003c`, `\u003C`, 1), strings.Replace(html, "é", `\u00e9`, 1),
		strings.Replace(html, "é", string([]byte{0xc3}), 1), strings.Replace(html, "é", `\ud800`, 1),
	} {
		avAttemptMetaBadRequest(t, []byte(wire), scope, artifact.ErrInvalidErasureContract)
	}
	for _, identity := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		wire := strings.Replace(avAttemptMetaRequestVectors[0].wire, avAttemptMetaRequestVectors[0].identity, identity, 1)
		avAttemptMetaBadRequest(t, []byte(wire), scope, artifact.ErrInvalidErasureContract)
	}
	wrongIdentity := strings.Replace(avAttemptMetaRequestVectors[0].wire, avAttemptMetaRequestVectors[0].identity, avAttemptMetaOther, 1)
	avAttemptMetaBadRequest(t, []byte(wrongIdentity), scope, artifact.ErrErasureIdentityMismatch)
	malformedAndWrong := strings.Replace(wrongIdentity, `"page_limit":0`, `"page_limit":1`, 1)
	avAttemptMetaBadRequest(t, []byte(malformedAndWrong), avAttemptMetaDifferentScope(t), artifact.ErrInvalidErasureContract)
	avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVectors[0].wire), audit.ReviewScope{}, artifact.ErrInvalidErasureContract)
	avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVectors[0].wire), avAttemptMetaDifferentScope(t), artifact.ErrErasureIdentityMismatch)
}

func TestAttemptValuesOmittedDependenciesAreClaims(t *testing.T) {
	for field, text := range map[string]string{
		"allowance_document_digest": strings.Repeat("f", 64), "allowance_identity": strings.Repeat("f", 64),
		"protected_policy_identity": strings.Repeat("f", 64), "expected_bucket_owner": "000000000001",
		"key": "other-prefix/metadata-key", "observation_identity": strings.Repeat("f", 64),
		"body_digest": strings.Repeat("f", 64), "operation_identity": strings.Repeat("f", 64),
	} {
		t.Run(field, func(t *testing.T) {
			fresh := avAttemptMetaRequestVariant(t, 7, map[string]string{field: avAttemptMetaQuote(text)})
			parsed := avAttemptMetaParseRequest(t, fresh, avAttemptMetaScope(t))
			if parsed.Identity() == avAttemptMetaRequestVectors[7].identity {
				t.Fatal("claim change lost")
			}
			fields := avAttemptMetaFields(t, avAttemptMetaRequestVectors[7].wire)
			unchangedHash := strings.Replace(avAttemptMetaRequestVectors[7].wire, avAttemptMetaQuote(field)+":"+string(fields[field]), avAttemptMetaQuote(field)+":"+avAttemptMetaQuote(text), 1)
			avAttemptMetaBadRequest(t, []byte(unchangedHash), avAttemptMetaScope(t), artifact.ErrErasureIdentityMismatch)
		})
	}
}

func TestAttemptValuesRequestCopiesAndCaps(t *testing.T) {
	input := []byte(avAttemptMetaRequestVectors[9].wire)
	parsed, err := artifact.ParseAttemptRequest(input, avAttemptMetaScope(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] = 0xff
	}
	first, err := artifact.EncodeAttemptRequest(parsed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := artifact.EncodeAttemptRequest(parsed)
	if err != nil || string(second) != avAttemptMetaRequestVectors[9].wire {
		t.Fatal("parser retained input", err)
	}
	first[0] = '!'
	if string(second) != avAttemptMetaRequestVectors[9].wire {
		t.Fatal("encoder shares bytes")
	}
	third, err := artifact.EncodeAttemptRequest(parsed)
	if err != nil || !bytes.Equal(second, third) {
		t.Fatal("encoder mutation changed value", err)
	}
	options := avAttemptMetaOptions(t, 9)
	value := avAttemptMetaNewRequest(t, options)
	copied := value.Scope()
	options.Cursor.KeyMarker = "other"
	options.Cursor.VersionIDMarker = "other"
	options.MaximumResponseBytes = 1
	options.ReservationIdentity = avAttemptMetaOther
	options.Operation = artifact.ErasureOperation{}
	options.Allowance = artifact.ResumeAllowance{}
	copied = avAttemptMetaDifferentScope(t)
	if copied == value.Scope() {
		t.Fatal("scope fixture did not change")
	}
	encoded, err := artifact.EncodeAttemptRequest(value)
	if err != nil || string(encoded) != avAttemptMetaRequestVectors[9].wire {
		t.Fatal("options reassignment changed value", err)
	}
	for _, input := range [][]byte{nil, {}, bytes.Repeat([]byte{0xff}, 8192), bytes.Repeat([]byte{'{'}, 8193), bytes.Repeat([]byte{0xff}, 1<<20)} {
		avAttemptMetaBadRequest(t, input, avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		avAttemptMetaBadRequest(t, input, audit.ReviewScope{}, artifact.ErrInvalidErasureContract)
	}
	huge := strings.Repeat("x", 1<<20)
	for _, field := range []string{"reservation", "body", "observation", "key_marker", "version_marker"} {
		o := avAttemptMetaOptions(t, 7)
		if field == "key_marker" || field == "version_marker" {
			o = avAttemptMetaOptions(t, 3)
		}
		switch field {
		case "reservation":
			o.ReservationIdentity = huge
		case "body":
			o.BodyDigest = huge
		case "observation":
			o.ObservationIdentity = huge
		case "key_marker":
			o.Cursor.KeyMarker = huge
		case "version_marker":
			o.Cursor.KeyMarker = o.Key.Key()
			o.Cursor.VersionIDMarker = huge
		}
		avAttemptMetaBadNewRequest(t, o, artifact.ErrInvalidErasureContract)
	}
	avAttemptMetaZeroRequest(t, artifact.AttemptRequest{})
}

func avAttemptMetaFormatting(t *testing.T, value any, text, goText string) {
	t.Helper()
	for _, format := range []string{"%v", "%+v", "%s", "%x", "%d", "%f", "%1000000.1000000v", "%1000000.1000000s", "%+010x"} {
		if got := fmt.Sprintf(format, value); got != text {
			t.Fatalf("format %s produced %q", format, got)
		}
	}
	for _, row := range []struct{ format, want string }{
		{"%q", strconv.Quote(text)}, {"%1000000.1000000q", strconv.Quote(text)},
		{"%#v", goText}, {"%#1000000.1000000v", goText},
	} {
		if got := fmt.Sprintf(row.format, value); got != row.want {
			t.Fatalf("format %s produced %q", row.format, got)
		}
	}
}

func TestAttemptValuesRequestRedactionAndJSON(t *testing.T) {
	for _, value := range []artifact.AttemptRequest{{}, avAttemptMetaNewRequest(t, avAttemptMetaOptions(t, 7))} {
		if value.String() != "artifact erasure attempt request" || value.GoString() != "artifact.AttemptRequest{<redacted>}" {
			t.Fatal("request string constants")
		}
		avAttemptMetaFormatting(t, value, value.String(), value.GoString())
		avAttemptMetaFormatting(t, &value, value.String(), value.GoString())
	}
	for _, wire := range []string{`{}`, avAttemptMetaRequestVectors[7].wire} {
		var value artifact.AttemptRequest
		_ = json.Unmarshal([]byte(wire), &value)
		avAttemptMetaZeroRequest(t, value)
	}
	encoded, err := json.Marshal(avAttemptMetaNewRequest(t, avAttemptMetaOptions(t, 7)))
	if err != nil || string(encoded) != "{}" {
		t.Fatal("private metadata JSON exposure", err)
	}
	if artifact.ErrInvalidErasureContract.Error() != "invalid erasure contract" || artifact.ErrErasureIdentityMismatch.Error() != "erasure identity mismatch" || artifact.ErrErasureBindingMismatch.Error() != "erasure binding mismatch" {
		t.Fatal("fixed error strings")
	}
}

func TestAttemptValuesCanonicalZeroAndOptionalMembers(t *testing.T) {
	wire := avAttemptMetaRequestVectors[0].wire
	for _, field := range []string{"page_limit", "body_bytes"} {
		for _, token := range []string{"-0", "0.0", "0e0", `"0"`} {
			avAttemptMetaBadRequest(t, []byte(strings.Replace(wire, avAttemptMetaQuote(field)+":0", avAttemptMetaQuote(field)+":"+token, 1)), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		}
	}
	for _, field := range []string{"version_kind", "version_id", "key_marker", "version_id_marker", "body_digest", "condition", "observation_identity"} {
		if !strings.Contains(wire, avAttemptMetaQuote(field)+`:""`) {
			t.Fatal("optional empty field absent", field)
		}
		omitted := strings.Replace(avAttemptMetaRequestVectors[0].unsigned, ","+avAttemptMetaQuote(field)+`:""`, "", 1)
		if omitted == avAttemptMetaRequestVectors[0].unsigned || avAttemptMetaHash(avAttemptMetaRequestContract+"/v1\x00"+omitted) == avAttemptMetaRequestVectors[0].identity {
			t.Fatal("optional omission identity", field)
		}
	}
}

func TestAttemptValuesCreateUsesSuppliedOperationBytes(t *testing.T) {
	operationWire := avAttemptMetaVariant(t, avAttemptMetaOperationJSON, avAttemptMetaOperationOrder, "open-trestle/artifact-erasure-operation/v2\x00", map[string]string{"prepared_at_milliseconds": "10000"})
	operation, err := artifact.ParseErasureOperation([]byte(operationWire), avAttemptMetaScope(t))
	if err != nil {
		t.Fatal(err)
	}
	allowance, err := artifact.NewResumeAllowance(artifact.ResumeAllowanceOptions{
		Operation: operation, RecoveryPolicyIdentity: strings.Repeat("6", 64), ProtectedPolicyIdentity: avAttemptMetaOther,
		PrincipalIdentity: strings.Repeat("8", 64), IssuanceIdentity: strings.Repeat("a", 64), ExpectedBucketOwner: "123456789012",
		NotBefore: time.UnixMilli(1000).UTC(), NotAfter: time.UnixMilli(2000).UTC(), Maximum: artifact.ResumeBudget{Requests: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	fenceOrder := strings.Fields("contract schema_version identity erasure_protocol namespace_identity scope_identity artifact_identity operation_identity prepared_at_milliseconds")
	fenceWire := "OTAF0001" + avAttemptMetaVariant(t, strings.TrimPrefix(avAttemptMetaFenceBytes, "OTAF0001"), fenceOrder, "open-trestle/artifact-erasure-fence/v1\x00", map[string]string{"operation_identity": avAttemptMetaQuote(operation.Identity()), "prepared_at_milliseconds": "10000"})
	for _, index := range []int{4, 5} {
		o := avAttemptMetaOptions(t, index)
		o.Operation = operation
		o.Allowance = allowance
		avAttemptMetaBadNewRequest(t, o, artifact.ErrErasureBindingMismatch)
		want := operationWire
		actual, err := artifact.EncodeErasureOperation(operation)
		if index == 5 {
			want = fenceWire
			fence, fenceErr := artifact.NewErasureFence(operation)
			if fenceErr != nil {
				t.Fatal(fenceErr)
			}
			actual, err = artifact.EncodeErasureFence(fence)
		}
		if err != nil || string(actual) != want {
			t.Fatal("changed operation body bytes", err)
		}
		o.BodyBytes = uint32(len(want))
		o.BodyDigest = avAttemptMetaHash(want)
		value := avAttemptMetaNewRequest(t, o)
		if value.BodyDigest() != avAttemptMetaHash(want) || value.BodyBytes() != uint32(len(want)) {
			t.Fatal("supplied body projection")
		}
		changed := o
		changed.BodyDigest = avAttemptMetaOther
		avAttemptMetaBadNewRequest(t, changed, artifact.ErrErasureBindingMismatch)
		changed = o
		changed.BodyBytes--
		avAttemptMetaBadNewRequest(t, changed, artifact.ErrErasureBindingMismatch)
	}
}

func TestAttemptValuesExplicitScopeComponents(t *testing.T) {
	for _, component := range []string{"x", strings.Repeat("x", 128), "a-_.:0"} {
		scope, err := audit.NewReviewScope(component, component, component)
		if err != nil {
			t.Fatal(err)
		}
		wire := avAttemptMetaRequestVariant(t, 0, map[string]string{"scope_identity": avAttemptMetaQuote(scope.Identity())})
		value := avAttemptMetaParseRequest(t, wire, scope)
		if value.Scope().TenantID() != component || value.Scope().RepositoryID() != component || value.Scope().ReviewRunID() != component {
			t.Fatal("explicit full scope lost")
		}
		avAttemptMetaBadRequest(t, []byte(wire), avAttemptMetaScope(t), artifact.ErrErasureIdentityMismatch)
	}
	for _, component := range []string{"", strings.Repeat("x", 129), "X", "-x", "x-", "x y", "x/y", "é", "x\x00y"} {
		for index := 0; index < 3; index++ {
			parts := []string{"tenant-auth", "repo-auth", "run-auth"}
			parts[index] = component
			scope, err := audit.NewReviewScope(parts[0], parts[1], parts[2])
			if err == nil || scope.Validate() == nil {
				t.Fatal("invalid scope fixture accepted")
			}
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVectors[0].wire), scope, artifact.ErrInvalidErasureContract)
		}
	}
}

func TestAttemptValuesRequestTopLevelAndTypedWireRefusal(t *testing.T) {
	for _, wire := range []string{"null", "[]", "{}", "true", "0", `"request"`} {
		avAttemptMetaBadRequest(t, []byte(wire), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
	for _, raw := range []string{"0", "1", "2", "null", `"DATA"`, `"delete-marker"`} {
		avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, 6, map[string]string{"version_kind": raw})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
	}
	for _, field := range []string{"key", "version_id", "key_marker", "version_id_marker"} {
		index := 6
		if field == "key_marker" || field == "version_id_marker" {
			index = 9
		}
		for _, raw := range []string{"0", "[]", "{}", "false"} {
			avAttemptMetaBadRequest(t, []byte(avAttemptMetaRequestVariant(t, index, map[string]string{field: raw})), avAttemptMetaScope(t), artifact.ErrInvalidErasureContract)
		}
	}
}

func TestAttemptValuesRequestLengthGuardAllocations(t *testing.T) {
	scope := avAttemptMetaScope(t)
	for _, input := range [][]byte{nil, {}, bytes.Repeat([]byte{'{'}, 8193), bytes.Repeat([]byte{0xff}, 1<<20)} {
		var value artifact.AttemptRequest
		var err error
		// Count heap allocations only for already-owned inputs rejected by the length guard.
		allocations := testing.AllocsPerRun(5, func() { value, err = artifact.ParseAttemptRequest(input, scope) })
		avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
		avAttemptMetaZeroRequest(t, value)
		if allocations != 0 {
			t.Fatalf("length refusal allocated: %v", allocations)
		}
	}
}
