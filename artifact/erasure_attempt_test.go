package artifact_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

var avAttemptMetaAttemptOrder = strings.Fields("contract schema_version identity request_identity sequence reserved_at_milliseconds")

var avAttemptMetaAttemptVectors = []struct{ name, unsigned, identity, wire string }{
	{"current_read", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"328f6330284e5c6c1233382d1ef7be17c3bfce91d425b270466e98b34bce5833","sequence":1,"reserved_at_milliseconds":1}`, "45906510917683456d5a40e0e504dca1e3c1eef14721c504978970456dd85b06", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"45906510917683456d5a40e0e504dca1e3c1eef14721c504978970456dd85b06","request_identity":"328f6330284e5c6c1233382d1ef7be17c3bfce91d425b270466e98b34bce5833","sequence":1,"reserved_at_milliseconds":1}`},
	{"intent_read", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"0542544836a9d518deb3d00e574b32703134d34151b1fab0242c11f5bc98aed0","sequence":1,"reserved_at_milliseconds":1}`, "9c4efd2f6e66dfa715affe1ffc4abff2d558546f62c415b034f4a13e5de42b5e", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"9c4efd2f6e66dfa715affe1ffc4abff2d558546f62c415b034f4a13e5de42b5e","request_identity":"0542544836a9d518deb3d00e574b32703134d34151b1fab0242c11f5bc98aed0","sequence":1,"reserved_at_milliseconds":1}`},
	{"attestation_read", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"2474b8ca4400e4419ec00203c00b93788e049056e480c22595548bdb3a23bdca","sequence":1,"reserved_at_milliseconds":1}`, "53cb88e6eaea21bf79d2c0c1ff464facb35e744ca080a1e09b05da06d8ddc61f", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"53cb88e6eaea21bf79d2c0c1ff464facb35e744ca080a1e09b05da06d8ddc61f","request_identity":"2474b8ca4400e4419ec00203c00b93788e049056e480c22595548bdb3a23bdca","sequence":1,"reserved_at_milliseconds":1}`},
	{"version_list", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"2ef758aac8e195c5637b57f52b6a0d92ac4a2ccf8c94b3256d2211b99584d442","sequence":1,"reserved_at_milliseconds":1}`, "10432b182df7f45be63681d1a5a7277e36c32537ceecc4080e3df9a6074535ce", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"10432b182df7f45be63681d1a5a7277e36c32537ceecc4080e3df9a6074535ce","request_identity":"2ef758aac8e195c5637b57f52b6a0d92ac4a2ccf8c94b3256d2211b99584d442","sequence":1,"reserved_at_milliseconds":1}`},
	{"intent_create", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"409dca1fa266028430e3bae2fc32ad52e2918e61633990938247a316d18b7867","sequence":1,"reserved_at_milliseconds":1}`, "fa82c863d778b5998b07115b0cd0e79517c139d39fcc354ff4a86fe4549bb240", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"fa82c863d778b5998b07115b0cd0e79517c139d39fcc354ff4a86fe4549bb240","request_identity":"409dca1fa266028430e3bae2fc32ad52e2918e61633990938247a316d18b7867","sequence":1,"reserved_at_milliseconds":1}`},
	{"fence_create", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"589b3a9ae5856ac0eec14567d99ed87af345d6199a19820721fc04b59aa81747","sequence":1,"reserved_at_milliseconds":1}`, "eff8342fad5d8de90d7422e00af98692677103e9ab8366d9d920a4369999ed6d", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"eff8342fad5d8de90d7422e00af98692677103e9ab8366d9d920a4369999ed6d","request_identity":"589b3a9ae5856ac0eec14567d99ed87af345d6199a19820721fc04b59aa81747","sequence":1,"reserved_at_milliseconds":1}`},
	{"version_delete", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"465359c8cebaab354e6867767271f0177048fb69814783fc12cf6531b2b36303","sequence":1,"reserved_at_milliseconds":1}`, "3a90cfdd1bb6fc763fdb2037b4e2c38500dd3cfb5bb2cbd4ccb89c5621b71c0a", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"3a90cfdd1bb6fc763fdb2037b4e2c38500dd3cfb5bb2cbd4ccb89c5621b71c0a","request_identity":"465359c8cebaab354e6867767271f0177048fb69814783fc12cf6531b2b36303","sequence":1,"reserved_at_milliseconds":1}`},
	{"attestation_create", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"5684cc255fed1c08e3de921d9ac526b4cb37f0061989eb7632ede5d324accb50","sequence":1,"reserved_at_milliseconds":1}`, "e6917950f69ae2349da802766eeae7ff37cfcbc35017958c11d7721463f90f9b", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"e6917950f69ae2349da802766eeae7ff37cfcbc35017958c11d7721463f90f9b","request_identity":"5684cc255fed1c08e3de921d9ac526b4cb37f0061989eb7632ede5d324accb50","sequence":1,"reserved_at_milliseconds":1}`},
	{"delete_marker", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"8561b6536e0c55745de04c9942783595d356769986b5db53d9a62039a163baa4","sequence":1,"reserved_at_milliseconds":1}`, "03883aab7a40b8c6b163c5ad7129bfd674492b3197949fdc02649a2aecf217c7", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"03883aab7a40b8c6b163c5ad7129bfd674492b3197949fdc02649a2aecf217c7","request_identity":"8561b6536e0c55745de04c9942783595d356769986b5db53d9a62039a163baa4","sequence":1,"reserved_at_milliseconds":1}`},
	{"continuation", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"386664706d5189ed43a622a2441b1fc2ba357e3de24da8fb0989612ea56ee1bb","sequence":1,"reserved_at_milliseconds":1}`, "583be2e9cc2818fe0b779b4a0403428c562a7dc7160563432dadac53af6cd42d", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"583be2e9cc2818fe0b779b4a0403428c562a7dc7160563432dadac53af6cd42d","request_identity":"386664706d5189ed43a622a2441b1fc2ba357e3de24da8fb0989612ea56ee1bb","sequence":1,"reserved_at_milliseconds":1}`},
	{"opaque_utf8_html", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"request_identity":"ba3d83e8f7fd88f09a70ff93aadf038c426c0bc9a990360b268c6867ccae0dbc","sequence":1,"reserved_at_milliseconds":1}`, "4f50c0630a18406591cc32c802ce872dfa8b14ff040ee1b5a1a178176f901776", `{"contract":"open-trestle/artifact-erasure-attempt","schema_version":1,"identity":"4f50c0630a18406591cc32c802ce872dfa8b14ff040ee1b5a1a178176f901776","request_identity":"ba3d83e8f7fd88f09a70ff93aadf038c426c0bc9a990360b268c6867ccae0dbc","sequence":1,"reserved_at_milliseconds":1}`},
}

type avAttemptMetaAttemptAPI interface {
	Validate() error
	Identity() string
	Request() artifact.AttemptRequest
	Sequence() uint64
	ReservedAt() time.Time
	String() string
	GoString() string
	fmt.Formatter
}

var _ avAttemptMetaAttemptAPI = artifact.ErasureAttempt{}
var _ avAttemptMetaAttemptAPI = (*artifact.ErasureAttempt)(nil)
var _ func(artifact.AttemptRequest, uint64, time.Time) (artifact.ErasureAttempt, error) = artifact.NewErasureAttempt
var _ func([]byte, artifact.AttemptRequest) (artifact.ErasureAttempt, error) = artifact.ParseErasureAttempt
var _ func(artifact.ErasureAttempt) ([]byte, error) = artifact.EncodeErasureAttempt

func avAttemptMetaAttemptVariant(t *testing.T, index int, changes map[string]string) string {
	return avAttemptMetaVariant(t, avAttemptMetaAttemptVectors[index].wire, avAttemptMetaAttemptOrder, avAttemptMetaAttemptContract+"/v1\x00", changes)
}

func avAttemptMetaZeroAttempt(t *testing.T, value artifact.ErasureAttempt) {
	t.Helper()
	if !reflect.DeepEqual(value, artifact.ErasureAttempt{}) || value.Identity() != "" || value.Sequence() != 0 || value.ReservedAt() != (time.Time{}) {
		t.Fatal("nonzero failed attempt")
	}
	avAttemptMetaError(t, value.Validate(), artifact.ErrInvalidErasureContract)
	avAttemptMetaZeroRequest(t, value.Request())
	encoded, err := artifact.EncodeErasureAttempt(value)
	avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
	if encoded != nil {
		t.Fatal("failed attempt encode must return nil")
	}
}

func avAttemptMetaBadAttempt(t *testing.T, wire []byte, request artifact.AttemptRequest, want error) {
	t.Helper()
	value, err := artifact.ParseErasureAttempt(wire, request)
	avAttemptMetaError(t, err, want)
	avAttemptMetaZeroAttempt(t, value)
}

func avAttemptMetaBadNewAttempt(t *testing.T, request artifact.AttemptRequest, sequence uint64, at time.Time) {
	t.Helper()
	value, err := artifact.NewErasureAttempt(request, sequence, at)
	avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
	avAttemptMetaZeroAttempt(t, value)
}

func avAttemptMetaAttemptGetters(t *testing.T, value artifact.ErasureAttempt, request artifact.AttemptRequest, wire string) {
	t.Helper()
	fields := avAttemptMetaFields(t, wire)
	if value.Identity() != avAttemptMetaText(t, fields, "identity") || value.Request().Identity() != avAttemptMetaText(t, fields, "request_identity") || !reflect.DeepEqual(value.Request(), request) || value.Sequence() != avAttemptMetaNumber(t, fields, "sequence") || value.ReservedAt() != time.UnixMilli(int64(avAttemptMetaNumber(t, fields, "reserved_at_milliseconds"))).UTC() || value.ReservedAt().Location() != time.UTC {
		t.Fatal("attempt getter differs")
	}
}

func avAttemptMetaParseAttempt(t *testing.T, wire string, request artifact.AttemptRequest) artifact.ErasureAttempt {
	t.Helper()
	value, err := artifact.ParseErasureAttempt([]byte(wire), request)
	if err != nil {
		t.Fatal("parse attempt", err)
	}
	avAttemptMetaError(t, value.Validate(), nil)
	encoded, err := artifact.EncodeErasureAttempt(value)
	if err != nil || string(encoded) != wire {
		t.Fatal("canonical attempt changed", err)
	}
	avAttemptMetaAttemptGetters(t, value, request, wire)
	return value
}

func avAttemptMetaNewAttempt(t *testing.T, request artifact.AttemptRequest, sequence uint64, at time.Time) artifact.ErasureAttempt {
	t.Helper()
	value, err := artifact.NewErasureAttempt(request, sequence, at)
	if err != nil {
		t.Fatal("new attempt", err)
	}
	avAttemptMetaError(t, value.Validate(), nil)
	wire, err := artifact.EncodeErasureAttempt(value)
	if err != nil {
		t.Fatal(err)
	}
	parsed := avAttemptMetaParseAttempt(t, string(wire), request)
	if !reflect.DeepEqual(parsed, value) || value.Sequence() != sequence || value.ReservedAt() != at.UTC() {
		t.Fatal("attempt constructor projection differs")
	}
	return value
}

func TestAttemptValuesLiteralAttempts(t *testing.T) {
	if len(avAttemptMetaAttemptVectors) != len(avAttemptMetaRequestVectors) {
		t.Fatal("unpaired literal vector")
	}
	for index, vector := range avAttemptMetaAttemptVectors {
		t.Run(vector.name, func(t *testing.T) {
			if vector.name != avAttemptMetaRequestVectors[index].name {
				t.Fatal("paired vector name")
			}
			avAttemptMetaCheckLiteral(t, avAttemptMetaAttemptContract+"/v1\x00", vector.unsigned, vector.identity, vector.wire, avAttemptMetaAttemptOrder)
			request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[index].wire, avAttemptMetaScope(t))
			parsed := avAttemptMetaParseAttempt(t, vector.wire, request)
			value := avAttemptMetaNewAttempt(t, request, 1, time.UnixMilli(1).UTC())
			if value.Identity() != vector.identity || !reflect.DeepEqual(parsed, value) {
				t.Fatal("constructor differs from literal attempt")
			}
			encoded, err := artifact.EncodeErasureAttempt(value)
			if err != nil || string(encoded) != vector.wire {
				t.Fatal("literal attempt bytes", err)
			}
		})
	}
}

func TestAttemptValuesSequenceAndTimeBounds(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[0].wire, avAttemptMetaScope(t))
	for _, sequence := range []uint64{1, 4096} {
		for _, milliseconds := range []int64{1, 1000, 253402300799999} {
			at := time.UnixMilli(milliseconds).UTC()
			value := avAttemptMetaNewAttempt(t, request, sequence, at)
			wire := avAttemptMetaAttemptVariant(t, 0, map[string]string{"sequence": strconv.FormatUint(sequence, 10), "reserved_at_milliseconds": strconv.FormatInt(milliseconds, 10)})
			if value.Identity() != avAttemptMetaParseAttempt(t, wire, request).Identity() {
				t.Fatal("time/sequence identity")
			}
			if avAttemptMetaNewAttempt(t, request, sequence, at).Identity() != value.Identity() {
				t.Fatal("metadata is not deterministic")
			}
		}
	}
	named := time.Date(1970, time.January, 1, 0, 0, 0, int(time.Millisecond), time.FixedZone("named-zero", 0))
	value := avAttemptMetaNewAttempt(t, request, 1, named)
	if value.ReservedAt().Location() != time.UTC || value.Identity() != avAttemptMetaAttemptVectors[0].identity {
		t.Fatal("zero-offset zone not normalized to UTC")
	}
	for _, sequence := range []uint64{0, 4097, ^uint64(0)} {
		avAttemptMetaBadNewAttempt(t, request, sequence, time.UnixMilli(1).UTC())
	}
	for _, at := range []time.Time{
		{}, time.UnixMilli(0).UTC(), time.UnixMilli(-1).UTC(), time.Date(1969, time.December, 31, 0, 0, 0, 0, time.UTC),
		time.Unix(0, 1).UTC(), time.Unix(0, 1000001).UTC(), time.Unix(1, 999999999).UTC(),
		time.UnixMilli(1000).In(time.FixedZone("plus-one", 1)), time.UnixMilli(1000).In(time.FixedZone("minus-hour", -3600)),
		time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(1000000000, time.January, 1, 0, 0, 0, 0, time.UTC),
		time.Unix(1<<62, 0).UTC(), time.Unix(-(1 << 62), 0).UTC(), time.UnixMilli(1<<63 - 1).UTC(),
	} {
		avAttemptMetaBadNewAttempt(t, request, 1, at)
	}
	avAttemptMetaBadNewAttempt(t, artifact.AttemptRequest{}, 1, time.UnixMilli(1).UTC())
	for _, sequence := range []string{"0", "4097", "18446744073709551615", "18446744073709551616", "-1", "-0", "1.0", "1e0", "01", "+1", `"1"`} {
		avAttemptMetaBadAttempt(t, []byte(avAttemptMetaAttemptVariant(t, 0, map[string]string{"sequence": sequence})), request, artifact.ErrInvalidErasureContract)
	}
	for _, milliseconds := range []string{"0", "-1", "253402300800000", "9223372036854775807", "9223372036854775808", "18446744073709551615", "-9223372036854775809", "1.0", "1e0", "01", "+1", `"1"`} {
		avAttemptMetaBadAttempt(t, []byte(avAttemptMetaAttemptVariant(t, 0, map[string]string{"reserved_at_milliseconds": milliseconds})), request, artifact.ErrInvalidErasureContract)
	}
}

func TestAttemptValuesIdentitySensitivity(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[0].wire, avAttemptMetaScope(t))
	baseline := avAttemptMetaNewAttempt(t, request, 1, time.UnixMilli(1).UTC())
	changedSequence := avAttemptMetaNewAttempt(t, request, 2, time.UnixMilli(1).UTC())
	changedTime := avAttemptMetaNewAttempt(t, request, 1, time.UnixMilli(2).UTC())
	if baseline.Identity() == changedSequence.Identity() || baseline.Identity() == changedTime.Identity() || changedSequence.Identity() == changedTime.Identity() || changedSequence.Request().Identity() != request.Identity() || changedTime.Request().Identity() != request.Identity() {
		t.Fatal("attempt identity sensitivity")
	}
	options := avAttemptMetaOptions(t, 0)
	options.ReservationIdentity = strings.Repeat("f", 64)
	changedRequest := avAttemptMetaNewRequest(t, options)
	changedAttempt := avAttemptMetaNewAttempt(t, changedRequest, 1, time.UnixMilli(1).UTC())
	if changedRequest.Identity() == request.Identity() || changedAttempt.Identity() == baseline.Identity() {
		t.Fatal("reservation identity sensitivity")
	}
	// Metadata has no allowance-window or next-sequence input.
	avAttemptMetaNewAttempt(t, request, 4096, time.UnixMilli(253402300799999).UTC())
	avAttemptMetaNewAttempt(t, request, 4096, time.UnixMilli(1).UTC())
}

func TestAttemptValuesStrictAttemptParserAndBinding(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[0].wire, avAttemptMetaScope(t))
	avAttemptMetaStrictVariants(t, avAttemptMetaAttemptVectors[0].wire, avAttemptMetaAttemptOrder, func(wire []byte) { avAttemptMetaBadAttempt(t, wire, request, artifact.ErrInvalidErasureContract) })
	other := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[1].wire, avAttemptMetaScope(t))
	avAttemptMetaBadAttempt(t, []byte(avAttemptMetaAttemptVectors[0].wire), other, artifact.ErrErasureIdentityMismatch)
	avAttemptMetaBadAttempt(t, []byte(avAttemptMetaAttemptVectors[0].wire), artifact.AttemptRequest{}, artifact.ErrInvalidErasureContract)
	rehashed := avAttemptMetaAttemptVariant(t, 0, map[string]string{"request_identity": avAttemptMetaQuote(other.Identity())})
	avAttemptMetaBadAttempt(t, []byte(rehashed), request, artifact.ErrErasureIdentityMismatch)
	avAttemptMetaParseAttempt(t, rehashed, other)
	for _, field := range []string{"identity", "request_identity"} {
		for _, id := range []string{"", strings.Repeat("0", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
			wire := avAttemptMetaAttemptVariant(t, 0, map[string]string{"request_identity": avAttemptMetaQuote(id)})
			if field == "identity" {
				wire = strings.Replace(avAttemptMetaAttemptVectors[0].wire, avAttemptMetaAttemptVectors[0].identity, id, 1)
			}
			avAttemptMetaBadAttempt(t, []byte(wire), request, artifact.ErrInvalidErasureContract)
		}
	}
	wrongIdentity := strings.Replace(avAttemptMetaAttemptVectors[0].wire, avAttemptMetaAttemptVectors[0].identity, avAttemptMetaOther, 1)
	avAttemptMetaBadAttempt(t, []byte(wrongIdentity), request, artifact.ErrErasureIdentityMismatch)
	unboundHash := strings.Replace(avAttemptMetaAttemptVectors[0].wire, request.Identity(), other.Identity(), 1)
	avAttemptMetaBadAttempt(t, []byte(unboundHash), request, artifact.ErrErasureIdentityMismatch)
	malformed := strings.Replace(wrongIdentity, `"sequence":1`, `"sequence":0`, 1)
	avAttemptMetaBadAttempt(t, []byte(malformed), other, artifact.ErrInvalidErasureContract)
	equivalent := avAttemptMetaNewRequest(t, avAttemptMetaOptions(t, 0))
	avAttemptMetaParseAttempt(t, avAttemptMetaAttemptVectors[0].wire, equivalent)
}

func TestAttemptValuesAttemptCopiesCapsAndZero(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[10].wire, avAttemptMetaScope(t))
	input := []byte(avAttemptMetaAttemptVectors[10].wire)
	value, err := artifact.ParseErasureAttempt(input, request)
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] = 0xff
	}
	first, err := artifact.EncodeErasureAttempt(value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := artifact.EncodeErasureAttempt(value)
	if err != nil || string(second) != avAttemptMetaAttemptVectors[10].wire {
		t.Fatal("attempt retained parse input", err)
	}
	first[0] = '!'
	third, err := artifact.EncodeErasureAttempt(value)
	if err != nil || !bytes.Equal(second, third) || string(second) != avAttemptMetaAttemptVectors[10].wire {
		t.Fatal("attempt encoded bytes alias", err)
	}
	copied := value.Request()
	copied = artifact.AttemptRequest{}
	request = artifact.AttemptRequest{}
	if copied.Validate() == nil || request.Validate() == nil || value.Request().Identity() != avAttemptMetaRequestVectors[10].identity {
		t.Fatal("attempt request value copy")
	}
	avAttemptMetaRequestGetters(t, value.Request(), avAttemptMetaRequestVectors[10].wire, avAttemptMetaScope(t))
	validRequest := value.Request()
	sequence := uint64(1)
	at := time.UnixMilli(1).UTC()
	created := avAttemptMetaNewAttempt(t, validRequest, sequence, at)
	sequence = 2
	at = time.UnixMilli(2).UTC()
	validRequest = artifact.AttemptRequest{}
	if created.Sequence() == sequence || created.ReservedAt() == at || created.Request().Validate() != nil {
		t.Fatal("constructor retains caller variables")
	}
	for _, input := range [][]byte{nil, {}, bytes.Repeat([]byte{0xff}, 1024), bytes.Repeat([]byte{'{'}, 1025), bytes.Repeat([]byte{0xff}, 1<<20)} {
		avAttemptMetaBadAttempt(t, input, value.Request(), artifact.ErrInvalidErasureContract)
		avAttemptMetaBadAttempt(t, input, artifact.AttemptRequest{}, artifact.ErrInvalidErasureContract)
	}
	avAttemptMetaZeroAttempt(t, artifact.ErasureAttempt{})
}

func TestAttemptValuesAttemptRedactionAndJSON(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[10].wire, avAttemptMetaScope(t))
	for _, value := range []artifact.ErasureAttempt{{}, avAttemptMetaNewAttempt(t, request, 1, time.UnixMilli(1).UTC())} {
		if value.String() != "artifact erasure attempt" || value.GoString() != "artifact.ErasureAttempt{<redacted>}" {
			t.Fatal("attempt string constants")
		}
		avAttemptMetaFormatting(t, value, value.String(), value.GoString())
		avAttemptMetaFormatting(t, &value, value.String(), value.GoString())
	}
	for _, wire := range []string{`{}`, avAttemptMetaAttemptVectors[10].wire} {
		var value artifact.ErasureAttempt
		_ = json.Unmarshal([]byte(wire), &value)
		avAttemptMetaZeroAttempt(t, value)
	}
	encoded, err := json.Marshal(avAttemptMetaNewAttempt(t, request, 1, time.UnixMilli(1).UTC()))
	if err != nil || string(encoded) != "{}" {
		t.Fatal("attempt private JSON exposure", err)
	}
}

func TestAttemptValuesAttemptTopLevelRefusal(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[0].wire, avAttemptMetaScope(t))
	for _, wire := range []string{"null", "[]", "{}", "true", "0", `"attempt"`} {
		avAttemptMetaBadAttempt(t, []byte(wire), request, artifact.ErrInvalidErasureContract)
	}
}

func TestAttemptValuesAttemptLengthGuardAllocations(t *testing.T) {
	request := avAttemptMetaParseRequest(t, avAttemptMetaRequestVectors[0].wire, avAttemptMetaScope(t))
	for _, input := range [][]byte{nil, {}, bytes.Repeat([]byte{'{'}, 1025), bytes.Repeat([]byte{0xff}, 1<<20)} {
		var value artifact.ErasureAttempt
		var err error
		// Count heap allocations only for already-owned inputs rejected by the length guard.
		allocations := testing.AllocsPerRun(5, func() { value, err = artifact.ParseErasureAttempt(input, request) })
		avAttemptMetaError(t, err, artifact.ErrInvalidErasureContract)
		avAttemptMetaZeroAttempt(t, value)
		if allocations != 0 {
			t.Fatalf("length refusal allocated: %v", allocations)
		}
	}
}
