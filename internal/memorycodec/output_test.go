package memorycodec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
)

func codecFixture(t *testing.T, name string) map[string]artifact.Artifact {
	t.Helper()
	raw, err := os.ReadFile("../../handlers/memory/testdata/old-code-memory-" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var envelopes map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelopes); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]artifact.Artifact)
	for key, data := range envelopes {
		v, err := artifact.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		out[key] = v
	}
	return out
}
func TestLegacyOmissionReasonIsParserOnly(t *testing.T) {
	frozen := codecFixture(t, "zero-and-omitted")
	change, base, head := frozen["change"], frozen["base"], frozen["head"]
	value := frozen["memory"]
	var wire resultWire
	if err := json.Unmarshal(value.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Omissions) != 1 || wire.Omissions[0].Reason != "path_not_authorized" {
		t.Fatal("unexpected frozen shape")
	}
	wire.Omissions[0].Reason = "query_limit"
	r := fromWire(wire)
	wire.Identity = deriveIdentity(r)
	payload, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	modified, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), payload, value.CreatedAt(), value.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResultArtifact(modified, change, base, head)
	if err != nil {
		t.Fatalf("legacy parser tightened: %v", err)
	}
	changed, err := changecodec.ParseResultArtifact(change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeResult(parsed, changed)
	if err != nil || !bytes.Equal(encoded, payload) {
		t.Fatalf("historical encoder tightened: %v", err)
	}
	scope, err := parsed.MemoryScope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewResult(change, changed, parsed.PolicyIdentity(), parsed.RetrieverIdentity(), scope, parsed.AsOf(), parsed.Queries(), parsed.Omissions()); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("new producer accepted false omission authority")
	}
}
func TestCodecConstructorDeepOwnershipAndFormatting(t *testing.T) {
	frozen := codecFixture(t, "nonempty")
	value, change, base, head := frozen["memory"], frozen["change"], frozen["base"], frozen["head"]
	parsed, err := ParseResultArtifact(value, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := changecodec.ParseResultArtifact(change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := parsed.MemoryScope()
	if err != nil {
		t.Fatal(err)
	}
	queries := parsed.Queries()
	q := queries[0]
	retrieval, err := q.Retrieval(scope, parsed.AsOf())
	if err != nil {
		t.Fatal(err)
	}
	constructedQuery, err := NewQuery(scope, retrieval.Query(), retrieval)
	if err != nil {
		t.Fatal(err)
	}
	input := []Query{constructedQuery}
	result, err := NewResult(change, changed, parsed.PolicyIdentity(), parsed.RetrieverIdentity(), scope, parsed.AsOf(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := EncodeResult(result, changed)
	if err != nil {
		t.Fatal(err)
	}
	input[0].items[0].text = "corruption"
	input[0].items[0].evidenceIDs[0] = "corruption"
	got := result.Queries()
	got[0].items[0].text = "corruption"
	got[0].items[0].evidenceIDs[0] = "corruption"
	items := result.Queries()[0].Items()
	items[0].text = "corruption"
	items[0].evidenceIDs[0] = "corruption"
	after, err := EncodeResult(result, changed)
	if err != nil || !bytes.Equal(before, after) || !bytes.Equal(after, value.Payload()) {
		t.Fatal("constructor ownership or wire drift")
	}
	secret := result.Queries()[0].items[0].text
	for _, render := range []string{result.String(), result.GoString(), fmt.Sprintf("%v", result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result), fmt.Sprintf("%q", result)} {
		if secret != "" && bytes.Contains([]byte(render), []byte(secret)) {
			t.Fatal("formatter leaked text")
		}
	}
	forged := result.Queries()
	forged[0].items[0].text = "forged record"
	if _, err := NewResult(change, changed, parsed.PolicyIdentity(), parsed.RetrieverIdentity(), scope, parsed.AsOf(), forged, nil); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("forged record accepted")
	}
	if _, err := NewQuery(scope, retrieval.Query(), memorycore.LexicalRetrieval{}); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("zero retrieval accepted")
	}
	if b, err := EncodeResult(Result{}, changed); b != nil || !errors.Is(err, ErrInvalidResult) {
		t.Fatal("invalid encoder")
	}
}
