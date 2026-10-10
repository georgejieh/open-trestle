package memory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
)

// These envelopes were captured from the unmodified v1 Handler.Execute producer at
// 3ad095e7b71a39c02412ee6fcea87b68cf97fef0. They are not synthetic parser output.
type oldMemoryGolden struct {
	name, payloadDigest, resultIdentity, artifactIdentity          string
	paths, prefixes                                                []string
	withRecord                                                     bool
	validUntil, expiresAt                                          int64
	queries, omissions                                             int
	queryIdentity, retrievalIdentity, itemIdentity, recordIdentity string
}

var oldMemoryGoldens = []oldMemoryGolden{
	// Captured identities below are literal checks independent of current constructors.
	{name: "nonempty", queryIdentity: "c53438d60eb1df95bb9523120744a82999a0b7c40a467d451a0fc6ce423ed22a", retrievalIdentity: "dd230dc2ff0a549088749db8ad0df6289b2f7370562a2fb7d98036aeb20d1027", itemIdentity: "ea3bcf94d59cf227a4db0f334cf70024b5a4b502e844912fd5c12c2afb69e795", recordIdentity: "733b0447b90913fa5535ac429aa581e8ec7d27a709cf589d400d58a5b6f72b52", payloadDigest: "c2c484b43eb82a44cb04605a5cd8e60276d3008ee63b755915631356e46797c5", resultIdentity: "1703d76d4220d346c37690d432c56693862a310ca4dab63009d7321893bdbeef", artifactIdentity: "d48df0151a0fbbd2730f6b8b829d64ef975f6f957b0ea1165df8f2d365de58af", paths: []string{"a.txt"}, prefixes: []string{"."}, withRecord: true, validUntil: 700, expiresAt: 700, queries: 1, omissions: 0},
	{name: "zero-and-omitted", queryIdentity: "2330e5be88b476bb5c728025d7346cd3665116f708e2197b267a6df7b9ca92aa", retrievalIdentity: "bffd91947b3bfd1187de6d011b41c7bb5661ad4643b49f004ff212e73498ee20", payloadDigest: "83ec0f297fdea6f414f80ae4e2f5bad2631a22cfe9b1fa183af45997b6050177", resultIdentity: "a28af51f9220a57d55fafeb76ed0a95808b5215c7cf49e619ee1a465a4689ba1", artifactIdentity: "d7c03dae099906ed22a54bf04a9153e09f98a86e69449ebd45591fe07414428e", paths: []string{"a.txt", "b.txt"}, prefixes: []string{"a.txt"}, withRecord: false, validUntil: 0, expiresAt: 10000, queries: 1, omissions: 1},
	{name: "all-omitted", payloadDigest: "9566f13eaa80ad7ffe155d8275f670635132f8b54586ee160786a76237aff9b6", resultIdentity: "bc3f0583ec35ef00a2ba4ca1432a046339bb070466dcbba55921d800905e6cdc", artifactIdentity: "74fd05b38f46db2a915a22b4f0bfd056ea9e83e8c8a3697e225b942f64f79404", paths: []string{"b.txt"}, prefixes: []string{"a.txt"}, withRecord: false, validUntil: 0, expiresAt: 10000, queries: 0, omissions: 1},
}

func loadOldMemoryGolden(t *testing.T, name string) map[string]artifact.Artifact {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", "old-code-memory-"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 {
		t.Fatalf("%s: want exactly four artifact envelopes, got %d", name, len(raw))
	}
	result := make(map[string]artifact.Artifact, 4)
	for _, key := range []string{"base", "head", "change", "memory"} {
		value, err := artifact.Parse(raw[key])
		if err != nil {
			t.Fatalf("%s/%s: %v", name, key, err)
		}
		result[key] = value
	}
	return result
}

func TestOldCodeMemoryProducerGoldens(t *testing.T) {
	for _, want := range oldMemoryGoldens {
		t.Run(want.name, func(t *testing.T) {
			frozen := loadOldMemoryGolden(t, want.name)
			live := runMemoryProducerFixture(t, want.paths, want.prefixes, want.withRecord, want.validUntil)
			actual := map[string]artifact.Artifact{"base": live.base, "head": live.head, "change": live.change, "memory": live.output}
			for _, key := range []string{"base", "head", "change", "memory"} {
				liveBytes, err := artifact.Encode(actual[key])
				if err != nil {
					t.Fatal(err)
				}
				frozenBytes, err := artifact.Encode(frozen[key])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(liveBytes, frozenBytes) {
					t.Fatalf("%s envelope drift: live=%s frozen=%s", key, liveBytes, frozenBytes)
				}
				if !bytes.Equal(actual[key].Payload(), frozen[key].Payload()) {
					t.Fatalf("%s payload drift", key)
				}
			}
			output := actual["memory"]
			digest := sha256.Sum256(output.Payload())
			if got := hex.EncodeToString(digest[:]); got != want.payloadDigest || output.PayloadDigest() != want.payloadDigest {
				t.Fatalf("payload digest=%s stored=%s want=%s", got, output.PayloadDigest(), want.payloadDigest)
			}
			if output.Identity() != want.artifactIdentity || output.ExpiresAt().UnixMilli() != want.expiresAt {
				t.Fatalf("artifact=%s expiry=%d want=%s expiry=%d", output.Identity(), output.ExpiresAt().UnixMilli(), want.artifactIdentity, want.expiresAt)
			}
			result, err := ParseResultArtifact(output, actual["change"], actual["base"], actual["head"])
			if err != nil || result.Identity() != want.resultIdentity || result.ArtifactIdentity() != want.artifactIdentity {
				t.Fatalf("parsed result=%s artifact=%s err=%v", result.Identity(), result.ArtifactIdentity(), err)
			}
			scope, err := result.MemoryScope()
			if err != nil || scope.Identity() != result.MemoryScopeIdentity() {
				t.Fatalf("memory scope=%s err=%v", scope.Identity(), err)
			}
			if len(result.Queries()) != want.queries || len(result.Omissions()) != want.omissions {
				t.Fatalf("queries=%d omissions=%d", len(result.Queries()), len(result.Omissions()))
			}
			for _, query := range result.Queries() {
				if query.identity != want.queryIdentity {
					t.Fatalf("query identity=%s want=%s", query.identity, want.queryIdentity)
				}
				retrieval, err := query.Retrieval(scope, result.AsOf())
				if err != nil || retrieval.Identity() != query.retrievalIdentity {
					t.Fatalf("retrieval=%s err=%v", retrieval.Identity(), err)
				}
				if retrieval.Identity() != want.retrievalIdentity {
					t.Fatalf("retrieval identity=%s want=%s", retrieval.Identity(), want.retrievalIdentity)
				}
				for i, item := range query.Items() {
					if item.Identity() != want.itemIdentity || item.RecordIdentity() != want.recordIdentity {
						t.Fatalf("item=%s record=%s", item.Identity(), item.RecordIdentity())
					}
					record, err := item.Record(scope)
					if err != nil || record.Identity() != item.RecordIdentity() || retrieval.Items()[i].Identity() != item.Identity() {
						t.Fatalf("record=%s item=%s err=%v", record.Identity(), item.Identity(), err)
					}
					if !record.FreshAt(result.AsOf()) {
						t.Fatal("emitted record is stale as of retrieval")
					}
					if want.withRecord && record.Identity() != live.record.Identity() {
						t.Fatalf("record identity=%s want=%s", record.Identity(), live.record.Identity())
					}
				}
			}
			if want.name == "zero-and-omitted" {
				if result.Queries()[0].Path() != "a.txt" || len(result.Queries()[0].Items()) != 0 || result.Omissions()[0].Path() != "b.txt" || result.Omissions()[0].Reason() != "path_not_authorized" || !bytes.Contains(output.Payload(), []byte(`"items":[]`)) {
					t.Fatal("zero-hit/unauthorized shape drift")
				}
			}
			if want.name == "all-omitted" {
				if result.Omissions()[0].Reason() != "path_not_authorized" || !bytes.Contains(output.Payload(), []byte(`"queries":[]`)) {
					t.Fatal("all-unauthorized shape drift")
				}
			}
		})
	}
}

func TestOldCodeMemoryParserNegativeCorpus(t *testing.T) {
	frozen := loadOldMemoryGolden(t, "nonempty")
	output, change, base, head := frozen["memory"], frozen["change"], frozen["base"], frozen["head"]
	rebuild := func(t *testing.T, payload []byte, provenance []string) artifact.Artifact {
		t.Helper()
		a, err := artifact.New(output.Scope(), output.Kind(), output.MediaType(), output.Classification(), output.Origin(), output.Protection(), provenance, payload, output.CreatedAt(), output.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	withoutRetriever := make([]string, 0, len(output.Provenance()))
	for _, v := range output.Provenance() {
		if v != strings.Repeat("6", 64) {
			withoutRetriever = append(withoutRetriever, v)
		}
	}
	unknown := bytes.Replace(output.Payload(), []byte(`"contract":`), []byte(`"unrecognized":true,"contract":`), 1)
	cases := []struct {
		name                       string
		memory, change, base, head artifact.Artifact
	}{
		{"wrong provenance", rebuild(t, output.Payload(), withoutRetriever), change, base, head},
		{"source order mismatch", output, change, head, base},
		{"unknown JSON field", rebuild(t, unknown, output.Provenance()), change, base, head},
		{"noncanonical whitespace", rebuild(t, append([]byte(" "), output.Payload()...), output.Provenance()), change, base, head},
		{"trailing JSON", rebuild(t, append(output.Payload(), []byte("{}")...), output.Provenance()), change, base, head},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseResultArtifact(tc.memory, tc.change, tc.base, tc.head)
			if !errors.Is(err, ErrInvalidResult) || result.Identity() != "" {
				t.Fatalf("result=%s err=%v", result.Identity(), err)
			}
		})
	}
	// A second real producer's change cannot be substituted for the memory chain.
	other := loadOldMemoryGolden(t, "zero-and-omitted")
	if result, err := ParseResultArtifact(output, other["change"], base, head); !errors.Is(err, ErrInvalidResult) || result.Identity() != "" {
		t.Fatalf("changed chain result=%s err=%v", result.Identity(), err)
	}
}
