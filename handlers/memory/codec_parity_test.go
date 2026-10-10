package memory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/changecodec"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
)

func TestMemoryCodecAndFacadeFrozenReplay(t *testing.T) {
	if !errors.Is(ErrInvalidResult, memorycodec.ErrInvalidResult) {
		t.Fatal("initial sentinel split")
	}
	for _, want := range oldMemoryGoldens {
		t.Run(want.name, func(t *testing.T) {
			frozen := loadOldMemoryGolden(t, want.name)
			value, change, base, head := frozen["memory"], frozen["change"], frozen["base"], frozen["head"]
			direct, err := memorycodec.ParseResultArtifact(value, change, base, head)
			if err != nil {
				t.Fatal(err)
			}
			facade, err := ParseResultArtifact(value, change, base, head)
			if err != nil || direct.Identity() != facade.Identity() || direct.Identity() != want.resultIdentity || direct.ArtifactIdentity() != want.artifactIdentity {
				t.Fatalf("parser parity %v", err)
			}
			changed, err := changecodec.ParseResultArtifact(change, base, head)
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range []Result{direct, facade} {
				encoded, err := memorycodec.EncodeResult(result, changed)
				if err != nil || !bytes.Equal(encoded, value.Payload()) {
					t.Fatalf("codec encode drift: %v", err)
				}
				encoded, err = encodeResult(result, changed)
				if err != nil || !bytes.Equal(encoded, value.Payload()) {
					t.Fatalf("facade encode drift: %v", err)
				}
				scope, err := result.MemoryScope()
				if err != nil {
					t.Fatal(err)
				}
				for _, query := range result.Queries() {
					retrieval, err := query.Retrieval(scope, result.AsOf())
					if err != nil || retrieval.Identity() != query.RetrievalIdentity() {
						t.Fatalf("replay: %v", err)
					}
					for _, item := range query.Items() {
						record, err := item.Record(scope)
						if err != nil || record.Identity() != item.RecordIdentity() {
							t.Fatalf("record: %v", err)
						}
					}
				}
				for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
					if want.recordIdentity != "" && strings.Contains(fmt.Sprintf(format, result), want.recordIdentity) || strings.Contains(fmt.Sprintf(format, result), "private record text") {
						t.Fatal("formatter leaked")
					}
				}
			}
			if len(direct.Queries()) > 0 {
				scope, _ := direct.MemoryScope()
				q := direct.Queries()[0]
				retrieval, err := q.Retrieval(scope, direct.AsOf())
				if err != nil {
					t.Fatal(err)
				}
				expected, err := memorycore.NewLexicalQuery(scope, q.Path(), nil, nil, direct.AsOf(), retrieval.Query().Limit())
				if err != nil {
					t.Fatal(err)
				}
				created, err := memorycodec.NewQuery(scope, expected, retrieval)
				if err != nil || created.Identity() != q.Identity() {
					t.Fatalf("new query: %v", err)
				}
				if _, err := memorycodec.NewQuery(scope, memorycore.LexicalQuery{}, retrieval); !errors.Is(err, memorycodec.ErrInvalidResult) {
					t.Fatal("forged expected accepted")
				}
			}
			freshQueries := make([]Query, 0, len(direct.Queries()))
			for _, q := range direct.Queries() {
				scope, _ := direct.MemoryScope()
				retrieval, err := q.Retrieval(scope, direct.AsOf())
				if err != nil {
					t.Fatal(err)
				}
				constructed, err := memorycodec.NewQuery(scope, retrieval.Query(), retrieval)
				if err != nil {
					t.Fatal(err)
				}
				freshQueries = append(freshQueries, constructed)
			}
			scope, _ := direct.MemoryScope()
			omissions := direct.Omissions()
			constructed, err := memorycodec.NewResult(change, changed, direct.PolicyIdentity(), direct.RetrieverIdentity(), scope, direct.AsOf(), freshQueries, omissions)
			if err != nil || constructed.Identity() != direct.Identity() {
				t.Fatalf("new result: %v", err)
			}
			if output, err := memorycodec.EncodeResult(constructed, changed); err != nil || !bytes.Equal(output, value.Payload()) {
				t.Fatalf("fresh encode: %v", err)
			}
			if _, err := memorycodec.NewResult(base, changed, direct.PolicyIdentity(), direct.RetrieverIdentity(), scope, direct.AsOf(), freshQueries, omissions); !errors.Is(err, memorycodec.ErrInvalidResult) {
				t.Fatal("wrong change artifact accepted")
			}
			if _, err := memorycodec.NewResult(change, changecodec.Result{}, direct.PolicyIdentity(), direct.RetrieverIdentity(), scope, direct.AsOf(), freshQueries, omissions); !errors.Is(err, memorycodec.ErrInvalidResult) {
				t.Fatal("forged change accepted")
			}
			if _, err := memorycodec.NewResult(change, changed, direct.PolicyIdentity(), direct.RetrieverIdentity(), scope, time.Time{}, freshQueries, omissions); !errors.Is(err, memorycodec.ErrInvalidResult) {
				t.Fatal("zero time accepted")
			}
			if want.name == "zero-and-omitted" {
				bad, _ := memorycodec.NewOmission("b.txt", "query_limit")
				if _, err := memorycodec.NewResult(change, changed, direct.PolicyIdentity(), direct.RetrieverIdentity(), scope, direct.AsOf(), freshQueries, []Omission{bad}); !errors.Is(err, memorycodec.ErrInvalidResult) {
					t.Fatal("unauthorized budget omission accepted")
				}
			}
		})
	}
	if data, err := memorycodec.EncodeResult(Result{}, changecodec.Result{}); data != nil || !errors.Is(err, memorycodec.ErrInvalidResult) {
		t.Fatal("zero encoder accepted")
	}
	if _, err := memorycodec.NewOmission("../invalid", "query_limit"); !errors.Is(err, memorycodec.ErrInvalidResult) {
		t.Fatal("invalid omission path accepted")
	}
}

func TestMemoryCodecAndFacadeNegativeCorpus(t *testing.T) {
	frozen := loadOldMemoryGolden(t, "nonempty")
	value, change, base, head := frozen["memory"], frozen["change"], frozen["base"], frozen["head"]
	cases := []struct{ name, old, new string }{
		{"contract", `"contract":"open-trestle/memory-retrieval-result"`, `"contract":"invalid"`},
		{"version", `"schema_version":1`, `"schema_version":2`},
		{"scope", `"actor_id":"reviewer"`, `"actor_id":""`},
		{"record", `"kind":"canonical_fact"`, `"kind":"invalid"`},
		{"coverage", `"path":"a.txt","identity"`, `"path":"b.txt","identity"`},
		{"query identity", `"identity":"c53438d60eb1df95bb9523120744a82999a0b7c40a467d451a0fc6ce423ed22a"`, `"identity":"0000000000000000000000000000000000000000000000000000000000000001"`},
		{"leading whitespace", `{"contract"`, ` {"contract"`},
		{"trailing value", `"omissions":[]}`, `"omissions":[]}{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := []byte(tc.old)
			if !bytes.Contains(value.Payload(), old) {
				t.Fatal("fixture shape changed")
			}
			payload := bytes.Replace(value.Payload(), old, []byte(tc.new), 1)
			altered, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), payload, value.CreatedAt(), value.ExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			for name, parse := range map[string]func(artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) (Result, error){"codec": memorycodec.ParseResultArtifact, "facade": ParseResultArtifact} {
				result, err := parse(altered, change, base, head)
				if !errors.Is(err, memorycodec.ErrInvalidResult) || result.Identity() != "" {
					t.Fatalf("%s accepted: %s %v", name, result.Identity(), err)
				}
			}
		})
	}
	provenance := make([]string, 0, len(value.Provenance()))
	for _, identity := range value.Provenance() {
		if identity != strings.Repeat("6", 64) {
			provenance = append(provenance, identity)
		}
	}
	withoutRetriever, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), provenance, value.Payload(), value.CreatedAt(), value.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	for name, parse := range map[string]func(artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) (Result, error){"codec": memorycodec.ParseResultArtifact, "facade": ParseResultArtifact} {
		result, err := parse(withoutRetriever, change, base, head)
		if !errors.Is(err, memorycodec.ErrInvalidResult) || result.Identity() != "" {
			t.Fatalf("%s missing provenance accepted", name)
		}
	}
	for name, parse := range map[string]func(artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) (Result, error){"codec": memorycodec.ParseResultArtifact, "facade": ParseResultArtifact} {
		result, err := parse(value, change, head, base)
		if !errors.Is(err, memorycodec.ErrInvalidResult) || result.Identity() != "" {
			t.Fatalf("%s source substitution accepted", name)
		}
	}
}

func TestMemoryHandlerFailureClassificationUnchanged(t *testing.T) {
	ctx := context.Background()
	if got := retrievalFailure(ctx, memorycore.ErrMemoryIndexCapacity); got != controlplane.RunFailureResourceLimit {
		t.Fatal(got)
	}
	if got := retrievalFailure(ctx, memorycore.ErrMemoryContextDone); got != controlplane.RunFailureCanceled {
		t.Fatal(got)
	}
	if got := readFailure(ctx, artifact.ErrArtifactNotFound); got != controlplane.RunFailureInvalidInput {
		t.Fatal(got)
	}
	if got := readFailure(ctx, artifact.ErrStoreCapacity); got != controlplane.RunFailureResourceLimit {
		t.Fatal(got)
	}
	if got := writeFailure(ctx, artifact.ErrStoreCapacity); got != controlplane.RunFailureResourceLimit {
		t.Fatal(got)
	}
}
