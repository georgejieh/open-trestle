package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const rmProducer = "084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f"
const rmAdvice = "CLI_RETAINED_ADVICE_SENTINEL: operator recalls zero-input handling; inspect actual source."

type rmScopeWire struct {
	Identity   string   `json:"identity"`
	Tenant     string   `json:"tenant_id"`
	Repository string   `json:"repository_id"`
	Actor      string   `json:"actor_id"`
	Visibility string   `json:"ref_visibility"`
	RefSet     string   `json:"ref_set_identity"`
	Prefixes   []string `json:"path_prefixes"`
}

type rmHeadWire struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Identity  string `json:"identity"`
}

type rmRecordWire struct {
	Identity string   `json:"record_identity"`
	Kind     string   `json:"kind"`
	Taint    string   `json:"taint"`
	Path     string   `json:"path"`
	Symbols  []string `json:"symbols"`
	Text     string   `json:"text"`
	Evidence []string `json:"evidence_ids"`
	Producer string   `json:"producer_identity"`
	Observed int64    `json:"observed_at"`
	From     int64    `json:"valid_from"`
	Until    int64    `json:"valid_until"`
}

type rmEnvelopeWire struct {
	Contract    string         `json:"contract"`
	Version     int            `json:"schema_version"`
	Attestation string         `json:"attestation"`
	Scope       rmScopeWire    `json:"scope"`
	Repository  string         `json:"repository_identity"`
	Head        rmHeadWire     `json:"head_revision"`
	Policy      string         `json:"runtime_policy_identity"`
	Paths       []string       `json:"allowed_paths"`
	Records     []rmRecordWire `json:"records"`
}

func rmJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func rmHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func rmHeadBytes(t *testing.T, w rmHeadWire) []byte {
	return rmJSON(t, struct {
		Contract  string `json:"contract"`
		Version   int    `json:"schema_version"`
		Kind      string `json:"kind"`
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	}{"open-trestle/revision-identity", 1, w.Kind, w.Algorithm, w.Digest})
}

func rmScopeBytes(t *testing.T, w rmScopeWire) []byte {
	return rmJSON(t, struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Tenant     string   `json:"tenant"`
		Repository string   `json:"repository"`
		Actor      string   `json:"actor"`
		Visibility string   `json:"ref_visibility"`
		RefSet     string   `json:"ref_set_identity"`
		Prefixes   []string `json:"path_prefixes"`
	}{"open-trestle/memory-scope", 1, w.Tenant, w.Repository, w.Actor, w.Visibility, w.RefSet, w.Prefixes})
}

func rmNoteBytes(t *testing.T, scopeID string, r rmRecordWire) []byte {
	return rmJSON(t, []any{"open-trestle/operator-feedback-note", 1, scopeID, r.Path, r.Text, r.Observed, r.From, r.Until})
}

func rmRecordBytes(t *testing.T, scopeID string, r rmRecordWire) []byte {
	// Native empty arrays are null; only the new wire symbols array is [].
	return rmJSON(t, struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Scope      string   `json:"scope"`
		Kind       string   `json:"kind"`
		Taint      string   `json:"taint"`
		Path       string   `json:"path"`
		Symbols    []string `json:"symbols"`
		TextDigest string   `json:"text_digest"`
		TextBytes  int      `json:"text_bytes"`
		Evidence   []string `json:"evidence"`
		Derived    []string `json:"derived_from"`
		Counter    []string `json:"counter_evidence"`
		Producer   string   `json:"producer"`
		Observed   int64    `json:"observed_at"`
		From       int64    `json:"valid_from"`
		Until      int64    `json:"valid_until"`
		Stale      int64    `json:"stale_after"`
		Freshness  string   `json:"freshness"`
		Confidence uint16   `json:"confidence"`
	}{"open-trestle/memory-record", 1, scopeID, r.Kind, r.Taint, r.Path, nil,
		rmHash([]byte(r.Text)), len(r.Text), r.Evidence, nil, nil, r.Producer,
		r.Observed, r.From, r.Until, 0, "", 0})
}

func rmInputBytes(t *testing.T, w rmEnvelopeWire) []byte {
	return rmJSON(t, []any{"open-trestle/protected-retained-input", 1, "local-only", 65536, 16, 16, 4096, 1024, 8192, 32768, 604800000, w})
}

func rmScope(t *testing.T, w rmScopeWire) memory.Scope {
	t.Helper()
	visibility, err := memory.ParseRefVisibility(w.Visibility)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := memory.NewScope(w.Tenant, w.Repository, w.Actor, visibility, w.RefSet, w.Prefixes)
	if err != nil || scope.Validate() != nil {
		t.Fatal("invalid native scope fixture")
	}
	if scope.Identity() != rmHash(rmScopeBytes(t, w)) || scope.Identity() != w.Identity ||
		scope.TenantID() != w.Tenant || scope.RepositoryID() != w.Repository || scope.ActorID() != w.Actor ||
		scope.RefVisibility().String() != w.Visibility || scope.RefSetIdentity() != w.RefSet ||
		!reflect.DeepEqual(scope.PathPrefixes(), w.Prefixes) {
		t.Fatal("native scope recipe drift")
	}
	return scope
}

func rmNativeRecord(t *testing.T, scope memory.Scope, r rmRecordWire) memory.Record {
	t.Helper()
	kind, err := memory.ParseRecordKind(r.Kind)
	if err != nil {
		t.Fatal(err)
	}
	taint, err := memory.ParseTaintClass(r.Taint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := memory.NewRecord(scope, memory.RecordInput{
		Kind: kind, Taint: taint, Path: r.Path, Text: r.Text, EvidenceIDs: r.Evidence,
		ProducerIdentity: r.Producer, ObservedAt: time.UnixMilli(r.Observed).UTC(),
		ValidFrom: time.UnixMilli(r.From).UTC(), ValidUntil: time.UnixMilli(r.Until).UTC(),
	})
	if err != nil || record.Validate() != nil || record.Identity() != r.Identity {
		t.Fatal("native record recipe drift")
	}
	return record
}

func rmReseal(t *testing.T, w *rmEnvelopeWire, native bool) {
	t.Helper()
	w.Head.Identity = rmHash(rmHeadBytes(t, w.Head))
	w.Scope.RefSet = w.Head.Identity
	w.Scope.Identity = rmHash(rmScopeBytes(t, w.Scope))
	for i := range w.Records {
		r := &w.Records[i]
		r.Evidence = []string{"operator-note:" + rmHash(rmNoteBytes(t, w.Scope.Identity, *r))}
		r.Identity = rmHash(rmRecordBytes(t, w.Scope.Identity, *r))
	}
	sort.Strings(w.Paths)
	sort.Slice(w.Records, func(i, j int) bool { return w.Records[i].Identity < w.Records[j].Identity })
	if native {
		head, err := evidence.NewRevisionIdentity(evidence.RevisionKind(w.Head.Kind), evidence.RevisionAlgorithm(w.Head.Algorithm), w.Head.Digest)
		if err != nil || head.Identity() != w.Head.Identity || string(head.Kind()) != w.Head.Kind || string(head.Algorithm()) != w.Head.Algorithm || head.Digest() != w.Head.Digest {
			t.Fatal("native head recipe drift")
		}
		scope := rmScope(t, w.Scope)
		for _, record := range w.Records {
			rmNativeRecord(t, scope, record)
		}
	}
}

func rmCLIInput(t *testing.T, f *localModelFixture) (string, rmEnvelopeWire) {
	t.Helper()
	_, policy, e := runtimeconfig.LoadProtectedConfiguration(context.Background(), f.inventoryPath, f.policyPath)
	if e != nil {
		t.Fatal(e)
	}
	repository, e := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if e != nil {
		t.Fatal(e)
	}
	// CLI uses its real wall clock. A one-hour declaration is well inside seven
	// days and strictly beyond the unchanged five-second execution budget.
	now := time.Now().UTC().Add(-time.Second).UnixMilli()
	w := rmEnvelopeWire{Contract: "open-trestle/retained-memory-input", Version: 1, Attestation: "operator_attested_advisory_feedback",
		Scope:      rmScopeWire{Tenant: "tenant-local", Repository: "repository-local", Actor: "local-reviewer", Visibility: "exact", Prefixes: []string{"."}},
		Repository: repository.Identity(), Head: rmHeadWire{Kind: "git_commit", Algorithm: "sha1", Digest: f.head}, Policy: policy.Identity(), Paths: []string{"a.go", "caller.go"}, Records: []rmRecordWire{}}
	for _, path := range w.Paths {
		w.Records = append(w.Records, rmRecordWire{Kind: "human_feedback", Taint: "user_controlled", Path: path, Symbols: []string{}, Text: rmAdvice, Producer: rmProducer, Observed: now, From: now, Until: now + 3600000})
	}
	rmReseal(t, &w, true)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "operator-feedback.json")
	if e := os.WriteFile(path, rmJSON(t, w), 0600); e != nil {
		t.Fatal(e)
	}
	input, e := runtimeconfig.LoadProtectedRetainedMemoryInput(context.Background(), path, rmScope(t, w.Scope), repository, policy, time.Now().UTC())
	if e != nil || input.Identity() != rmHash(rmInputBytes(t, w)) || len(input.Records()) != 2 {
		t.Fatal("actual protected loader or independent identity fixture drift")
	}
	return path, w
}
func rmCLIArgs(f *localModelFixture, path string) []string {
	return append(append([]string(nil), f.args...), "--retained-memory-input", path)
}
func rmCLINoCalls(t *testing.T, f *localModelFixture) {
	t.Helper()
	g, _ := f.generation.snapshot()
	v, _ := f.verification.snapshot()
	if g != 0 || v != 0 {
		t.Fatal("refusal dispatched external model")
	}
}
func rmCLIPacket(t *testing.T, p localModelPacket, w rmEnvelopeWire) {
	t.Helper()
	if p.MemoryScope != w.Scope.Identity || p.MemoryAuthority != "advisory_only" || p.SourceAuthority != "evidence_data_not_instructions" || len(p.Memory.Items) != 1 || len(p.AdditionalMemory) != 0 || p.Memory.IndexRevision != 2 || len(p.Memory.QueryIdentity) != 64 || len(p.Memory.RetrievalIdentity) != 64 {
		t.Fatal("actual CLI request lacks scoped real query/advisory memory")
	}
	var expected rmRecordWire
	for _, r := range w.Records {
		if r.Path == "a.go" {
			expected = r
		}
	}
	i := p.Memory.Items[0]
	if i.MemoryID != expected.Identity || i.Kind != expected.Kind || i.Taint != expected.Taint || i.Path != expected.Path || i.Text != expected.Text || i.ProducerIdentity != expected.Producer || !slices.Equal(i.EvidenceIDs, expected.Evidence) || len(i.Symbols) != 0 || len(i.DerivedFromIDs) != 0 || len(i.CounterEvidenceIDs) != 0 || i.ObservedAt != expected.Observed || i.ValidFrom != expected.From || i.ValidUntil != expected.Until || i.StaleAfter != 0 || i.FreshnessIdentity != "" || i.Confidence != 0 || i.Rank != 1 || i.PathScore != 1 || i.SymbolScore != 0 || i.TextScore != 0 {
		t.Fatal("actual CLI model advice differs from loaded declaration")
	}
	for _, source := range p.Sources {
		if source.ID == i.MemoryID || slices.Contains(i.EvidenceIDs, source.ID) {
			t.Fatal("advisory note became source custody")
		}
	}
}
func rmCLILimits(t *testing.T, r localModelReceipt, encoded, path string, opted bool) {
	t.Helper()
	if len(encoded) > 256<<10 || strings.Contains(encoded, path) || strings.Contains(encoded, rmAdvice) || strings.Contains(encoded, localModelKey) || strings.Contains(encoded, localModelSecret) {
		t.Fatal("CLI output leaked private input or exceeded bound")
	}
	if slices.Contains(r.Limitations, "empty_memory_index") == opted || slices.Contains(r.Limitations, "retained_input_read_only") != opted || slices.Contains(r.Limitations, "retained_input_advisory_not_all_records_selected") != opted {
		t.Fatal("CLI labels loaded input incorrectly")
	}
	for _, limitation := range []string{"loose_git_objects_only", "bounded_source_context", "no_publication", "ephemeral_state_no_resume"} {
		if !slices.Contains(r.Limitations, limitation) {
			t.Fatal("existing output limitation lost")
		}
	}
}

func TestLocalGitRetainedMemoryActualFreshCLIGraphs(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	path, w := rmCLIInput(t, f)
	args := rmCLIArgs(f, path)
	if _, _, _, _, e := parseLocalModelReview(args[2:]); e != nil {
		t.Fatal("retained-memory input flag was not admitted")
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var prior localModelReceipt
	for run := 0; run < 2; run++ {
		r, encoded := localModelExecute(t, f, args, 4)
		rmCLILimits(t, r, encoded, path, true)
		if r.Status != "findings" || r.RunStatus != "succeeded" || r.Independence != "distinct_provider" || len(r.Tasks) != 9 || r.GenerationRoute != f.generationRoute || r.VerificationRoute != f.verificationRoute {
			t.Fatal("CLI bypassed ordinary nine-task independent verification")
		}
		for _, task := range r.Tasks {
			if task.Status != "succeeded" || task.Attempts != 1 {
				t.Fatal("CLI invented completion or retried model")
			}
		}
		_, g := f.generation.snapshot()
		_, v := f.verification.snapshot()
		if len(g) != run+1 || len(v) != run+1 {
			t.Fatal("fresh CLI invocation did not dispatch once per role")
		}
		gc, vc := g[run], v[run]
		rmCLIPacket(t, gc.Packet, w)
		rmCLIPacket(t, vc.Packet, w)
		if gc.ContextID != r.Context || gc.RequestID != r.GenerationRequest || vc.ContextID != r.VerificationContext || vc.RequestID != r.VerificationRequest || vc.Packet.GenerationContext != gc.ContextID || vc.Packet.CandidateBatch != r.CandidateBatch || gc.Packet.Scope != r.Scope || vc.Packet.Scope != r.Scope || !reflect.DeepEqual(gc.Packet.Memory, vc.Packet.Memory) {
			t.Fatal("CLI model requests lost actual context/retrieval lineage")
		}
		if run > 0 && (r.Request == prior.Request || r.Scope == prior.Scope || r.Context == prior.Context || r.Plan == prior.Plan) {
			t.Fatal("CLI reused closed graph authority")
		}
		prior = r
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("CLI wrote or curated the configured input")
	}
	// Omitted flag remains empty, even with a valid protected file nearby.
	r, encoded := localModelExecute(t, f, f.args, 4)
	rmCLILimits(t, r, encoded, path, false)
	_, g := f.generation.snapshot()
	if len(g) != 3 || len(g[2].Packet.Memory.Items) != 0 || g[2].Packet.Memory.IndexRevision != 0 {
		t.Fatal("CLI discovered advisory input without explicit opt-in")
	}
}

func TestLocalGitRetainedMemoryArgumentAdmission(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	path, _ := rmCLIInput(t, f)
	valid := rmCLIArgs(f, path)
	if _, _, _, _, e := parseLocalModelReview(valid[2:]); e != nil {
		t.Fatal("known retained-memory input flag was rejected as unknown")
	}
	for name, args := range map[string][]string{
		"empty":             replaceLocalGitChangeValue(valid, "--retained-memory-input", ""),
		"duplicate":         append(append([]string(nil), valid...), "--retained-memory-input", path),
		"investigation":     append(append([]string(nil), valid...), "--investigation-policy", "/private/never-read-policy"),
		"remote permission": replaceLocalGitChangeValue(valid, "--egress", "policy-approved"),
		"overlong":          replaceLocalGitChangeValue(valid, "--retained-memory-input", strings.Repeat("x", 4097)),
	} {
		t.Run(name, func(t *testing.T) {
			args = replaceLocalGitChangeValue(args, "--objects-root", "/private/never-open-root")
			args = replaceLocalGitChangeValue(args, "--route-inventory", "/private/never-open-inventory")
			var out, errout bytes.Buffer
			if _, _, _, _, e := parseLocalModelReview(args[2:]); e == nil {
				t.Fatal("mixed/invalid flags passed inert parser")
			}
			if code := runWithContext(context.Background(), args, &out, &errout); code != 2 || out.Len() != 0 || !strings.Contains(errout.String(), "usage:") || strings.Contains(errout.String(), path) || strings.Contains(errout.String(), "/private/") {
				t.Fatal("argument refusal performed work or leaked intent")
			}
			rmCLINoCalls(t, f)
		})
	}
}

func TestLocalGitRetainedMemoryProtectedLoadBeforeSourceDisposition(t *testing.T) {
	// The existing CLI has no opener/credential spy seam. This differential
	// observes disposition precedence, not a kernel-open or credential-read count.
	// The corrected scope accepts this bounded differential plus source-order
	// review and zero HTTP; it does not require or authorize a product hook.
	for _, kind := range []string{"malformed", "missing", "world writable file", "wrong head", "expired", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			path, w := rmCLIInput(t, f)
			switch kind {
			case "malformed":
				if e := os.WriteFile(path, []byte(`{"contract":`), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing":
				path = filepath.Join(filepath.Dir(path), "missing-input.json")
			case "world writable file":
				if e := os.Chmod(path, 0602); e != nil {
					t.Fatal(e)
				}
			case "wrong head":
				w.Head.Digest = f.base
				rmReseal(t, &w, true)
				if e := os.WriteFile(path, rmJSON(t, w), 0600); e != nil {
					t.Fatal(e)
				}
			case "expired":
				for i := range w.Records {
					w.Records[i].Observed -= 7200000
					w.Records[i].From -= 7200000
					w.Records[i].Until -= 7200000
				}
				rmReseal(t, &w, true)
				if e := os.WriteFile(path, rmJSON(t, w), 0600); e != nil {
					t.Fatal(e)
				}
			}
			args := replaceLocalGitChangeValue(rmCLIArgs(f, path), "--objects-root", filepath.Join(t.TempDir(), "missing-objects"))
			if _, _, _, _, e := parseLocalModelReview(args[2:]); e != nil {
				t.Fatal("supported retained-memory input was not admitted")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled" {
				cancel()
			}
			var out, errout bytes.Buffer
			code := runWithContext(ctx, args, &out, &errout)
			var receipt localModelReceipt
			if json.Unmarshal(out.Bytes(), &receipt) != nil || errout.Len() != 0 || len(out.Bytes()) > 256<<10 {
				t.Fatal("input refusal lacks bounded result")
			}
			want := "refused"
			if kind == "canceled" {
				want = "canceled"
			}
			// Corrected root contract preserves existing refusal=blocked/4. Only
			// actual caller cancellation is inconclusive/3. No global mapping changes.
			wantCode, wantCI := 4, "blocked"
			if kind == "canceled" {
				wantCode, wantCI = 3, "inconclusive"
			}
			if code != wantCode || receipt.Status != want || receipt.CI != wantCI || receipt.RunStatus != "not_opened" || len(receipt.Tasks) != 0 || len(receipt.Audit) != 0 || receipt.Plan != "" || receipt.Request != "" || receipt.Output != "" || receipt.Context != "" || receipt.Readiness != "" {
				t.Fatal("input was loaded after source or asserted opened work")
			}
			rmCLILimits(t, receipt, out.String(), path, false)
			rmCLINoCalls(t, f)
		})
	}
}

func TestLocalGitRetainedMemoryKeepsSourceModelBudgetAndOutputGuards(t *testing.T) {
	for _, kind := range []string{"cost", "capacity", "verifier pending", "remote inventory", "text", "short writer"} {
		t.Run(kind, func(t *testing.T) {
			settings := localModelFixtureOptions{expensive: kind == "cost", capacity: kind == "capacity", verifierPending: kind == "verifier pending"}
			f := newLocalModelFixture(t, settings)
			path, _ := rmCLIInput(t, f)
			args := rmCLIArgs(f, path)
			if kind == "remote inventory" {
				// Preserve a genuine loaded local input, then select a separately decoded
				// remote configuration. No cross-policy/head relabel is permitted.
				remote := newLocalModelFixture(t, localModelFixtureOptions{remote: true})
				args = replaceLocalGitChangeValue(args, "--route-inventory", remote.inventoryPath)
				args = replaceLocalGitChangeValue(args, "--runtime-policy", remote.policyPath)
			}
			if _, _, _, _, e := parseLocalModelReview(args[2:]); e != nil {
				t.Fatal("retained-memory input flag was not admitted")
			}
			var out, errout bytes.Buffer
			if kind == "short writer" {
				if code := runWithContext(context.Background(), args, shortWriter{}, &errout); code != 1 || !strings.Contains(errout.String(), "write result: failed") {
					t.Fatal("short output lost bounded failure")
				}
				return
			}
			if kind == "text" {
				args = replaceLocalGitChangeValue(args, "--format", "text")
			}
			code := runWithContext(context.Background(), args, &out, &errout)
			if errout.Len() != 0 || strings.Contains(out.String(), rmAdvice) || strings.Contains(out.String(), path) || strings.Contains(out.String(), localModelKey) {
				t.Fatal("guard leaked input/credentials")
			}
			if kind == "text" {
				if code != 4 || out.Len() == 0 || out.Len() > 64<<10 || !strings.Contains(out.String(), "retained_input_read_only") {
					t.Fatal("text output/limitations changed")
				}
				return
			}
			var receipt localModelReceipt
			if json.Unmarshal(out.Bytes(), &receipt) != nil || out.Len() > 256<<10 || receipt.CI == "pass" || receipt.Status == "findings" || receipt.RunStatus == "active" || code == 0 {
				t.Fatal("memory bypassed existing budget/local inventory constraints")
			}
			g, _ := f.generation.snapshot()
			v, _ := f.verification.snapshot()
			if v != 0 || kind != "verifier pending" && g != 0 {
				t.Fatal("refused budget/route reached model")
			}
		})
	}
}
