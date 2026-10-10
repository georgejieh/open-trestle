package context

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

func precedenceProfile(t *testing.T, changed []string, base, head map[string][]byte) semanticimpact.Profile {
	t.Helper()
	changes := make([]semanticimpact.ChangedPath, 0, len(changed))
	for _, path := range changed {
		value, err := semanticimpact.NewChangedPath(path)
		if err != nil {
			t.Fatalf("changed path %q: %v", path, err)
		}
		changes = append(changes, value)
	}
	makeFiles := func(files map[string][]byte) []semanticimpact.File {
		out := make([]semanticimpact.File, 0, len(files))
		for path, content := range files {
			file, err := semanticimpact.NewFile(path, content)
			if err != nil {
				t.Fatalf("file %q: %v", path, err)
			}
			out = append(out, file)
		}
		return out
	}
	input, err := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), changes, makeFiles(base), makeFiles(head))
	if err != nil {
		t.Fatalf("semantic input: %v", err)
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatalf("semantic analysis: %v", err)
	}
	return profile
}

func precedenceScope(t *testing.T, prefixes ...string) memorycore.Scope {
	t.Helper()
	scope, err := memorycore.NewScope("tenant", "repository", "actor", memorycore.RefVisibilityExact, strings.Repeat("d", 64), prefixes)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return scope
}

func precedenceReferences(t *testing.T, profile semanticimpact.Profile, paths []string, lines []int) {
	t.Helper()
	refs := profile.References()
	if len(refs) != len(paths) || len(paths) != len(lines) {
		t.Fatalf("reference count=%d, want %d", len(refs), len(paths))
	}
	for i, ref := range refs {
		if ref.Path() != paths[i] || ref.Line() != lines[i] {
			t.Fatalf("reference %d: %q:%d, want %q:%d", i, ref.Path(), ref.Line(), paths[i], lines[i])
		}
	}
}

func precedenceFailure(t *testing.T, candidates []review.ContextSource, omissions []review.ContextSourceOmission, failure, want controlplane.RunFailure) {
	t.Helper()
	if failure != want || candidates != nil || omissions != nil {
		t.Fatalf("failure=%s candidates=%v omissions=%v; want %s and both nil", failure, candidates, omissions, want)
	}
}

func precedenceCandidate(t *testing.T, got review.ContextSource, path string, line int, file, body []byte) {
	t.Helper()
	repositoryFile, err := evidence.NewRepositoryFile(path, file)
	if err != nil {
		t.Fatalf("repository file: %v", err)
	}
	sourceRange, err := evidence.NewSourceRange(path, line, line)
	if err != nil {
		t.Fatalf("source range: %v", err)
	}
	binding, err := evidence.BindSourceSlice(repositoryFile, file, sourceRange, body)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), sourceRange)
	if err != nil {
		t.Fatalf("evidence item: %v", err)
	}
	expected, err := review.NewBoundContextSource(review.ContextStageDirectReference, memorycore.TaintRepositoryControlled, item, body, binding)
	if err != nil {
		t.Fatalf("expected source: %v", err)
	}
	if got.Identity() != expected.Identity() || got.Stage() != review.ContextStageDirectReference || got.Taint() != memorycore.TaintRepositoryControlled || got.ReferenceID() != binding.Identity() || got.EvidenceItem() != item || !bytes.Equal(got.Content(), body) || !got.HasSliceBinding() || got.SliceBinding() != binding || got.SliceBindingIdentity() != binding.Identity() {
		t.Fatalf("source %q:%d does not match bound source", path, line)
	}
}

type precedenceOmissionKey struct{ path, reason string }
type precedenceOmissionValue struct {
	start, end int
	count      uint32
}

func precedenceOmissions(t *testing.T, got []review.ContextSourceOmission, want map[precedenceOmissionKey]precedenceOmissionValue) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("omissions=%d, want %d", len(got), len(want))
	}
	seen := make(map[precedenceOmissionKey]bool)
	for _, omission := range got {
		if err := omission.Validate(); err != nil {
			t.Fatalf("invalid omission: %v", err)
		}
		key := precedenceOmissionKey{omission.Path(), omission.Reason()}
		expected, ok := want[key]
		if !ok || seen[key] || omission.StartLine() != expected.start || omission.EndLine() != expected.end || omission.Count() != expected.count {
			t.Fatalf("unexpected omission (%q,%q,%d,%d,%d)", key.path, key.reason, omission.StartLine(), omission.EndLine(), omission.Count())
		}
		seen[key] = true
	}
}

func TestAppendSemanticCandidatesOmissionPreflightPrecedence(t *testing.T) {
	profile := precedenceProfile(t, nil, nil, map[string][]byte{"a.go": []byte("package p\n")})
	precedenceReferences(t, profile, nil, nil)
	scope := precedenceScope(t, ".")
	valid, err := review.NewCountedContextSourceOmission("existing.go", 0, 0, "candidate_limit", 32768)
	if err != nil {
		t.Fatal(err)
	}
	zero := review.ContextSourceOmission{}
	tooLong := append([]review.ContextSourceOmission{zero}, make([]review.ContextSourceOmission, 16384)...)
	for i := 1; i < len(tooLong); i++ {
		tooLong[i] = valid
	}
	for _, row := range []struct {
		name      string
		omissions []review.ContextSourceOmission
		want      controlplane.RunFailure
	}{
		{"length before invalid", tooLong, controlplane.RunFailureResourceLimit},
		{"invalid before count", []review.ContextSourceOmission{valid, zero, valid, valid}, controlplane.RunFailureInvalidInput},
		{"count exactly 65536", []review.ContextSourceOmission{valid, valid}, 0},
		{"count exceeds 65536", []review.ContextSourceOmission{valid, valid, valid}, controlplane.RunFailureResourceLimit},
	} {
		t.Run(row.name, func(t *testing.T) {
			candidates, omissions, failure := appendSemanticCandidates(nil, scope, profile, nil, row.omissions)
			if row.want != 0 {
				precedenceFailure(t, candidates, omissions, failure, row.want)
				return
			}
			if failure != 0 || len(candidates) != 0 {
				t.Fatalf("success failure=%s candidates=%d", failure, len(candidates))
			}
			if len(omissions) != 2 {
				t.Fatalf("omission count=%d", len(omissions))
			}
			for _, omission := range omissions {
				if err := omission.Validate(); err != nil || omission.Path() != valid.Path() || omission.Reason() != valid.Reason() || omission.StartLine() != 0 || omission.EndLine() != 0 || omission.Count() != valid.Count() {
					t.Fatalf("unexpected existing omission: %v (validation=%v)", omission, err)
				}
			}
		})
	}
}

func TestAppendSemanticCandidatesMissingContentPrecedesSeenRange(t *testing.T) {
	base := []byte("package p\nfunc Target(){}\n")
	head := []byte("package p\nfunc Target(){_=1}\nfunc Use(){Target()}\n")
	profile := precedenceProfile(t, []string{"a.go"}, map[string][]byte{"a.go": base}, map[string][]byte{"a.go": head})
	precedenceReferences(t, profile, []string{"a.go"}, []int{3})
	scope := precedenceScope(t, ".")
	candidates, omissions, failure := appendSemanticCandidates(map[string][]byte{"a.go": head}, scope, profile, nil, nil)
	if failure != 0 || len(candidates) != 1 {
		t.Fatalf("seed failure=%s candidates=%d", failure, len(candidates))
	}
	precedenceOmissions(t, omissions, nil)
	precedenceCandidate(t, candidates[0], "a.go", 3, head, []byte("func Use(){Target()}\n"))
	if candidates[0].ReferenceID() == profile.References()[0].Identity() {
		t.Fatal("semantic ID used instead of slice-binding ID")
	}
	for _, row := range []struct {
		name     string
		contents map[string][]byte
		seeded   []review.ContextSource
	}{
		{"missing content before duplicate", nil, candidates},
		{"short physical file", map[string][]byte{"a.go": []byte("package p\n")}, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			gotCandidates, gotOmissions, gotFailure := appendSemanticCandidates(row.contents, scope, profile, row.seeded, nil)
			precedenceFailure(t, gotCandidates, gotOmissions, gotFailure, controlplane.RunFailureInvalidInput)
		})
	}
}

func TestAppendSemanticCandidatesCapBeforeScopeAndCachedReason(t *testing.T) {
	base := []byte("package p\nfunc Target(){}\n")
	var builder strings.Builder
	builder.WriteString("package p\nfunc Target(){_=1}\nfunc Use(){\n")
	for range 128 {
		builder.WriteString("Target()\n")
	}
	builder.WriteString("}\n")
	head := []byte(builder.String())
	other := []byte("package p\nfunc UseZ(){Target();Target()}\n")
	profile := precedenceProfile(t, []string{"a.go"}, map[string][]byte{"a.go": base}, map[string][]byte{"a.go": head, "z.go": other})
	paths, lines := make([]string, 0, 130), make([]int, 0, 130)
	for line := 4; line <= 131; line++ {
		paths = append(paths, "a.go")
		lines = append(lines, line)
	}
	paths, lines = append(paths, "z.go", "z.go"), append(lines, 2, 2)
	precedenceReferences(t, profile, paths, lines)
	scope := precedenceScope(t, "a.go")
	candidates, omissions, failure := appendSemanticCandidates(map[string][]byte{"a.go": head, "z.go": other}, scope, profile, nil, nil)
	if failure != 0 || len(candidates) != 128 {
		t.Fatalf("failure=%s candidates=%d", failure, len(candidates))
	}
	for i, candidate := range candidates {
		precedenceCandidate(t, candidate, "a.go", i+4, head, []byte("Target()\n"))
	}
	precedenceOmissions(t, omissions, map[precedenceOmissionKey]precedenceOmissionValue{{"z.go", "semantic_candidate_limit"}: {2, 2, 2}})
}

func TestAppendSemanticCandidatesSizeBoundaryAndInternalPath(t *testing.T) {
	base := []byte("package p\nfunc Target(){}\n")
	scope := precedenceScope(t, ".")
	for _, row := range []struct {
		name      string
		size      int
		oversized bool
	}{
		{"exactly 256 KiB", 256 << 10, false},
		{"one byte over 256 KiB", (256 << 10) + 1, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			prefix, suffix := "func Use(){Target() /*", "*/}\n"
			line := []byte(prefix + strings.Repeat("x", row.size-len(prefix)-len(suffix)) + suffix)
			if len(line) != row.size {
				t.Fatalf("line length=%d", len(line))
			}
			head := append([]byte("package p\nfunc Target(){_=1}\n"), line...)
			profile := precedenceProfile(t, []string{"a.go"}, map[string][]byte{"a.go": base}, map[string][]byte{"a.go": head})
			precedenceReferences(t, profile, []string{"a.go"}, []int{3})
			candidates, omissions, failure := appendSemanticCandidates(map[string][]byte{"a.go": head}, scope, profile, nil, nil)
			if failure != 0 {
				t.Fatalf("failure=%s", failure)
			}
			if row.oversized {
				if len(candidates) != 0 {
					t.Fatalf("oversized candidates=%d", len(candidates))
				}
				precedenceOmissions(t, omissions, map[precedenceOmissionKey]precedenceOmissionValue{{"a.go", "semantic_source_size_limit"}: {3, 3, 1}})
			} else {
				if len(candidates) != 1 {
					t.Fatalf("boundary candidates=%d", len(candidates))
				}
				precedenceCandidate(t, candidates[0], "a.go", 3, head, line)
				precedenceOmissions(t, omissions, nil)
			}
		})
	}
	t.Run("1025-byte path yields internal omission failure", func(t *testing.T) {
		path := strings.Repeat("q", 1022) + ".go"
		if len(path) != 1025 {
			t.Fatalf("path length=%d", len(path))
		}
		target := []byte("package p\nfunc Target(){_=1}\n")
		other := []byte("package p\nfunc Use(){Target()}\n")
		head := map[string][]byte{"a.go": target, path: other}
		profile := precedenceProfile(t, []string{"a.go"}, map[string][]byte{"a.go": base}, head)
		precedenceReferences(t, profile, []string{path}, []int{2})
		candidates, omissions, failure := appendSemanticCandidates(head, scope, profile, nil, nil)
		precedenceFailure(t, candidates, omissions, failure, controlplane.RunFailureInternal)
	})
}
