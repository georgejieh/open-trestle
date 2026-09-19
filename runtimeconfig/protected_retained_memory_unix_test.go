//go:build unix

package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func rmProtectedFile(t *testing.T, encoded []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "operator-private-note.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rmLoadBytes(t *testing.T, encoded []byte, expected rmEnvelopeWire, policy RuntimePolicy, at time.Time, accept bool) RetainedMemoryInput {
	t.Helper()
	value, err := LoadProtectedRetainedMemoryInput(context.Background(), rmProtectedFile(t, encoded), rmScope(t, expected.Scope), rmRepository(t, "source-repository"), policy, at)
	if !accept {
		rmError(t, err)
		rmZero(t, value)
		return value
	}
	if err != nil {
		t.Fatal("valid protected input refused")
	}
	if value.ValidateFor(rmScope(t, expected.Scope), rmRepository(t, "source-repository"), policy, at) != nil {
		t.Fatal("loaded snapshot failed pure validation")
	}
	if value.Identity() != rmHash(rmInputBytes(t, expected)) || !reflect.DeepEqual(value.Scope(), rmScope(t, expected.Scope)) {
		t.Fatal("canonical snapshot binding drift")
	}
	records := value.Records()
	if len(records) != len(expected.Records) {
		t.Fatal("lost records")
	}
	for i, wire := range expected.Records {
		record := records[i]
		if !reflect.DeepEqual(record, rmNativeRecord(t, rmScope(t, expected.Scope), wire)) || record.Validate() != nil || !record.FreshAt(at) ||
			record.ScopeIdentity() != expected.Scope.Identity || record.Identity() != wire.Identity || record.Kind() != memory.RecordHumanFeedback || record.Taint() != memory.TaintUserControlled ||
			record.Path() != wire.Path || record.Text() != wire.Text || record.ProducerIdentity() != rmProducer || !reflect.DeepEqual(record.EvidenceIDs(), wire.Evidence) ||
			len(record.Symbols()) != 0 || len(record.DerivedFromIDs()) != 0 || len(record.CounterEvidenceIDs()) != 0 || record.IsDerived() ||
			record.ConfidenceBasisPoints() != 0 || record.FreshnessIdentity() != "" || record.StaleAfterUnixMilliseconds() != 0 ||
			record.ObservedAtUnixMilliseconds() != wire.Observed || record.ValidFromUnixMilliseconds() != wire.From || record.ValidUntilUnixMilliseconds() != wire.Until {
			t.Fatal("original native advisory fields changed")
		}
	}
	return value
}

func rmObject(t *testing.T, w rmEnvelopeWire, level string, transform func([]byte) []byte) []byte {
	t.Helper()
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(rmJSON(t, w), &outer); err != nil {
		t.Fatal(err)
	}
	if level == "envelope" {
		return transform(rmJSON(t, w))
	}
	if level == "record" {
		var records []json.RawMessage
		if err := json.Unmarshal(outer["records"], &records); err != nil {
			t.Fatal(err)
		}
		records[0] = transform(records[0])
		outer["records"] = rmJSON(t, records)
	} else {
		outer[level] = transform(outer[level])
	}
	return rmJSON(t, outer)
}

func rmEdit(t *testing.T, w rmEnvelopeWire, level string, change func(map[string]json.RawMessage)) []byte {
	t.Helper()
	return rmObject(t, w, level, func(raw []byte) []byte {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		change(fields)
		return rmJSON(t, fields)
	})
}

func TestLoadProtectedRetainedMemoryInputBindsCanonicalSnapshot(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 2, rmLiteralText)
	w.Paths = append(w.Paths, "unused/safe.go")
	rmReseal(t, &w, true)
	canonical := rmJSON(t, w)
	var arbitrary map[string]any
	if err := json.Unmarshal(canonical, &arbitrary); err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, rmJSON(t, arbitrary), "", "  "); err != nil {
		t.Fatal(err)
	}
	escaped := bytes.ReplaceAll(canonical, []byte("é"), []byte(`\u00e9`))
	escaped = bytes.ReplaceAll(escaped, []byte(`\u003c`), []byte("<"))
	var identity string
	for _, raw := range [][]byte{canonical, pretty.Bytes(), escaped} {
		value := rmLoadBytes(t, raw, w, policy, time.UnixMilli(rmObserved+1), true)
		if identity != "" && value.Identity() != identity {
			t.Fatal("raw key order, escaping, whitespace or pathname joined identity")
		}
		identity = value.Identity()
	}
	paired := rmEnvelope(t, policy.Identity(), 1, "operator 😀 advisory")
	pairedRaw := bytes.ReplaceAll(rmJSON(t, paired), []byte("😀"), []byte(`\ud83d\ude00`))
	rmLoadBytes(t, pairedRaw, paired, policy, time.UnixMilli(rmObserved), true)
	otherAt := rmLoadBytes(t, canonical, w, policy, time.UnixMilli(rmObserved+2).In(time.FixedZone("offset", 9*3600)), true)
	if otherAt.Identity() != identity {
		t.Fatal("read time joined content identity")
	}
	for _, changedText := range []string{"<&> é é \u2028\u2029\n\toperator advisory", "changed advisory"} {
		changed := rmEnvelope(t, policy.Identity(), 2, changedText)
		changed.Paths = append(changed.Paths, "unused/safe.go")
		rmReseal(t, &changed, true)
		value := rmLoadBytes(t, rmJSON(t, changed), changed, policy, time.UnixMilli(rmObserved), true)
		if value.Identity() == identity {
			t.Fatal("content change or Unicode normalization lost identity distinction")
		}
	}
}

func TestLoadProtectedRetainedMemoryInputRejectsStrictWire(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 1, "operator private advisory")
	valid := rmJSON(t, w)
	refuse := func(t *testing.T, raw []byte) { rmLoadBytes(t, raw, w, policy, time.UnixMilli(rmObserved), false) }
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil}, {"array", []byte(`[]`)}, {"string", []byte(`"x"`)}, {"null", []byte(`null`)},
		{"BOM", append([]byte{0xef, 0xbb, 0xbf}, valid...)}, {"trailing", append(append([]byte{}, valid...), []byte(` {}`)...)},
		{"comment", append([]byte("/*x*/"), valid...)},
		{"invalid-UTF8", bytes.Replace(valid, []byte("operator private advisory"), []byte{0xff}, 1)},
		{"high-surrogate", bytes.Replace(valid, []byte("operator private advisory"), []byte(`\ud800`), 1)},
		{"low-surrogate", bytes.Replace(valid, []byte("operator private advisory"), []byte(`\udfff`), 1)},
		{"reversed-surrogates", bytes.Replace(valid, []byte("operator private advisory"), []byte(`\udc00\ud800`), 1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) { refuse(t, test.raw) })
	}
	for _, level := range []string{"envelope", "scope", "head_revision", "record"} {
		var keys []string
		rmObject(t, w, level, func(raw []byte) []byte {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			for key := range fields {
				keys = append(keys, key)
			}
			return raw
		})
		sort.Strings(keys)
		for _, key := range keys {
			for _, mutation := range []string{"missing", "null", "wrong-case", "duplicate", "escaped-duplicate", "wrong-type", "empty-string"} {
				t.Run(level+"/"+key+"/"+mutation, func(t *testing.T) {
					raw := rmObject(t, w, level, func(raw []byte) []byte {
						var fields map[string]json.RawMessage
						if err := json.Unmarshal(raw, &fields); err != nil {
							t.Fatal(err)
						}
						switch mutation {
						case "missing":
							delete(fields, key)
						case "null":
							fields[key] = json.RawMessage(`null`)
						case "wrong-case":
							fields[strings.ToUpper(key)] = fields[key]
							delete(fields, key)
						case "wrong-type":
							fields[key] = json.RawMessage(`true`)
						case "empty-string":
							fields[key] = json.RawMessage(`""`)
						case "duplicate", "escaped-duplicate":
							encodedKey := string(rmJSON(t, key))
							if mutation == "escaped-duplicate" {
								encodedKey = `"` + fmt.Sprintf(`\u%04x`, key[0]) + key[1:] + `"`
							}
							return append([]byte("{"+encodedKey+":"+string(fields[key])+","), raw[1:]...)
						}
						return rmJSON(t, fields)
					})
					refuse(t, raw)
				})
			}
		}
		t.Run(level+"/unknown", func(t *testing.T) {
			refuse(t, rmEdit(t, w, level, func(m map[string]json.RawMessage) { m["unexpected"] = json.RawMessage(`0`) }))
		})
	}
	for _, field := range []string{"contract", "attestation", "repository_identity", "runtime_policy_identity"} {
		for _, value := range []string{`""`, `"wrong"`} {
			t.Run(field+value, func(t *testing.T) {
				refuse(t, rmEdit(t, w, "envelope", func(m map[string]json.RawMessage) { m[field] = json.RawMessage(value) }))
			})
		}
	}
	for _, value := range []string{`0`, `2`, `1.0`, `1e0`, `"1"`, `-1`, `18446744073709551616`} {
		t.Run("version/"+value, func(t *testing.T) {
			refuse(t, rmEdit(t, w, "envelope", func(m map[string]json.RawMessage) { m["schema_version"] = json.RawMessage(value) }))
		})
	}
	for _, lexeme := range []string{"+1700000000000", "01700000000000", "1700000000000."} {
		t.Run("invalid-time-lexeme/"+lexeme, func(t *testing.T) {
			refuse(t, bytes.Replace(valid, []byte(`"observed_at":1700000000000`), []byte(`"observed_at":`+lexeme), 1))
		})
	}
	for _, field := range []string{"observed_at", "valid_from", "valid_until"} {
		for _, value := range []string{`0`, `-1`, `1.0`, `1e3`, `"1700000000000"`, `253402300800000`, `9223372036854775808`, `18446744073709551616`} {
			t.Run(field+"/"+value, func(t *testing.T) {
				refuse(t, rmEdit(t, w, "record", func(m map[string]json.RawMessage) { m[field] = json.RawMessage(value) }))
			})
		}
	}
	for _, field := range []string{"derived_from_ids", "counter_evidence_ids", "stale_after", "freshness_identity", "confidence_basis_points", "scope", "source", "provider", "custody", "raw_source", "url"} {
		for _, raw := range []string{`[]`, `0`, `""`} {
			t.Run("forbidden/"+field+raw, func(t *testing.T) {
				refuse(t, rmEdit(t, w, "record", func(m map[string]json.RawMessage) { m[field] = json.RawMessage(raw) }))
			})
		}
	}
	refuse(t, rmEdit(t, w, "record", func(m map[string]json.RawMessage) { m["evidence_ids"] = json.RawMessage(`[]`) }))
	refuse(t, rmEdit(t, w, "record", func(m map[string]json.RawMessage) {
		m["evidence_ids"] = rmJSON(t, []string{w.Records[0].Evidence[0], w.Records[0].Evidence[0]})
	}))
	for _, raw := range []string{`[null]`, `[""]`, `[["."]]`} {
		t.Run("prefix-elements/"+raw, func(t *testing.T) {
			refuse(t, rmEdit(t, w, "scope", func(m map[string]json.RawMessage) { m["path_prefixes"] = json.RawMessage(raw) }))
		})
	}
	for _, field := range []string{"symbols", "evidence_ids"} {
		for _, value := range []string{`null`, `[null]`, `[""]`, `["extra"]`, `[[],{}]`} {
			t.Run(field+value, func(t *testing.T) {
				refuse(t, rmEdit(t, w, "record", func(m map[string]json.RawMessage) { m[field] = json.RawMessage(value) }))
			})
		}
	}
	refuse(t, rmEdit(t, w, "envelope", func(m map[string]json.RawMessage) { m["input_identity"] = rmJSON(t, rmHash(rmInputBytes(t, w))) }))
	for _, field := range []string{"allowed_paths", "records"} {
		for _, value := range []string{`[]`, `[null]`, `[""]`, `[[[]]]`} {
			t.Run(field+value, func(t *testing.T) {
				refuse(t, rmEdit(t, w, "envelope", func(m map[string]json.RawMessage) { m[field] = json.RawMessage(value) }))
			})
		}
	}
}

func rmBoundsExcept(t *testing.T, w rmEnvelopeWire, except string) {
	t.Helper()
	raw := rmJSON(t, w)
	if except != "raw" && len(raw) > 65536 {
		t.Fatal("fixture masked by raw bound")
	}
	if except != "records" && (len(w.Records) < 1 || len(w.Records) > 16) {
		t.Fatal("fixture masked by record count")
	}
	if except != "paths" && (len(w.Paths) < 1 || len(w.Paths) > 16) {
		t.Fatal("fixture masked by path count")
	}
	if except != "decoded" && rmDecodedBytes(t, raw) > 32768 {
		t.Fatal("fixture masked by decoded string bound")
	}
	total := 0
	for _, record := range w.Records {
		if except != "record" && len(rmJSON(t, record)) > 4096 {
			t.Fatal("fixture masked by canonical record bound")
		}
		if except != "text" && len(record.Text) > 1024 {
			t.Fatal("fixture masked by text bound")
		}
		if except != "path" && len(record.Path) > 1024 {
			t.Fatal("fixture masked by native path bound")
		}
		total += len(record.Text)
	}
	if except != "total" && total > 8192 {
		t.Fatal("fixture masked by aggregate text bound")
	}
	for _, path := range w.Paths {
		if except != "path" && len(path) > 1024 {
			t.Fatal("fixture masked by allowed native path bound")
		}
	}
}

func TestLoadProtectedRetainedMemoryInputEnforcesIndependentBounds(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	base := rmEnvelope(t, policy.Identity(), 1, "x")
	at := time.UnixMilli(rmObserved)
	for _, size := range []int{65536, 65537} {
		t.Run(fmt.Sprintf("raw/%d", size), func(t *testing.T) {
			raw := rmJSON(t, base)
			raw = append(raw, bytes.Repeat([]byte{' '}, size-len(raw))...)
			rmBoundsExcept(t, base, "raw")
			if len(raw) != size {
				t.Fatal("raw fixture size drift")
			}
			rmLoadBytes(t, raw, base, policy, at, size == 65536)
		})
	}
	for _, count := range []int{0, 16, 17} {
		t.Run(fmt.Sprintf("records/%d", count), func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), count, "x")
			if count == 0 {
				w.Paths = []string{"unused"}
			}
			// Seventeen unique record paths require seventeen allowed paths; no isolated 17-record positive-shape envelope exists.
			if count != 17 {
				rmBoundsExcept(t, w, "records")
			}
			rmLoadBytes(t, rmJSON(t, w), w, policy, at, count == 16)
		})
		t.Run(fmt.Sprintf("paths/%d", count), func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "x")
			w.Paths = []string{}
			if count > 0 {
				w.Paths = append(w.Paths, w.Records[0].Path)
			}
			for i := 1; i < count; i++ {
				w.Paths = append(w.Paths, fmt.Sprintf("unused/%02d", i))
			}
			rmBoundsExcept(t, w, "paths")
			rmLoadBytes(t, rmJSON(t, w), w, policy, at, count == 16)
		})
	}
	for _, size := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("record/%d", size), func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, strings.Repeat("<", 580))
			padding := size - len(rmJSON(t, w.Records[0]))
			if padding < 0 {
				t.Fatal("record sizing fixture drift")
			}
			w.Records[0].Text += strings.Repeat("x", padding)
			rmReseal(t, &w, true)
			if len(rmJSON(t, w.Records[0])) != size {
				t.Fatal("canonical record fixture size drift")
			}
			rmBoundsExcept(t, w, "record")
			rmLoadBytes(t, rmJSON(t, w), w, policy, at, size == 4096)
		})
	}
	for _, size := range []int{1024, 1025} {
		for _, metric := range []string{"text", "path"} {
			t.Run(fmt.Sprintf("%s/%d", metric, size), func(t *testing.T) {
				w := rmEnvelope(t, policy.Identity(), 1, "x")
				value := strings.Repeat("é", size/2) + strings.Repeat("x", size%2)
				if metric == "text" {
					w.Records[0].Text = value
				} else {
					w.Records[0].Path = value
					w.Paths = []string{value}
				}
				rmReseal(t, &w, metric == "text" || size == 1024)
				rmBoundsExcept(t, w, metric)
				rmLoadBytes(t, rmJSON(t, w), w, policy, at, size == 1024)
			})
		}
	}
	for _, total := range []int{8192, 8193} {
		t.Run(fmt.Sprintf("total/%d", total), func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 9, strings.Repeat("x", 1024))
			w.Records[0].Text = strings.Repeat("x", 512)
			w.Records[1].Text = strings.Repeat("x", total-7680)
			rmReseal(t, &w, true)
			rmBoundsExcept(t, w, "total")
			got := 0
			for _, r := range w.Records {
				got += len(r.Text)
			}
			if got != total {
				t.Fatal("aggregate text fixture drift")
			}
			rmLoadBytes(t, rmJSON(t, w), w, policy, at, total == 8192)
		})
	}
	for _, total := range []int{32768, 32769} {
		t.Run(fmt.Sprintf("decoded/%d", total), func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 15, "x")
			w.Paths = []string{}
			for i := range w.Records {
				w.Records[i].Path = fmt.Sprintf("p%02d", i)
				w.Paths = append(w.Paths, w.Records[i].Path)
			}
			w.Paths = append(w.Paths, "z")
			rmReseal(t, &w, true)
			extra := total - rmDecodedBytes(t, rmJSON(t, w))
			if extra < 0 {
				t.Fatal("decoded sizing fixture drift")
			}
			w.Paths = []string{}
			for i := range w.Records {
				w.Records[i].Path += strings.Repeat("x", extra/30)
				w.Paths = append(w.Paths, w.Records[i].Path)
			}
			w.Paths = append(w.Paths, "z"+strings.Repeat("x", extra%30))
			rmReseal(t, &w, true)
			raw := rmJSON(t, w)
			if rmDecodedBytes(t, raw) != total {
				t.Fatal("decoded fixture drift; count keys and repeated values")
			}
			rmBoundsExcept(t, w, "decoded")
			rmLoadBytes(t, raw, w, policy, at, total == 32768)
			// Escape decoded keys without changing their byte count or approaching the raw bound.
			escaped := bytes.ReplaceAll(raw, []byte(`"text"`), []byte(`"\u0074ext"`))
			if len(escaped) > 65536 || rmDecodedBytes(t, escaped) != total {
				t.Fatal("escaped decoded fixture drift")
			}
			rmLoadBytes(t, escaped, w, policy, at, total == 32768)
		})
	}
}

func TestLoadProtectedRetainedMemoryInputRejectsDeclaredScopeAndBinding(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	base := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	at := time.UnixMilli(rmObserved)
	for _, field := range []string{"tenant", "logical-repository", "actor", "visibility", "prefix", "head"} {
		t.Run("reconstructed-foreign/"+field, func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			switch field {
			case "tenant":
				w.Scope.Tenant = "tenant-b"
			case "logical-repository":
				w.Scope.Repository = "logical-other"
			case "actor":
				w.Scope.Actor = "other-reviewer"
			case "visibility":
				w.Scope.Visibility = "reachable"
			case "prefix":
				w.Scope.Prefixes = []string{"src"}
			case "head":
				w.Head.Digest = strings.Repeat("b", 40)
			}
			rmReseal(t, &w, true)
			if w.Scope.Identity == base.Scope.Identity || w.Records[0].Identity == base.Records[0].Identity {
				t.Fatal("foreign scope was relabeled with expected identity")
			}
			rmLoadBytes(t, rmJSON(t, w), base, policy, at, false)
			if field == "actor" || field == "visibility" || field == "prefix" {
				rmLoadBytes(t, rmJSON(t, w), w, policy, at, false)
			} else {
				rmLoadBytes(t, rmJSON(t, w), w, policy, at, true)
			}
		})
	}
	for _, test := range []struct{ level, key, raw string }{
		{"scope", "tenant_id", `"INVALID"`}, {"scope", "repository_id", `"../repo"`}, {"scope", "actor_id", `" actor "`},
		{"scope", "identity", `"forged"`}, {"scope", "ref_visibility", `"unknown"`},
		{"scope", "path_prefixes", `["src","."]`}, {"scope", "path_prefixes", `[".","src"]`}, {"scope", "path_prefixes", `[".","."]`}, {"scope", "path_prefixes", `[]`},
		{"head_revision", "kind", `"tree"`}, {"head_revision", "algorithm", `"md5"`}, {"head_revision", "digest", `"aaaaaaaa"`},
		{"head_revision", "digest", `"0000000000000000000000000000000000000000"`}, {"head_revision", "digest", `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`},
		{"head_revision", "identity", `"forged"`}, {"scope", "ref_set_identity", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`},
	} {
		t.Run(test.level+"/"+test.key+test.raw, func(t *testing.T) {
			raw := rmEdit(t, base, test.level, func(m map[string]json.RawMessage) { m[test.key] = json.RawMessage(test.raw) })
			rmLoadBytes(t, raw, base, policy, at, false)
		})
	}
	for _, field := range []string{"repository_identity", "runtime_policy_identity"} {
		t.Run(field, func(t *testing.T) {
			raw := rmEdit(t, base, "envelope", func(m map[string]json.RawMessage) { m[field] = rmJSON(t, strings.Repeat("b", 64)) })
			rmLoadBytes(t, raw, base, policy, at, false)
		})
	}
	for _, path := range []string{".", "..", "../escape", "/absolute", "src/../file.go", "src//file.go", "src\\file.go", "src/\x01file.go"} {
		t.Run("unsafe-path/"+path, func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			w.Paths = []string{path}
			w.Records[0].Path = path
			rmReseal(t, &w, path == ".")
			rmLoadBytes(t, rmJSON(t, w), base, policy, at, false)
		})
	}
	for _, mutation := range []string{"outside-allowed", "outside-declared", "duplicate-path", "duplicate-id", "reverse-records", "reverse-paths", "duplicate-allowed"} {
		t.Run(mutation, func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 2, "operator advisory")
			switch mutation {
			case "outside-allowed":
				w.Paths = []string{"unused"}
			case "outside-declared":
				w.Scope.Prefixes = []string{"other"}
				rmReseal(t, &w, false)
			case "duplicate-path":
				w.Records[1].Path = w.Records[0].Path
				w.Records[1].Text = "distinct note"
				rmReseal(t, &w, true)
			case "duplicate-id":
				w.Records[1] = w.Records[0]
			case "reverse-records":
				w.Records[0], w.Records[1] = w.Records[1], w.Records[0]
			case "reverse-paths":
				w.Paths[0], w.Paths[1] = w.Paths[1], w.Paths[0]
			case "duplicate-allowed":
				w.Paths = append(w.Paths, w.Paths[1])
			}
			rmLoadBytes(t, rmJSON(t, w), base, policy, at, false)
		})
	}
	sha256Head := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	sha256Head.Head.Algorithm = "sha256"
	sha256Head.Head.Digest = strings.Repeat("c", 64)
	rmReseal(t, &sha256Head, true)
	rmLoadBytes(t, rmJSON(t, sha256Head), sha256Head, policy, at, true)
	rawDigestScope := sha256Head
	rawDigestScope.Scope.RefSet = rawDigestScope.Head.Digest
	rawDigestScope.Scope.Identity = rmHash(rmScopeBytes(t, rawDigestScope.Scope))
	rawDigestScope.Records = append([]rmRecordWire(nil), sha256Head.Records...)
	for i := range rawDigestScope.Records {
		r := &rawDigestScope.Records[i]
		r.Evidence = []string{"operator-note:" + rmHash(rmNoteBytes(t, rawDigestScope.Scope.Identity, *r))}
		r.Identity = rmHash(rmRecordBytes(t, rawDigestScope.Scope.Identity, *r))
		rmNativeRecord(t, rmScope(t, rawDigestScope.Scope), *r)
	}
	rmLoadBytes(t, rmJSON(t, rawDigestScope), rawDigestScope, policy, at, false)
}

func TestLoadProtectedRetainedMemoryInputRejectsUnapprovedRecord(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	base := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	at := time.UnixMilli(rmObserved)
	for _, kind := range []string{"canonical_fact", "review_episode", "derived_observation", "unknown"} {
		t.Run("kind/"+kind, func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			w.Records[0].Kind = kind
			// Derived observation cannot be native-valid with the required empty derivation fields.
			rmReseal(t, &w, kind == "canonical_fact" || kind == "review_episode")
			rmLoadBytes(t, rmJSON(t, w), base, policy, at, false)
		})
	}
	for _, taint := range []string{"trusted", "repository_controlled", "external_unverified", "unknown"} {
		t.Run("taint/"+taint, func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			w.Records[0].Taint = taint
			rmReseal(t, &w, taint != "unknown")
			rmLoadBytes(t, rmJSON(t, w), base, policy, at, false)
		})
	}
	for _, mutation := range []string{"producer", "arbitrary-evidence", "wrong-note", "multiple-evidence", "url-evidence", "record-id", "note-text", "note-path", "note-observed", "note-from", "note-until"} {
		t.Run(mutation, func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			r := &w.Records[0]
			switch mutation {
			case "producer":
				r.Producer = strings.Repeat("b", 64)
			case "arbitrary-evidence":
				r.Evidence = []string{"arbitrary-note"}
			case "wrong-note":
				r.Evidence = []string{"operator-note:" + strings.Repeat("b", 64)}
			case "multiple-evidence":
				r.Evidence = append(r.Evidence, "operator-note:"+strings.Repeat("f", 64))
				sort.Strings(r.Evidence)
			case "url-evidence":
				r.Evidence = []string{"https://example.test/claim"}
			case "note-text":
				r.Text = "changed text with old note ID"
			case "note-path":
				r.Path = "src/other.go"
				w.Paths = []string{r.Path}
			case "note-observed":
				r.Observed++
			case "note-from":
				r.From--
			case "note-until":
				r.Until++
			}
			r.Identity = rmHash(rmRecordBytes(t, w.Scope.Identity, *r))
			if mutation == "record-id" {
				r.Identity = strings.Repeat("b", 64)
			} else if mutation != "url-evidence" {
				rmNativeRecord(t, rmScope(t, w.Scope), *r)
			}
			rmLoadBytes(t, rmJSON(t, w), base, policy, time.UnixMilli(rmObserved+1), false)
		})
	}
	for _, text := range []string{"", " \n\t", "hidden\x00text", "hidden\rtext", "hidden\u200btext"} {
		t.Run("text/"+fmt.Sprintf("%q", text), func(t *testing.T) {
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			w.Records[0].Text = text
			rmReseal(t, &w, false)
			rmLoadBytes(t, rmJSON(t, w), base, policy, at, false)
		})
	}
}

func TestLoadProtectedRetainedMemoryInputValidatesPolicySurface(t *testing.T) {
	for _, test := range []struct {
		name          string
		zone          provider.ProviderZone
		endpoint      string
		mixed, accept bool
	}{
		{"loopback-v4", provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false, true},
		{"loopback-v6", provider.ProviderZoneLocal, "http://[::1]:11434/v1", false, true},
		{"mixed-allowance", provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", true, true},
		{"remote", provider.ProviderZonePrivateRemote, "https://example.test/v1", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := rmPolicy(t, test.zone, test.endpoint, test.mixed)
			w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			rmLoadBytes(t, rmJSON(t, w), w, policy, time.UnixMilli(rmObserved), test.accept)
		})
	}
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	path := rmProtectedFile(t, rmJSON(t, w))
	scope, repository, at := rmScope(t, w.Scope), rmRepository(t, "source-repository"), time.UnixMilli(rmObserved)
	for _, test := range []struct {
		name       string
		scope      memory.Scope
		repository evidence.RepositoryIdentity
		policy     RuntimePolicy
	}{
		{"zero-policy", scope, repository, RuntimePolicy{}},
		{"zero-repository", scope, evidence.RepositoryIdentity{}, policy},
		{"foreign-repository", scope, rmRepository(t, "other-source"), policy},
		{"zero-scope", memory.Scope{}, repository, policy},
		{"other-local-policy", scope, repository, rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11435/v1", false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := LoadProtectedRetainedMemoryInput(context.Background(), path, test.scope, test.repository, test.policy, at)
			rmError(t, err)
			rmZero(t, value)
		})
	}
	// Malformed policies can only be obtained as decoder refusals, not by seeding private policy fields.
	definition := routeDefinition(t, "model-a")
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{definition})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"http://example.test/v1", "https://localhost/v1", "https://user:secret@example.test/v1", "https://example.test/v1?secret=x", "https://[0:0:0:0:0:0:0:1]/v1"} {
		t.Run("malformed-policy/"+endpoint, func(t *testing.T) {
			document := bytes.Replace(runtimePolicyDocument(t, inventory), []byte("https://api.openai.com/v1"), []byte(endpoint), 1)
			invalid, decodeErr := DecodeRuntimePolicy(context.Background(), bytes.NewReader(document), inventory)
			if decodeErr == nil || invalid.Identity() != "" {
				t.Fatal("malformed policy fixture did not refuse")
			}
			value, loadErr := LoadProtectedRetainedMemoryInput(context.Background(), path, scope, repository, invalid, at)
			rmError(t, loadErr)
			rmZero(t, value)
		})
	}
}

func TestRetainedMemoryInputValidateForTimeBounds(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	scope, repository := rmScope(t, w.Scope), rmRepository(t, "source-repository")
	loaded := rmLoadBytes(t, rmJSON(t, w), w, policy, time.UnixMilli(rmObserved), true)
	identity := loaded.Identity()
	for _, test := range []struct {
		name   string
		at     time.Time
		accept bool
	}{
		{"observed-inclusive", time.UnixMilli(rmObserved), true},
		{"offset", time.UnixMilli(rmObserved).In(time.FixedZone("west", -7*3600)), true},
		{"observed-sub-ms", time.UnixMilli(rmObserved).Add(999999 * time.Nanosecond), true},
		{"before-observed-sub-ms", time.UnixMilli(rmObserved).Add(-time.Nanosecond), false},
		{"before-expiry-sub-ms", time.UnixMilli(rmUntil).Add(-time.Nanosecond), true},
		{"expiry-exclusive", time.UnixMilli(rmUntil), false},
		{"expired", time.UnixMilli(rmUntil + 1), false},
		{"zero", time.Time{}, false}, {"negative", time.UnixMilli(-1), false},
		{"before-minimum-sub-ms", time.UnixMilli(1).Add(-time.Nanosecond), false},
		{"upper-exclusive", time.UnixMilli(rmMaximum + 1), false},
		{"year-10000", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := loaded.ValidateFor(scope, repository, policy, test.at)
			if test.accept {
				if err != nil {
					t.Fatal("valid instant refused")
				}
			} else {
				rmError(t, err)
			}
			rmLoadBytes(t, rmJSON(t, w), w, policy, test.at, test.accept)
			if loaded.Identity() != identity || loaded.Records()[0].ValidUntilUnixMilliseconds() != rmUntil {
				t.Fatal("validation mutated historical identity or dates")
			}
		})
	}
	for _, index := range []int{0, 1} {
		mixed := rmEnvelope(t, policy.Identity(), 2, "operator advisory")
		mixed.Records[index].Until = rmObserved + 1
		rmReseal(t, &mixed, true)
		rmLoadBytes(t, rmJSON(t, mixed), mixed, policy, time.UnixMilli(rmObserved), true)
		rmLoadBytes(t, rmJSON(t, mixed), mixed, policy, time.UnixMilli(rmObserved+1), false)
	}
	near := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
	near.Records[0].Observed, near.Records[0].From, near.Records[0].Until = rmMaximum-1, rmMaximum-1, rmMaximum
	rmReseal(t, &near, true)
	rmLoadBytes(t, rmJSON(t, near), near, policy, time.UnixMilli(rmMaximum).Add(-time.Nanosecond), true)
	rmLoadBytes(t, rmJSON(t, near), near, policy, time.UnixMilli(rmMaximum).Add(999999*time.Nanosecond), false)
	for _, test := range []struct {
		name                      string
		observed, from, until, at int64
		native, accept            bool
	}{
		{"minimum", 1, 1, 2, 1, true, true},
		{"seven-days", rmObserved, rmObserved - 1, rmObserved + 604800000, rmObserved, true, true},
		{"no-invented-maximum-age", rmObserved, rmObserved - 604800000, rmObserved + 604800000, rmObserved + 604799999, true, true},
		{"seven-days-plus-ms", rmObserved, rmObserved, rmObserved + 604800001, rmObserved, true, false},
		{"near-maximum", rmMaximum - 1, rmMaximum - 1, rmMaximum, rmMaximum - 1, true, true},
		{"future-observed", rmObserved + 1, rmObserved, rmUntil, rmObserved, true, false},
		{"from-after-observed", rmObserved, rmObserved + 1, rmUntil, rmObserved, false, false},
		{"until-equals-observed", rmObserved, rmObserved - 1, rmObserved, rmObserved, true, false},
		{"until-before-observed", rmObserved, rmObserved - 2, rmObserved - 1, rmObserved, true, false},
		{"until-zero", rmObserved, rmObserved, 0, rmObserved, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := rmEnvelope(t, policy.Identity(), 1, "operator advisory")
			changed.Records[0].Observed, changed.Records[0].From, changed.Records[0].Until = test.observed, test.from, test.until
			rmReseal(t, &changed, test.native)
			rmLoadBytes(t, rmJSON(t, changed), changed, policy, time.UnixMilli(test.at), test.accept)
		})
	}
}

func TestRetainedMemoryInputCopiesFormattingAndPureRevalidation(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 2, "private operator advisory")
	scope, repository, at := rmScope(t, w.Scope), rmRepository(t, "source-repository"), time.UnixMilli(rmObserved)
	path := rmProtectedFile(t, rmJSON(t, w))
	value, err := LoadProtectedRetainedMemoryInput(context.Background(), path, scope, repository, policy, at)
	if err != nil {
		t.Fatal("protected fixture refused")
	}
	identity := value.Identity()
	before := value.Records()
	records := value.Records()
	evidenceIDs := records[0].EvidenceIDs()
	evidenceIDs[0] = "mutated"
	prefixes := value.Scope().PathPrefixes()
	prefixes[0] = "mutated"
	for _, empty := range [][]string{records[0].Symbols(), records[0].DerivedFromIDs(), records[0].CounterEvidenceIDs()} {
		if len(empty) != 0 {
			t.Fatal("unexpected native authority slice")
		}
		empty = append(empty, "mutated")
		if len(empty) != 1 {
			t.Fatal("copy fixture drift")
		}
	}
	records[0] = memory.Record{}
	if !reflect.DeepEqual(value.Records(), before) || !reflect.DeepEqual(value.Scope(), scope) || value.Identity() != identity {
		t.Fatal("getter exposed mutable alias")
	}
	rmFormat(t, value)
	var zero RetainedMemoryInput
	if err := json.Unmarshal(rmJSON(t, w), &zero); err != nil {
		t.Fatal(err)
	}
	rmZero(t, zero)
	rmError(t, zero.ValidateFor(scope, repository, policy, at))
	changed := rmEnvelope(t, policy.Identity(), 2, "replacement operator advisory")
	replacement := filepath.Join(filepath.Dir(path), "replacement")
	if err := os.WriteFile(replacement, rmJSON(t, changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadProtectedRetainedMemoryInput(context.Background(), path, scope, repository, policy, at)
	if err != nil || reopened.Identity() != rmHash(rmInputBytes(t, changed)) || reopened.Identity() == identity {
		t.Fatal("reopen reused old pathname authority")
	}
	if err := os.WriteFile(path, []byte(`{"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid, err := LoadProtectedRetainedMemoryInput(context.Background(), path, scope, repository, policy, at)
	rmError(t, err)
	rmZero(t, invalid)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if value.ValidateFor(scope, repository, policy, at) != nil || value.Identity() != identity || !reflect.DeepEqual(value.Records(), before) {
		t.Fatal("pure snapshot validation depended on pathname or replacement")
	}
	missing, err := LoadProtectedRetainedMemoryInput(context.Background(), path, scope, repository, policy, at)
	rmError(t, err)
	rmZero(t, missing)
	foreign := rmEnvelope(t, policy.Identity(), 2, "private operator advisory")
	foreign.Scope.Tenant = "tenant-b"
	rmReseal(t, &foreign, true)
	for _, test := range []struct {
		name       string
		scope      memory.Scope
		repository evidence.RepositoryIdentity
		policy     RuntimePolicy
		at         time.Time
	}{
		{"scope", rmScope(t, foreign.Scope), repository, policy, at},
		{"repository", scope, rmRepository(t, "other-source"), policy, at},
		{"policy", scope, repository, rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11435/v1", false), at},
		{"zero-scope", memory.Scope{}, repository, policy, at},
		{"zero-repository", scope, evidence.RepositoryIdentity{}, policy, at},
		{"invalid-policy", scope, repository, RuntimePolicy{}, at},
		{"remote-policy", scope, repository, rmPolicy(t, provider.ProviderZonePrivateRemote, "https://example.test/v1", false), at},
		{"expired", scope, repository, policy, time.UnixMilli(rmUntil)},
	} {
		t.Run(test.name, func(t *testing.T) { rmError(t, value.ValidateFor(test.scope, test.repository, test.policy, test.at)) })
	}
}

func TestLoadProtectedRetainedMemoryInputProtectedRefusals(t *testing.T) {
	policy := rmPolicy(t, provider.ProviderZoneLocal, "http://127.0.0.1:11434/v1", false)
	w := rmEnvelope(t, policy.Identity(), 1, "private operator advisory")
	scope, repository, at := rmScope(t, w.Scope), rmRepository(t, "source-repository"), time.UnixMilli(rmObserved)
	for _, mutation := range []string{"missing", "directory", "group-writable-file", "world-writable-file", "group-writable-parent", "world-writable-parent", "symlink-file", "symlink-parent", "nil-context", "canceled", "malformed-plus-binding", "expired-plus-binding"} {
		t.Run(mutation, func(t *testing.T) {
			path := rmProtectedFile(t, rmJSON(t, w))
			ctx := context.Background()
			expected := repository
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "missing":
				check(os.Remove(path))
			case "directory":
				path = filepath.Dir(path)
			case "group-writable-file":
				check(os.Chmod(path, 0o620))
			case "world-writable-file":
				check(os.Chmod(path, 0o602))
			case "group-writable-parent":
				check(os.Chmod(filepath.Dir(path), 0o720))
			case "world-writable-parent":
				check(os.Chmod(filepath.Dir(path), 0o702))
			case "symlink-file":
				link := path + ".link"
				check(os.Symlink(path, link))
				path = link
			case "symlink-parent":
				linkDir := t.TempDir()
				check(os.Chmod(linkDir, 0o700))
				link := filepath.Join(linkDir, "linked")
				check(os.Symlink(filepath.Dir(path), link))
				path = filepath.Join(link, filepath.Base(path))
			case "nil-context":
				ctx = nil
			case "canceled":
				canceled, cancel := context.WithCancel(context.Background())
				cancel()
				ctx = canceled
			case "malformed-plus-binding":
				check(os.WriteFile(path, []byte(`{"private-text":`), 0o600))
				expected = rmRepository(t, "other-source")
			case "expired-plus-binding":
				changed := rmEnvelope(t, policy.Identity(), 1, "private operator advisory")
				changed.Records[0].Observed -= 120000
				changed.Records[0].From -= 120000
				changed.Records[0].Until -= 120000
				rmReseal(t, &changed, true)
				check(os.WriteFile(path, rmJSON(t, changed), 0o600))
				expected = rmRepository(t, "other-source")
			}
			value, err := LoadProtectedRetainedMemoryInput(ctx, path, scope, expected, policy, at)
			rmError(t, err)
			rmZero(t, value)
		})
	}
}
