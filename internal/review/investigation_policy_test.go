package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func investigationPolicyFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/investigation-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != "fb99a4928f1649c627875f854d6e82cfe7751d98ca6cd44d22987d0457fe5be8" {
		t.Fatal("policy contract fixture changed")
	}
	return b
}
func TestInvestigationPolicyCanonicalValueCannotRaiseRuntimeCap(t *testing.T) {
	b := investigationPolicyFixture(t)
	policy, err := ParseInvestigationPolicy(b)
	if err != nil || policy.Identity() == "" || policy.MaxCostMicroUSD() != 100000 {
		t.Fatal("canonical policy refused")
	}
	encoded, err := EncodeInvestigationPolicy(policy)
	if err != nil || !bytes.Equal(encoded, b) {
		t.Fatal("policy codec changed canonical bytes")
	}
	b[0] = 'x'
	encoded[0] = 'x'
	again, err := EncodeInvestigationPolicy(policy)
	if err != nil || !bytes.Equal(again, investigationPolicyFixture(t)) {
		t.Fatal("immutable policy aliases input or encoded output")
	}
	for _, cap := range []uint64{0, 99999, 100000, 100001} {
		runtime, err := provider.NewModelCostBudget(1, 4096, cap)
		if err != nil {
			t.Fatal(err)
		}
		err = policy.ValidateRuntimeBudget(runtime)
		if (err == nil) != (cap >= 100000) {
			t.Fatal("investigation changed existing monetary ceiling")
		}
	}
	for _, field := range []string{"max_returned_bytes", "max_scanned_bytes", "max_result_bytes", "max_model_turns", "max_tool_calls"} {
		b := investigationPolicyFixture(t)
		start := bytes.Index(b, []byte(`"`+field+`":`)) + len(field) + 3
		end := start
		for end < len(b) && b[end] >= '0' && b[end] <= '9' {
			end++
		}
		low := append(append(append([]byte(nil), b[:start]...), '1'), b[end:]...)
		if _, err := ParseInvestigationPolicy(low); err != nil {
			t.Fatalf("low valid %s budget converted runtime refusal to parsing failure", field)
		}
	}
}
func TestInvestigationPolicyRefusesAmbiguousUnboundedAuthority(t *testing.T) {
	base := string(investigationPolicyFixture(t))
	cases := map[string]string{
		"unknown":            strings.Replace(base, `"contract":`, `"callback":"shell","contract":`, 1),
		"duplicate":          strings.Replace(base, `"profile":"snapshot-read-v1"`, `"profile":"snapshot-read-v1","profile":"snapshot-read-v1"`, 1),
		"null":               strings.Replace(base, `"max_files":16`, `"max_files":null`, 1),
		"case":               strings.Replace(base, `"max_files":16`, `"Max_files":16`, 1),
		"missing":            strings.Replace(base, `"max_files":16,`, ``, 1),
		"fraction":           strings.Replace(base, `"max_files":16`, `"max_files":1.5`, 1),
		"decimal integer":    strings.Replace(base, `"max_files":16`, `"max_files":16.0`, 1),
		"exponent":           strings.Replace(base, `"max_files":16`, `"max_files":16e0`, 1),
		"negative":           strings.Replace(base, `"max_files":16`, `"max_files":-1`, 1),
		"overflow":           strings.Replace(base, `"max_cost_micro_usd":100000`, `"max_cost_micro_usd":18446744073709551616`, 1),
		"ceiling":            strings.Replace(base, `"max_files":16`, `"max_files":65`, 1),
		"zero count":         strings.Replace(base, `"max_files":16`, `"max_files":0`, 1),
		"version":            strings.Replace(base, `"schema_version":1`, `"schema_version":3`, 1),
		"profile":            strings.Replace(base, `snapshot-read-v1`, `shell-v1`, 1),
		"leading whitespace": " " + base,
		"trailing newline":   base + "\n",
		"two documents":      base + base,
		"space":              strings.Replace(base, `"max_files":16`, `"max_files": 16`, 1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if b == base {
				t.Fatal("mutation missed fixture")
			}
			p, err := ParseInvestigationPolicy([]byte(b))
			if err == nil || p.Identity() != "" {
				t.Fatal("invalid policy gained authority")
			}
		})
	}
}

func TestInvestigationPolicyEnforcesEveryHostCountCeiling(t *testing.T) {
	base := string(investigationPolicyFixture(t))
	for _, bound := range []struct {
		field         string
		current, over uint64
	}{
		{"max_model_turns", 5, 9}, {"max_tool_calls", 3, 7},
		{"max_returned_bytes", 32768, 262145}, {"max_scanned_bytes", 65536, 16777217},
		{"max_files", 16, 65}, {"max_lines_per_read", 20, 257},
		{"max_matches", 8, 65}, {"max_result_bytes", 8192, 65537},
		{"timeout_milliseconds", 5000, 900001},
	} {
		t.Run(bound.field, func(t *testing.T) {
			old := `"` + bound.field + `":` + strconv.FormatUint(bound.current, 10)
			changed := strings.Replace(base, old, `"`+bound.field+`":`+strconv.FormatUint(bound.over, 10), 1)
			if changed == base {
				t.Fatal("ceiling mutation missed fixture")
			}
			if _, err := ParseInvestigationPolicy([]byte(changed)); err == nil {
				t.Fatal("host ceiling exceeded")
			}
		})
	}
}

func TestInvestigationPolicyZeroValueAndMalformedBudgetRefuse(t *testing.T) {
	if _, err := EncodeInvestigationPolicy(InvestigationPolicy{}); err == nil {
		t.Fatal("zero policy encoded")
	}
	if (InvestigationPolicy{}).Validate() == nil {
		t.Fatal("zero policy validated")
	}
	p, err := ParseInvestigationPolicy(investigationPolicyFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.ValidateRuntimeBudget(provider.ModelCostBudget{}) == nil {
		t.Fatal("invalid host budget accepted")
	}
	p.identity = strings.Repeat("f", 64)
	if _, err := EncodeInvestigationPolicy(p); err == nil {
		t.Fatal("forged policy identity encoded")
	}
}
