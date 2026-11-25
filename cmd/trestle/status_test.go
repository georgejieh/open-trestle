package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/spending"
)

func runStatusIn(t *testing.T, folder string, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(folder)
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"status"}, args...), &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
		t.Fatal("trestle status printed the key")
	}
	return code, stdout.String(), stderr.String()
}

func TestStatusPrintsLabelValueLinesWithoutATerminal(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	code, out, errText := runStatusIn(t, checkout)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || errText != "" || len(lines) != 7 || strings.Contains(out, "\x1b") {
		t.Fatalf("exit=%d\n%s%s", code, out, errText)
	}
	for i, want := range []string{
		"Repository:  ", "Setup:       ~/.local/state/open-trestle/",
		"Models:      finder gemma4:31b · checker qwen3.5:397b",
		"Runs on:     Ollama Cloud (https://ollama.com/v1)",
		"Key:         OPEN_TRESTLE_PROVIDER_REMOTE_TEST (from the environment)",
		"Spending:    $0.00 recorded this month; no limit set (an upper-bound estimate, not a bill)",
		"Last run:    none recorded yet",
	} {
		if !strings.HasPrefix(lines[i], want) {
			t.Fatalf("line %d is %q, want %q", i+1, lines[i], want)
		}
	}
	if !strings.HasSuffix(lines[0], "(on branch review)") {
		t.Fatalf("repository line: %q", lines[0])
	}
	// A missing key is a row to fix, not an unusable setup.
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
	code, out, _ = runStatusIn(t, checkout)
	if want := "Key:         OPEN_TRESTLE_PROVIDER_REMOTE_TEST (not set) -> trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST\n"; code != 0 || !strings.Contains(out, want) {
		t.Fatalf("missing key: exit=%d\n%s", code, out)
	}
}

func TestStatusFailsWithoutAUsableSetup(t *testing.T) {
	keyStoreForTest(t)
	t.Setenv("HOME", t.TempDir())
	if code, out, _ := runStatusIn(t, t.TempDir()); code != 1 || out != "Repository:  none: this folder is not inside a Git checkout, or git is not installed -> cd REPOSITORY && trestle status\n" {
		t.Fatalf("outside a repository: exit=%d %q", code, out)
	}
	code, out, _ := runStatusIn(t, latestChangeCheckout(t))
	if code != 1 || !strings.HasSuffix(out, "\nSetup:       none yet -> trestle init\n") {
		t.Fatalf("no setup: exit=%d %q", code, out)
	}
	code, out, _ = runStatusIn(t, t.TempDir(), "--json")
	var document struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Ready         bool   `json:"ready"`
		Rows          []struct {
			Label, Value, State string
			Next                []string
		} `json:"rows"`
	}
	if code != 1 || json.Unmarshal([]byte(out), &document) != nil || document.Contract != statusContract || document.SchemaVersion != 1 || document.Ready || len(document.Rows) != 1 || document.Rows[0].State != "fail" || document.Rows[0].Next[0] != "cd REPOSITORY && trestle status" {
		t.Fatalf("json: exit=%d %s", code, out)
	}
	if code, _, errText := runStatusIn(t, t.TempDir(), "--full"); code != 2 || !strings.HasPrefix(errText, "usage: trestle status") {
		t.Fatalf("unknown flag: exit=%d %q", code, errText)
	}
}

func TestStatusJSONHasTheCardRows(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	code, out, _ := runStatusIn(t, checkout, "--json")
	var document struct {
		Ready bool                `json:"ready"`
		Rows  []map[string]string `json:"rows"`
	}
	if code != 0 || strings.Count(out, "\n") != 1 || json.Unmarshal([]byte(out), &document) != nil || !document.Ready {
		t.Fatalf("exit=%d %s", code, out)
	}
	labels := []string{}
	for _, row := range document.Rows {
		if row["state"] != "ok" || row["value"] == "" {
			t.Fatalf("row: %v", row)
		}
		labels = append(labels, row["label"])
	}
	if strings.Join(labels, ",") != "Repository,Setup,Models,Runs on,Key,Spending,Last run" {
		t.Fatalf("labels: %v", labels)
	}
}

// The card measures its width on visible characters, so marks and tones
// keep every line of the frame at initWidth columns.
func TestStatusCardKeepsItsFrameWithColor(t *testing.T) {
	rows := []healthRow{
		{Label: "Repository", Value: "~/work/app (on branch main)", State: healthOK},
		{Label: "Key", Value: "OPEN_TRESTLE_PROVIDER_OPENROUTER (not set)", State: healthFail, Next: []string{"trestle keys set OPEN_TRESTLE_PROVIDER_OPENROUTER"}},
		{Label: "Spending", Value: "$9.00 of your $10.00 monthly limit this month (90%), alerts at 80% and 100% (an upper-bound estimate, not a bill)", State: healthAttention, Next: []string{"trestle usage"}, tone: initToneWarning},
		{Label: "Update", Value: "available: 0.2.0 (you have 0.1.0)", State: healthAttention, Next: []string{"trestle update"}},
	}
	for _, style := range []initStyle{{palette: initColor256}, {palette: initColorTrue}, {ascii: true}, {}} {
		lines := statusCard(style, "app", rows)
		card := strings.Join(lines, "\n")
		for _, line := range lines {
			if initVisible(line) != initWidth {
				t.Fatalf("card line is %d columns, want %d: %q\n%s", initVisible(line), initWidth, line, card)
			}
		}
		bad, wait := style.markOf(healthFail), style.markOf(healthAttention)
		plain := strings.NewReplacer("│", " ", "|", " ").Replace(initANSI.ReplaceAllString(card, ""))
		if !strings.Contains(card, bad+" ") || !strings.Contains(card, wait+" ") || !initHas(plain, "OPEN_TRESTLE_PROVIDER_OPENROUTER (not set) -> trestle keys set") || !initHas(plain, "(90%), alerts at 80% and 100%") {
			t.Fatalf("card lacks a mark or a value:\n%s", card)
		}
		if style.palette != initPlain && !strings.Contains(card, style.paint(initToneWarning, "(90%),")) {
			t.Fatalf("the spending row lost its tone:\n%q", card)
		}
	}
}

func TestHomeCardMarksRowsThatNeedActionAndShowsTheUpdate(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	useInteractiveHome(t)
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
	store := spendingTestStore(t)
	spendingTestLimit(t, store, 10_000_000, []int{80, 100})
	entry := spending.Entry{RecordedAt: spendingTestNow.Add(-time.Hour), ReviewRunID: "local-a", RuntimePolicyIdentity: strings.Repeat("ab", 32), Scopes: []spending.Scope{spendingTestScope(t)}, Models: []string{"gemma4:31b"}, RequestsSent: 2, UsageKnown: true, CostMicroUSD: 12_000_000}
	if err := store.Append(t.Context(), entry); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runHomeScript(t, checkout, "\n")
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	initAssertWidth(t, out)
	assertInOrder(t, out,
		"Key ✗ OPEN_TRESTLE_PROVIDER_REMOTE_TEST (not set) -> trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST",
		"Spending ✗ $12.00 of your $10.00 monthly limit", "-> trestle usage",
		"Update … available: 0.2.0 (you have 0.1.0) -> trestle update",
		"1) Review the latest change", "Update Open Trestle trestle update",
	)
	if strings.Contains(out, "Update available:") {
		t.Fatalf("the update notice is printed outside the card:\n%s", out)
	}
	// Rows that need nothing carry no mark.
	if !initHas(out, "Models finder gemma4:31b") {
		t.Fatalf("a row without a problem has a mark:\n%s", out)
	}
}
