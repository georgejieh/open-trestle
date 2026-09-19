package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const ambassadorBridgeArt = `       |X|\                     /|X|
    __/|X| \__               __/ |X|\__
 __/   |X| |  \____-----____/  |  |X|   \__
=======|X|=|==|==|==|==|==|==|==|=|X|=======
`

func TestAmbassadorBridgeArtworkLiteralFitsMinimumWidth(t *testing.T) {
	for index, line := range strings.Split(strings.TrimSuffix(ambassadorBridgeArt, "\n"), "\n") {
		if line == "" {
			t.Fatalf("bridge art line %d is empty", index+1)
		}
		for _, r := range line {
			if r > 127 {
				t.Fatalf("bridge art line %d contains non-ASCII rune %q", index+1, r)
			}
		}
		if width := utf8.RuneCountInString(line); width > minimumWidth {
			t.Fatalf("bridge art line %d width=%d exceeds minimum terminal width %d: %q", index+1, width, minimumWidth, line)
		}
	}
}

func TestRunRendererPreservesHeadingAndBridgeBrandingAcrossWidthsAndModes(t *testing.T) {
	for _, width := range []int{60, 100, 240} {
		for _, plain := range []bool{true, false} {
			name := fmt.Sprintf("width_%d_plain_%t", width, plain)
			t.Run(name, func(t *testing.T) {
				service, scope := tuiFixture(t)
				var output strings.Builder
				interface_, err := New(service, strings.NewReader(""), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: width, Plain: plain, Once: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := interface_.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				rendered := output.String()
				assertBridgeControlEnvelope(t, rendered, plain)
				assertBridgeAfterHeading(t, rendered, "OPEN TRESTLE")
				assertBridgeLinesFitWidth(t, width)
				assertLegacyEqualsRuleRemoved(t, rendered, width)
				for _, want := range []string{
					"OPEN TRESTLE\n",
					"Run         active",
					"available",
					"Verified diagnostics (text is untrusted)",
					"Avoid unchecked result",
					"Commands: r refresh  c cancel  q quit",
				} {
					if !strings.Contains(rendered, want) {
						t.Fatalf("missing %q in:\n%s", want, rendered)
					}
				}
			})
		}
	}
}

func TestSetupRendererPreservesHeadingAndBridgeBrandingAcrossWidthsAndModes(t *testing.T) {
	for _, width := range []int{60, 100, 240} {
		for _, plain := range []bool{true, false} {
			name := fmt.Sprintf("width_%d_plain_%t", width, plain)
			t.Run(name, func(t *testing.T) {
				interface_, output, state := setupInterfaceFixture(t, "")
				defer state.Close()
				interface_.options.Width = width
				interface_.options.Plain = plain
				interface_.options.Once = true
				if err := interface_.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				rendered := output.String()
				assertBridgeControlEnvelope(t, rendered, plain)
				assertBridgeAfterHeading(t, rendered, "OPEN TRESTLE SETUP")
				assertBridgeLinesFitWidth(t, width)
				assertLegacyEqualsRuleRemoved(t, rendered, width)
				for _, want := range []string{
					"OPEN TRESTLE SETUP\n",
					"Readiness  incomplete",
					"local single node",
					"state storage posture validated",
					"Receipt history",
					"Commands: j next  k previous  x run selected",
				} {
					if !strings.Contains(rendered, want) {
						t.Fatalf("missing %q in:\n%s", want, rendered)
					}
				}
			})
		}
	}
}

func assertBridgeControlEnvelope(t *testing.T, rendered string, plain bool) {
	t.Helper()
	if plain {
		if !strings.HasPrefix(rendered, "---\n") {
			t.Fatalf("plain output lost frame separator: %q", firstRenderedLine(rendered))
		}
		if strings.Contains(rendered, "\x1b[") {
			t.Fatalf("plain output contains terminal control sequence:\n%s", rendered)
		}
		return
	}
	if !strings.HasPrefix(rendered, "\x1b[H\x1b[2J") {
		t.Fatalf("nonplain output lost clear-screen control prefix: %q", firstRenderedLine(rendered))
	}
	if strings.HasPrefix(rendered, "---\n") {
		t.Fatalf("nonplain output contains plain frame separator")
	}
}

func assertBridgeAfterHeading(t *testing.T, rendered, heading string) {
	t.Helper()
	headingWithNewline := heading + "\n"
	index := strings.Index(rendered, headingWithNewline)
	if index < 0 {
		t.Fatalf("missing heading %q in:\n%s", heading, rendered)
	}
	afterHeading := rendered[index+len(headingWithNewline):]
	if !strings.HasPrefix(afterHeading, ambassadorBridgeArt) {
		t.Fatalf("heading %q is not immediately followed by frozen Ambassador Bridge art; next text is:\n%s", heading, firstRenderedLines(afterHeading, 6))
	}
	if count := strings.Count(rendered, ambassadorBridgeArt); count != 1 {
		t.Fatalf("bridge art count=%d, want 1 in:\n%s", count, rendered)
	}
}

func assertBridgeLinesFitWidth(t *testing.T, width int) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSuffix(ambassadorBridgeArt, "\n"), "\n") {
		if lineWidth := utf8.RuneCountInString(line); lineWidth > width {
			t.Fatalf("bridge line width=%d exceeds terminal width=%d: %q", lineWidth, width, line)
		}
	}
}

func assertLegacyEqualsRuleRemoved(t *testing.T, rendered string, width int) {
	t.Helper()
	ruleWidth := width
	if ruleWidth > 72 {
		ruleWidth = 72
	}
	legacyRule := "\n" + strings.Repeat("=", ruleWidth) + "\n"
	if strings.Contains(rendered, legacyRule) {
		t.Fatalf("legacy equals-sign brand rule is still rendered for width=%d", width)
	}
}

func firstRenderedLine(rendered string) string {
	if index := strings.IndexByte(rendered, '\n'); index >= 0 {
		return rendered[:index]
	}
	return rendered
}

func firstRenderedLines(rendered string, count int) string {
	lines := strings.Split(rendered, "\n")
	if len(lines) > count {
		lines = lines[:count]
	}
	return strings.Join(lines, "\n")
}
