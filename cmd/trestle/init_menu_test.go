package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/modelcatalog"
)

// fakeKeyTerminal is a terminal that can also be read one key at a time. It
// records raw mode, so tests can check that the terminal is always restored.
type fakeKeyTerminal struct {
	*fakeEchoTerminal
	mu             sync.Mutex
	raw            bool
	raws, restores int
}

func (f *fakeKeyTerminal) rawInput() (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw = true
	f.raws++
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.raw = false
		f.restores++
		return nil
	}, nil
}

func (f *fakeKeyTerminal) assertRestored(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.raw || f.raws == 0 || f.raws != f.restores {
		t.Fatalf("raw mode not restored: raw=%v raws=%d restores=%d", f.raw, f.raws, f.restores)
	}
}

// useFakeKeyTerminal makes the wizard show menus: standard input is a key
// terminal, standard output a terminal.
func useFakeKeyTerminal(t *testing.T) *fakeKeyTerminal {
	t.Helper()
	terminal := &fakeKeyTerminal{fakeEchoTerminal: newFakeEchoTerminal()}
	previous, previousOutput := openEchoTerminal, initEnableTerminalOutput
	openEchoTerminal = func(io.Reader) (echoTerminal, bool) { return terminal, true }
	initEnableTerminalOutput = func(io.Writer) (func(), bool) { return func() {}, true }
	t.Cleanup(func() { openEchoTerminal, initEnableTerminalOutput = previous, previousOutput })
	initAsTerminal(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	return terminal
}

func TestReadMenuKeyDecodesKeysAndSequences(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\x1b[A\x1b[B\x1bOC\x1b[D\x1b[5~\x1b[6~\x1b[H\x1b[4~\r\n\x7f\x15\x03\x04é\x1bq\x1b[1;5A\x1b"))
	want := []menuKey{{kind: menuUp}, {kind: menuDown}, {kind: menuRight}, {kind: menuLeft}, {kind: menuPageUp}, {kind: menuPageDown}, {kind: menuHome}, {kind: menuEnd}, {kind: menuEnter}, {kind: menuBackspace}, {kind: menuClear}, {kind: menuInterrupt}, {kind: menuEndOfInput}, {kind: menuRune, r: 'é'}, {kind: menuEscape}, {kind: menuRune, r: 'q'}, {kind: menuUp}, {kind: menuEscape}}
	for i, expected := range want {
		key, err := readMenuKey(reader)
		if err != nil || key != expected {
			t.Fatalf("key %d: got %+v %v, want %+v", i, key, err, expected)
		}
	}
	if _, err := readMenuKey(reader); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last key: %v", err)
	}
}

func initProviderMenu() *initMenu {
	items := []menuItem{}
	for _, p := range initProviders {
		items = append(items, menuItem{label: p.label})
	}
	return &initMenu{title: "Choose", items: items, back: true}
}

func TestInitMenuFrameShowsThePointerAndWrapsLabels(t *testing.T) {
	menu := initProviderMenu()
	menu.start()
	if _, _, done, err := menu.handle(menuKey{kind: menuDown}); done || err != nil {
		t.Fatal(done, err)
	}
	want := strings.Join([]string{
		"  Choose",
		"  ↑↓ move · Enter select · Esc back · q quit",
		"    1) OpenRouter (remote, needs an API key)",
		"  › 2) Ollama Cloud (remote, needs an API key)",
		"    3) OpenCode Go (remote, needs an API key)",
		"    4) A model server on this machine (Ollama, llama.cpp,",
		"       vLLM, LM Studio)",
		"    5) Ollama on this machine, signed in to Ollama Cloud",
		"       (remote)",
	}, "\n")
	if got := strings.Join(menu.frame(initStyle{}), "\n"); got != want {
		t.Fatalf("frame:\n%s\nwant:\n%s", got, want)
	}
}

// keysFrom feeds a menu the keys in text, as a terminal in raw mode would.
func keysFrom(text string) func() (menuKey, error) {
	reader := bufio.NewReader(strings.NewReader(text))
	return func() (menuKey, error) { return readMenuKey(reader) }
}

func TestInitMenuKeys(t *testing.T) {
	for _, test := range []struct {
		name, keys string
		selected   int
		index      int
		err        error
	}{
		{"Enter takes the proposed item", "\r", 2, 2, nil},
		{"arrows wrap around", "\x1b[A\x1b[A\r", 0, 3, nil},
		{"j and k move", "jjk\r", 0, 1, nil},
		{"a number picks at once", "4", 0, 3, nil},
		{"Esc goes back", "\x1b", 0, 0, errInitBack},
		{"Left goes back", "\x1b[D", 0, 0, errInitBack},
		{"q quits", "q", 0, 0, errInitCanceled},
		{"Ctrl-C quits", "\x03", 0, 0, errInitCanceled},
		{"input ends", "", 0, 0, errInitInputEnded},
	} {
		t.Run(test.name, func(t *testing.T) {
			menu := initProviderMenu()
			menu.selected = test.selected
			var out bytes.Buffer
			index, _, err := menu.run(&out, initStyle{}, keysFrom(test.keys))
			if !errors.Is(err, test.err) || err == nil && index != test.index {
				t.Fatalf("index=%d err=%v", index, err)
			}
			if !strings.HasPrefix(out.String(), "\x1b[?25l") || !strings.HasSuffix(out.String(), "\x1b[?25h") {
				t.Fatalf("the cursor was not hidden and shown again: %q", out.String())
			}
			// A choice leaves the question and its answer; back and quit leave nothing.
			last := out.String()[strings.LastIndex(out.String(), "\x1b[J")+3:]
			if wantLine := strings.Join(menu.answered(initStyle{}, initProviders[test.index].label), "\n") + "\n\x1b[?25h"; err == nil && last != wantLine {
				t.Fatalf("after the choice: %q", last)
			} else if err != nil && last != "\x1b[?25h" {
				t.Fatalf("after %v: %q", err, last)
			}
		})
	}
}

func TestInitMenuWithoutBackIgnoresEsc(t *testing.T) {
	menu := initProviderMenu()
	menu.back = false
	if index, _, err := menu.run(io.Discard, initStyle{}, keysFrom("\x1b\x1b[B\r")); err != nil || index != 1 {
		t.Fatalf("index=%d err=%v", index, err)
	}
	if strings.Contains(strings.Join(menu.frame(initStyle{}), "\n"), "Esc back") {
		t.Fatal("the hint offers Esc without a previous question")
	}
}

func initFakeModels(names ...string) []modelcatalog.Model {
	models := []modelcatalog.Model{}
	for _, name := range names {
		models = append(models, modelcatalog.Model{Selector: name})
	}
	return models
}

func TestInitModelMenuFiltersScrollsAndTakesTypedIDs(t *testing.T) {
	names := []string{}
	for i := 1; i <= 12; i++ {
		names = append(names, fmt.Sprintf("vendor/model-%02d", i))
	}
	names = append(names, "anthropic/claude-x", "other/claude-y")
	terminal := &fakeKeyTerminal{fakeEchoTerminal: newFakeEchoTerminal()}
	run := func(keys string) (string, string, error) {
		var out bytes.Buffer
		w := &initWizard{out: &out}
		w.prompt = newInitPrompter(context.Background(), strings.NewReader(keys), &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
		defer w.prompt.close()
		w.prompt.keys = terminal
		w.prompt.canBack = true
		choice, err := w.menuModel("Finder model", initFakeModels(names...), "", "vendor/model-03", func(value string) (string, error) {
			if strings.HasPrefix(value, "sk-") {
				return "", errors.New("That looks like an API key, not a model ID.")
			}
			return value, nil
		})
		return choice, out.String(), err
	}
	if choice, _, err := run("\r"); err != nil || choice != "vendor/model-03" {
		t.Fatalf("Enter did not take the proposed model: %q %v", choice, err)
	}
	choice, out, err := run("\x1b[F\r")
	if err != nil || choice != "other/claude-y" || !strings.Contains(out, "      ↓ 4 more") || !strings.Contains(out, "      ↑ 4 more") || !strings.Contains(out, "  Finder model: other/claude-y\n") {
		t.Fatalf("End: %q %v\n%s", choice, err, out)
	}
	if choice, _, err := run("\x1b[H\x1b[A\r"); err != nil || choice != "other/claude-y" {
		t.Fatalf("Up from the first model did not wrap: %q %v", choice, err)
	}
	choice, out, err = run("claude\x1b[B\r")
	if err != nil || choice != "other/claude-y" || !strings.Contains(out, "  Filter: claude_  2 of 14") || !strings.Contains(out, "  type to filter · ↑↓ move · Enter select · Esc back") {
		t.Fatalf("filter: %q %v\n%s", choice, err, out)
	}
	// Esc clears the filter first; a second Esc goes back.
	if _, _, err := run("claude\x1b\x1b"); !errors.Is(err, errInitBack) {
		t.Fatalf("Esc twice: %v", err)
	}
	choice, out, err = run("sk-x\r\x15vendor/new\r")
	if err != nil || choice != "vendor/new" || !initHas(out, "No listed model contains \"sk-x\". Enter uses it exactly as typed.") || !strings.Contains(out, "That looks like an API key, not a model ID.") {
		t.Fatalf("typed ID: %q %v\n%s", choice, err, out)
	}
	terminal.assertRestored(t)
	for _, line := range strings.Split(out, "\n") {
		if initVisible(line) > initWidth {
			t.Fatalf("menu line wider than %d columns: %q", initWidth, line)
		}
	}
}

func TestInitPrompterChoosesWithAMenuOrADefaultLine(t *testing.T) {
	terminal := &fakeKeyTerminal{fakeEchoTerminal: newFakeEchoTerminal()}
	var out bytes.Buffer
	prompt := newInitPrompter(context.Background(), strings.NewReader("\x1b[B\rn"), &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
	defer prompt.close()
	prompt.keys = terminal
	if index, err := prompt.choose("Which?", []string{"First", "Second", "Third"}, 0); err != nil || index != 1 {
		t.Fatalf("menu: %d %v", index, err)
	}
	if yes, err := prompt.confirm("Go on?", true); err != nil || yes {
		t.Fatalf("n at a yes/no menu: %v %v", yes, err)
	}
	if !strings.Contains(out.String(), "  Which? Second\n") || !strings.Contains(out.String(), "  Go on? No\n") {
		t.Fatalf("answers: %q", out.String())
	}
	terminal.assertRestored(t)

	// Without a key terminal: numbered lines, and Enter takes the proposal.
	out.Reset()
	lines := newInitPrompter(context.Background(), strings.NewReader("\nb\n1\nb\n"), &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
	defer lines.close()
	if index, err := lines.choose("Which?", []string{"First", "Second", "Third"}, 2); err != nil || index != 2 || !strings.Contains(out.String(), "  Which? (1-3) [3]: ") {
		t.Fatalf("line choice: %d %v %q", index, err, out.String())
	}
	if _, err := lines.choose("Which?", []string{"First", "Second"}, 0); errors.Is(err, errInitBack) {
		t.Fatal("b went back where there is no previous question")
	}
	lines.canBack = true
	if _, err := lines.confirm("Go on?", true); !errors.Is(err, errInitBack) {
		t.Fatalf("b at a line prompt: %v", err)
	}
}

func TestTypeSecretShowsOneStarPerCharacter(t *testing.T) {
	terminal := &fakeKeyTerminal{fakeEchoTerminal: newFakeEchoTerminal()}
	var out bytes.Buffer
	keys := remoteTestKey + remoteTestKey + "\r" + remoteTestKey + "x\x7f\r"
	prompt := newInitPrompter(context.Background(), strings.NewReader(keys), &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
	defer prompt.close()
	prompt.keys = terminal
	answer, err := prompt.askSecret("API key for OpenRouter", terminal)
	if err != nil || answer != remoteTestKey {
		t.Fatalf("answer matched=%v err=%v", answer == remoteTestKey, err)
	}
	text := out.String()
	room := initWidth - len("  API key for OpenRouter: ") - 1
	stars := strings.Repeat("*", min(len(remoteTestKey), room))
	if strings.Contains(text, remoteTestKey[:8]) || !strings.Contains(text, "  API key for OpenRouter: "+stars) || !strings.Contains(text, "the same text twice") || !strings.Contains(text, "Received ********"+remoteTestKey[len(remoteTestKey)-4:]) || strings.Contains(text, "(hidden)") {
		t.Fatalf("key entry output: %q", text)
	}
	if hidden, hides, _, _ := terminal.state(); hidden || hides != 0 {
		t.Fatal("echo was turned off although keys are read in raw mode")
	}
	terminal.assertRestored(t)
	for _, keys := range map[error]string{errInitBack: "ab\x1b", errInitCanceled: "ab\x03", errInitInputEnded: "\x04"} {
		prompt := newInitPrompter(context.Background(), strings.NewReader(keys), io.Discard, initStyle{}, func(string) {})
		prompt.keys, prompt.canBack = terminal, true
		_, err := prompt.askSecret("API key", terminal)
		prompt.close()
		if err == nil {
			t.Fatalf("%q was read as a key", keys)
		}
	}
	terminal.assertRestored(t)
}

// A first run with menus: back from the finder returns to the provider with
// the earlier choice selected, and back from the checker asks the finder again.
func TestInitMenusGoBackToEarlierAnswers(t *testing.T) {
	remoteScannerInstalled(t)
	keyStoreForTest(t)
	clearSessionKeys(t)
	spendingTestStore(t)
	terminal := useFakeKeyTerminal(t)
	initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	keys := "\x1b[B\r" + // Ollama Cloud
		"\x1b" + "\r" + // back to the provider, Enter keeps Ollama Cloud
		"gem\r" + // the finder
		"\x1b" + "\r" + // back from the checker; Enter keeps the finder
		"qwen\r" + // the checker
		"128000\n8192\n" + // the limits are line prompts
		"n" + // no per-token charge
		"y" + // confirm the summary
		"n" // no first review
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST"}, keys)
	if result.code != initExitDone {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	terminal.assertRestored(t)
	setup, err := loadInitSetup(context.Background(), dir)
	if err != nil || setup.provider.key != "ollama-cloud" || setup.generationModel != "gemma4:31b" || setup.verificationModel != "qwen3.5:397b" {
		t.Fatalf("saved setup %+v %v", setup, err)
	}
	if n := strings.Count(result.stdout, "› 1) OpenRouter"); n != 1 {
		t.Fatalf("after back the provider menu did not start on the earlier choice (%d frames on OpenRouter)", n)
	}
	initAssertOutput(t, result, "Enter accepts the highlighted answer; Esc goes back.", "Choose: Ollama Cloud (remote, needs an API key)")
	if strings.Contains(result.stdout, "(1-5)") {
		t.Fatal("numbered line prompts were shown beside the menus")
	}
}
