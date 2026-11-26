package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// `trestle` with no arguments, in an interactive terminal, is a home screen:
// a status card for the repository in the current directory and numbered
// next actions, each one or two steps away. Anywhere else (standard input or
// output not a terminal, NO_COLOR set, or TERM=dumb) it prints the usage text
// and exits 2, exactly as before, so scripts see no change. The home screen
// reads local state: the setup folder, the usage folder and the credential
// store. Its only network request is the update notice's release list GET,
// at most once a day (update_notice.go).

// homeInteractive reports whether the home screen may be shown. Tests
// replace it.
var homeInteractive = func(stdin io.Reader, stdout io.Writer) bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor || os.Getenv("TERM") == "dumb" {
		return false
	}
	in, inFile := stdin.(*os.File)
	out, outFile := stdout.(*os.File)
	return inFile && outFile && isTerminal(in) && isTerminal(out)
}

// isTerminal reports a real terminal: one whose terminal settings can be
// read, which /dev/null and other character devices are not.
func isTerminal(file *os.File) bool {
	if info, err := file.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	_, ok := platformEchoTerminal(file)
	return ok
}

// homeDocs is where the guides are, in the repository and online.
const homeDocs = "https://github.com/georgejieh/open-trestle/tree/main/docs"

func runHome(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	if !homeInteractive(stdin, stdout) {
		writeUsage(stderr)
		return 2
	}
	return runHomeScreen(ctx, stdin, stdout, stderr)
}

// homeReadChoice reads one line without reading past it, so a command the
// home screen starts next reads the following lines itself. Ctrl-C (a
// canceled context) or end of input reads as quit.
func homeReadChoice(ctx context.Context, stdin io.Reader) string {
	line := make(chan string, 1)
	go func() {
		var buffer []byte
		one := make([]byte, 1)
		for len(buffer) < initMaxAnswerBytes {
			n, err := stdin.Read(one)
			if n == 1 {
				if one[0] == '\n' {
					break
				}
				buffer = append(buffer, one[0])
			}
			if err != nil {
				if len(buffer) == 0 {
					line <- "q"
					return
				}
				break
			}
		}
		line <- strings.TrimSpace(string(buffer))
	}()
	select {
	case <-ctx.Done():
		return "q"
	case answer := <-line:
		return answer
	}
}

// homeAction is one numbered next action.
type homeAction struct {
	label, command string
	run            func() int
}

func runHomeScreen(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	notice := startUpdateNotice(ctx)
	w := latestReviewPrinter(ctx, stdout, "")
	mark := bridgeCompactMark
	for i, line := range []string{strings.TrimRight(mark[0], " "), mark[1], strings.TrimRight(mark[2], " ")} {
		if i == 1 {
			line = w.style.paint(initToneRule, line) + "  " + w.style.paint(initToneHeading, "Open Trestle")
		} else {
			line = w.style.paint(initToneRule, line)
		}
		w.sayVerbatim(line)
	}
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		w.say("\n  This folder is not inside a Git repository. Change into the repository you want reviewed and run trestle again; trestle init sets it up.")
		w.hint("  Guides: docs/getting-started.md · " + homeDocs)
		sayUpdateNotice(ctx, w, notice)
		return 0
	}
	w.checkout = checkout
	dir := discoverSetupDirectory(ctx, checkout)
	actions := []homeAction{}
	if !setupExists(dir) {
		w.say("\n  %s has no Open Trestle setup yet. Setup asks a few questions, sends no source, and can run the first review.", initDisplayPath(checkout))
		actions = append(actions, homeAction{"Set up this repository", "trestle init", func() int { return runInit(ctx, nil, stdin, stdout, stderr) }})
		return homeChoose(ctx, w, stdin, homeUpdate(ctx, w, notice, actions, stdin, stdout, stderr))
	}
	repo, err := loadRepositorySetup(ctx, checkout, dir)
	if err != nil {
		w.say("\n  %s The setup in %s cannot be read (%s).", w.bad, initDisplayPath(dir), err)
		actions = append(actions,
			homeAction{"Find out why", "trestle doctor", func() int { return runDoctor(ctx, nil, stdout, stderr) }},
			homeAction{"Check the setup", "trestle init", func() int { return runInit(ctx, nil, stdin, stdout, stderr) }})
		return homeChoose(ctx, w, stdin, homeUpdate(ctx, w, notice, actions, stdin, stdout, stderr))
	}
	rows := statusRows(ctx, repo)
	select {
	case line := <-notice:
		rows = withUpdate(rows, line)
	case <-ctx.Done():
	}
	notice = nil
	w.say("")
	for _, line := range statusCard(w.style, initLabel(filepath.Base(checkout), "repository"), rows) {
		w.sayVerbatim(line)
	}
	actions = append(actions,
		homeAction{"Review the latest change", "trestle review", func() int {
			code, _ := reviewLatestChange(ctx, latestReviewPrinter(ctx, stdout, checkout), repo, latestReviewOptions{}, stdout, stderr)
			return code
		}},
		homeAction{"See spending", "trestle usage", func() int { return runUsageStatus(ctx, stdout, stderr) }},
	)
	if keys := missingOrSetKeys(repo.setup); len(keys) == 1 {
		name := keys[0]
		actions = append(actions, homeAction{"Change the API key", "trestle keys", func() int { return runKeysSet(ctx, name, stdin, stdout, stderr) }})
	} else {
		actions = append(actions, homeAction{"See API keys", "trestle keys", func() int { return runKeysList(ctx, stdout, stderr) }})
	}
	actions = append(actions,
		homeAction{"Re-run setup", "trestle init", func() int { return runInit(ctx, nil, stdin, stdout, stderr) }},
		homeAction{"Read the guides", "docs/getting-started.md", func() int {
			w.say("  Getting started, the first review and running it again: docs/getting-started.md")
			w.say("  API keys: docs/keys.md · spending limits: docs/spending-limits.md")
			w.say("  Reading a result: docs/local-model-review.md")
			w.say("  Online: %s", homeDocs)
			return 0
		}},
	)
	return homeChoose(ctx, w, stdin, homeUpdate(ctx, w, notice, actions, stdin, stdout, stderr))
}

// homeUpdate prints the update notice unless the card shows it (notice is
// nil) and, on a packaged install, adds the update action last, so the other
// actions keep their numbers.
func homeUpdate(ctx context.Context, w *initWizard, notice <-chan string, actions []homeAction, stdin io.Reader, stdout, stderr io.Writer) []homeAction {
	if notice != nil {
		sayUpdateNotice(ctx, w, notice)
	}
	if _, installed := updatePackageInstalled(); installed {
		actions = append(actions, homeAction{"Update Open Trestle", "trestle update", func() int { return runUpdate(ctx, nil, stdin, stdout, stderr) }})
	}
	return actions
}

// missingOrSetKeys is the setup's key variables, for the key action.
func missingOrSetKeys(setup initSetup) []string {
	if !setup.remote || setup.provider.key == ollamaSigninProvider {
		return nil
	}
	return setup.credentials
}

// homeChoose prints the numbered actions and runs the one chosen.
func homeChoose(ctx context.Context, w *initWizard, stdin io.Reader, actions []homeAction) int {
	w.say("")
	width := 0
	for _, action := range actions {
		width = max(width, len(action.label))
	}
	for i, action := range actions {
		w.sayVerbatim(fmt.Sprintf("  %d) %-*s  %s", i+1, width, action.label, w.style.paint(initToneDim, action.command)))
	}
	choices := fmt.Sprintf("1-%d", len(actions))
	if len(actions) == 1 {
		choices = "1"
	}
	for range initMaxTries {
		fmt.Fprint(w.out, w.style.paint(initTonePrompt, "  Choose "+choices+", or Enter to quit: "))
		answer := homeReadChoice(ctx, stdin)
		switch answer {
		case "", "q", "Q", "quit":
			fmt.Fprintln(w.out)
			return 0
		}
		for i := range actions {
			if answer == fmt.Sprint(i+1) {
				fmt.Fprintln(w.out)
				return actions[i].run()
			}
		}
		w.say("    Please type a number from 1 to %d, or press Enter to quit.", len(actions))
	}
	return 0
}
