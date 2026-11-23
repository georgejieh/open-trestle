package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEchoTerminal stands in for a terminal whose echo can be turned off. It
// records every change, and gates its reader so that the typed line is
// delivered only while echo is off, like a person who starts typing once the
// prompt appears.
type fakeEchoTerminal struct {
	mu                    sync.Mutex
	hidden                bool
	hides, restores       int
	readWhileShown        bool
	hiddenSignal          chan struct{}
	failHide, failRestore bool
}

func newFakeEchoTerminal() *fakeEchoTerminal {
	return &fakeEchoTerminal{hiddenSignal: make(chan struct{}, 16)}
}

func (f *fakeEchoTerminal) hideInput() (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failHide {
		return nil, errors.New("echo cannot be turned off")
	}
	f.hidden = true
	f.hides++
	f.hiddenSignal <- struct{}{}
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.restores++
		if f.failRestore {
			return errors.New("echo cannot be restored")
		}
		f.hidden = false
		return nil
	}, nil
}

func (f *fakeEchoTerminal) state() (hidden bool, hides, restores int, readWhileShown bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hidden, f.hides, f.restores, f.readWhileShown
}

// gatedTerminalInput delivers each line only after the terminal hid its
// input, and notes a read that happened while input was shown.
type gatedTerminalInput struct {
	terminal *fakeEchoTerminal
	lines    []string
	pending  []byte
}

func (g *gatedTerminalInput) Read(p []byte) (int, error) {
	if len(g.pending) == 0 {
		if len(g.lines) == 0 {
			return 0, io.EOF
		}
		select {
		case <-g.terminal.hiddenSignal:
		case <-time.After(5 * time.Second):
			return 0, io.EOF
		}
		g.terminal.mu.Lock()
		if !g.terminal.hidden {
			g.terminal.readWhileShown = true
		}
		g.terminal.mu.Unlock()
		g.pending, g.lines = []byte(g.lines[0]+"\n"), g.lines[1:]
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}

func TestAskSecretReadsTheKeyOnlyWhileEchoIsOff(t *testing.T) {
	terminal := newFakeEchoTerminal()
	var out bytes.Buffer
	prompt := newInitPrompter(context.Background(), &gatedTerminalInput{terminal: terminal, lines: []string{"  " + remoteTestKey + "  "}}, &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
	defer prompt.close()
	answer, err := prompt.askSecret("API key for OpenRouter (hidden)", terminal)
	if err != nil || answer != remoteTestKey {
		t.Fatalf("answer matched=%v err=%v", answer == remoteTestKey, err)
	}
	hidden, hides, restores, readWhileShown := terminal.state()
	if hidden || hides != 1 || restores != 1 || readWhileShown {
		t.Fatalf("echo state after the read: hidden=%v hides=%d restores=%d readWhileShown=%v", hidden, hides, restores, readWhileShown)
	}
	receipt := fmt.Sprintf("    Received ********%s (%d characters).\n", remoteTestKey[len(remoteTestKey)-4:], len(remoteTestKey))
	if strings.Contains(out.String(), remoteTestKey) || !strings.HasPrefix(out.String(), "  API key for OpenRouter (hidden): ") || !strings.HasSuffix(out.String(), receipt) {
		t.Fatalf("prompt output: %q", out.String())
	}
}

func TestAskSecretRestoresEchoWhenInputEnds(t *testing.T) {
	for name, cancel := range map[string]bool{"end of input": false, "interrupt": true} {
		t.Run(name, func(t *testing.T) {
			terminal := newFakeEchoTerminal()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			var in io.Reader = strings.NewReader("")
			if cancel {
				blocked, writer := io.Pipe()
				defer writer.Close()
				in = blocked
				go func() {
					<-terminal.hiddenSignal
					stop()
				}()
			}
			var out bytes.Buffer
			prompt := newInitPrompter(ctx, in, &out, initStyle{}, func(string) {})
			defer prompt.close()
			if _, err := prompt.askSecret("API key", terminal); !errors.Is(err, errInitInputEnded) {
				t.Fatalf("err=%v", err)
			}
			if hidden, hides, restores, _ := terminal.state(); hidden || hides != 1 || restores != 1 {
				t.Fatalf("echo was not restored: hidden=%v hides=%d restores=%d", hidden, hides, restores)
			}
		})
	}
}

func TestAskSecretRefusesToReadWhenEchoCannotBeTurnedOff(t *testing.T) {
	terminal := newFakeEchoTerminal()
	terminal.failHide = true
	var out bytes.Buffer
	prompt := newInitPrompter(context.Background(), strings.NewReader(remoteTestKey+"\n"), &out, initStyle{}, func(string) {})
	defer prompt.close()
	if _, err := prompt.askSecret("API key", terminal); !errors.Is(err, errInitSecretUnavailable) {
		t.Fatalf("read a key with echo on: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a prompt was shown although echo could not be turned off: %q", out.String())
	}
	restoreFails := newFakeEchoTerminal()
	restoreFails.failRestore = true
	prompt = newInitPrompter(context.Background(), &gatedTerminalInput{terminal: restoreFails, lines: []string{remoteTestKey}}, &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
	defer prompt.close()
	if _, err := prompt.askSecret("API key", restoreFails); !errors.Is(err, errInitSecretUnavailable) || !strings.Contains(out.String(), "stty echo") {
		t.Fatalf("a failed restore was not reported: %v %q", err, out.String())
	}
}

// A reader that is not a terminal never gets a hidden prompt.
func TestOpenEchoTerminalRefusesNonTerminals(t *testing.T) {
	for _, in := range []io.Reader{strings.NewReader("x\n"), &bytes.Buffer{}} {
		if _, ok := openEchoTerminal(in); ok {
			t.Fatalf("%T was treated as a terminal", in)
		}
	}
}

func TestAskSecretAsksAgainForTheSameTextPastedTwice(t *testing.T) {
	terminal := newFakeEchoTerminal()
	var out bytes.Buffer
	prompt := newInitPrompter(context.Background(), &gatedTerminalInput{terminal: terminal, lines: []string{remoteTestKey + remoteTestKey, remoteTestKey}}, &out, initStyle{}, func(line string) { out.WriteString(line + "\n") })
	defer prompt.close()
	answer, err := prompt.askSecret("API key", terminal)
	if err != nil || answer != remoteTestKey || !strings.Contains(out.String(), "the same text twice") || strings.Contains(out.String(), remoteTestKey) {
		t.Fatalf("answer matched=%v err=%v", answer == remoteTestKey, err)
	}
}

func TestSecretReceiptShowsNoPartOfAShortAnswer(t *testing.T) {
	if got := secretReceipt("abcdefghijk"); got != "11 characters" {
		t.Fatal(got)
	}
}
