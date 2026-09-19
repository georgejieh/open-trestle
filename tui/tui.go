// Package tui provides a foreground terminal view of authenticated review-run state.
package tui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

const (
	defaultRefreshInterval = 2 * time.Second
	minimumRefreshInterval = 250 * time.Millisecond
	maximumRefreshInterval = time.Minute
	defaultWidth           = 100
	minimumWidth           = 60
	maximumWidth           = 240
	maxCommandBytes        = 256
)

var (
	// ErrInvalidInterface identifies missing or unsafe terminal interface configuration.
	ErrInvalidInterface = errors.New("invalid terminal interface")
	// ErrInvalidSnapshot identifies daemon state outside the configured review scope.
	ErrInvalidSnapshot = errors.New("invalid terminal interface snapshot")
	// ErrInputTooLarge identifies an excessive terminal command.
	ErrInputTooLarge = errors.New("terminal interface command exceeds size limit")
)

// Service is the least daemon authority used by the terminal interface.
type Service interface {
	GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error)
	GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error)
	CancelRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error)
}

// Options fixes one terminal view to an exact review scope.
type Options struct {
	Scope           audit.ReviewScope
	RefreshInterval time.Duration
	Width           int
	Plain           bool
	Once            bool
}

// Interface is a foreground, bounded view over daemon receipts and verified diagnostics.
type Interface struct {
	service Service
	input   io.Reader
	output  io.Writer
	options Options
}

// New constructs a terminal interface without starting network or terminal activity.
func New(service Service, input io.Reader, output io.Writer, options Options) (*Interface, error) {
	if options.RefreshInterval == 0 {
		options.RefreshInterval = defaultRefreshInterval
	}
	if options.Width == 0 {
		options.Width = defaultWidth
	}
	validInterval := options.RefreshInterval >= minimumRefreshInterval && options.RefreshInterval <= maximumRefreshInterval
	validWidth := options.Width >= minimumWidth && options.Width <= maximumWidth
	if isNilValue(service) || isNilValue(input) || isNilValue(output) || options.Scope.Validate() != nil || !validInterval || !validWidth {
		return nil, ErrInvalidInterface
	}
	return &Interface{service: service, input: input, output: output, options: options}, nil
}

// Run displays current state until input closes, the user quits, or context is canceled.
func (i *Interface) Run(ctx context.Context) error {
	if i == nil || ctx == nil {
		return ErrInvalidInterface
	}
	view := interfaceView{}
	if err := i.refresh(ctx, &view); err != nil {
		return err
	}
	if err := i.render(view); err != nil || i.options.Once {
		return err
	}
	commands := readCommands(ctx, i.input)
	ticker := time.NewTicker(i.options.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, open := <-commands:
			if !open {
				return nil
			}
			if result.err != nil {
				return result.err
			}
			if result.eof {
				return nil
			}
			quit, err := i.handleCommand(ctx, result.value, &view)
			if err != nil {
				return err
			}
			if quit {
				return nil
			}
		case <-ticker.C:
			if err := i.refresh(ctx, &view); err != nil {
				view.notice = "Refresh failed; showing the last authenticated snapshot."
			}
			if err := i.render(view); err != nil {
				return err
			}
		}
	}
}

type interfaceView struct {
	receipt        controlplane.ReviewRunReceipt
	diagnostics    diagnostics.Set
	hasDiagnostics bool
	pendingCancel  bool
	notice         string
	refreshedAt    time.Time
}

func (i *Interface) refresh(ctx context.Context, view *interfaceView) error {
	receipt, err := i.service.GetRun(ctx, i.options.Scope)
	if err != nil {
		return fmt.Errorf("load review run: %w", err)
	}
	if receipt.Validate() != nil || receipt.Scope().Identity() != i.options.Scope.Identity() {
		return ErrInvalidSnapshot
	}
	view.receipt = receipt
	view.refreshedAt = time.Now().UTC()
	view.notice = ""
	set, diagnosticErr := i.service.GetDiagnosticSet(ctx, i.options.Scope)
	if diagnosticErr != nil {
		view.diagnostics = diagnostics.Set{}
		view.hasDiagnostics = false
		return nil
	}
	if set.Validate() != nil || set.Scope().Identity() != i.options.Scope.Identity() {
		return ErrInvalidSnapshot
	}
	view.diagnostics = set
	view.hasDiagnostics = true
	return nil
}

func (i *Interface) handleCommand(ctx context.Context, raw string, view *interfaceView) (bool, error) {
	command := strings.TrimSpace(raw)
	switch command {
	case "q", "quit":
		return true, nil
	case "r", "refresh":
		if err := i.refresh(ctx, view); err != nil {
			view.notice = "Refresh failed; showing the last authenticated snapshot."
		}
	case "c":
		if view.receipt.Status() != controlplane.ReviewRunActive {
			view.notice = "This review run is already terminal."
			view.pendingCancel = false
		} else {
			view.pendingCancel = true
			view.notice = "Type cancel " + i.options.Scope.ReviewRunID() + " to confirm."
		}
	default:
		want := "cancel " + i.options.Scope.ReviewRunID()
		if command == want && view.pendingCancel {
			receipt, err := i.service.CancelRun(ctx, i.options.Scope)
			view.pendingCancel = false
			if err != nil {
				view.notice = "Cancellation failed; the last authenticated snapshot is unchanged."
			} else if receipt.Validate() != nil || receipt.Scope().Identity() != i.options.Scope.Identity() {
				return false, ErrInvalidSnapshot
			} else {
				view.receipt = receipt
				view.refreshedAt = time.Now().UTC()
				view.notice = "Cancellation requested."
			}
		} else if strings.HasPrefix(command, "cancel ") && view.pendingCancel {
			view.pendingCancel = false
			view.notice = "Confirmation did not match this review run."
		} else if command == "" {
			view.notice = ""
		} else {
			view.pendingCancel = false
			view.notice = "Unknown command. Use r, c, or q."
		}
	}
	return false, i.render(*view)
}

type commandResult struct {
	value string
	err   error
	eof   bool
}

func readCommands(ctx context.Context, input io.Reader) <-chan commandResult {
	results := make(chan commandResult, 1)
	go func() {
		defer close(results)
		reader := bufio.NewReaderSize(input, maxCommandBytes+2)
		for {
			line, err := reader.ReadSlice('\n')
			if errors.Is(err, bufio.ErrBufferFull) {
				sendCommandResult(ctx, results, commandResult{err: ErrInputTooLarge})
				return
			}
			line = bytes.TrimSuffix(line, []byte{'\n'})
			line = bytes.TrimSuffix(line, []byte{'\r'})
			if len(line) > maxCommandBytes {
				sendCommandResult(ctx, results, commandResult{err: ErrInputTooLarge})
				return
			}
			if len(line) > 0 || err == nil {
				if !sendCommandResult(ctx, results, commandResult{value: strings.Clone(string(line))}) {
					return
				}
			}
			if errors.Is(err, io.EOF) {
				sendCommandResult(ctx, results, commandResult{eof: true})
				return
			}
			if err != nil {
				sendCommandResult(ctx, results, commandResult{err: fmt.Errorf("terminal interface input: %w", err)})
				return
			}
		}
	}()
	return results
}

func sendCommandResult(ctx context.Context, results chan<- commandResult, result commandResult) bool {
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func safeTerminalText(value string) string {
	if !utf8.ValidString(value) {
		return "?"
	}
	var builder strings.Builder
	builder.Grow(len(value))
	space := false
	for _, candidate := range value {
		if candidate == '\n' || candidate == '\r' || candidate == '\t' || !unicode.IsPrint(candidate) {
			if !space {
				builder.WriteByte(' ')
				space = true
			}
			continue
		}
		builder.WriteRune(candidate)
		space = candidate == ' '
	}
	return strings.TrimSpace(builder.String())
}

func truncateTerminalText(value string, maximum int) string {
	value = safeTerminalText(value)
	characters := []rune(value)
	if len(characters) <= maximum {
		return value
	}
	if maximum <= 3 {
		return strings.Repeat(".", maximum)
	}
	return string(characters[:maximum-3]) + "..."
}
