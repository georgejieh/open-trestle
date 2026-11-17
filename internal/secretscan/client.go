package secretscan

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"
)

type FailureClass uint8

const (
	FailureNone FailureClass = iota
	FailureInvalidInput
	FailureResourceLimit
	FailurePolicy
	FailureCanceled
)

func (failure FailureClass) String() string {
	switch failure {
	case FailureNone:
		return ""
	case FailureInvalidInput:
		return "invalid_input"
	case FailureResourceLimit:
		return "resource_limit"
	case FailurePolicy:
		return "policy"
	case FailureCanceled:
		return "canceled"
	default:
		return ""
	}
}

type ScanMetadata struct {
	Scanner         string
	ScannerVersion  string
	ScannerCommit   string
	RulesetIdentity string
	BuildProfile    string
	LauncherSHA256  string
	WorkerSHA256    string
	// HelperSHA256 identifies the session helper executable for scans run
	// through a Session; it is empty for scans run through Client.
	HelperSHA256     string
	Duration         time.Duration
	SourceCount      int
	ScannedByteCount int
	MatchCount       int
}

type ScanResult struct {
	matches  []Match
	metadata ScanMetadata
	failure  FailureClass
	complete bool
}

func (result ScanResult) Complete() bool         { return result.complete && result.failure == FailureNone }
func (result ScanResult) Failure() FailureClass  { return result.failure }
func (result ScanResult) Metadata() ScanMetadata { return result.metadata }
func (result ScanResult) Matches() []Match       { return append([]Match(nil), result.matches...) }
func (result ScanResult) String() string         { return "secret scan result" }
func (result ScanResult) GoString() string       { return "secretscan.ScanResult{<redacted>}" }
func (result ScanResult) Format(state fmt.State, verb rune) {
	if verb == 'v' && state.Flag('#') {
		_, _ = fmt.Fprint(state, result.GoString())
		return
	}
	_, _ = fmt.Fprint(state, result.String())
}

type sourceScanner interface {
	scan(context.Context, [][]byte) ScanResult
}

func validateSourceInputs(sources [][]byte) bool {
	if len(sources) < 1 || len(sources) > maxSources {
		return false
	}
	total := 0
	for _, source := range sources {
		if source == nil || len(source) > maxSourceBytes || !utf8.Valid(source) || total > maxAggregateSourceBytes-len(source) {
			return false
		}
		total += len(source)
	}
	return true
}
