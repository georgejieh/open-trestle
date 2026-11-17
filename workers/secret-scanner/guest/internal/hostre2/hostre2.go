// Package hostre2 is a Betterleaks regex engine whose matching runs in the
// host, through the regexabi import interface. The guest never compiles or
// runs a regular expression itself.
//
// Every error result from the host ends the process with
// regexabi.GuestBridgeFailureExitCode. Returning an error or panicking would
// fail open: Betterleaks treats a pattern that fails to compile as one that
// never matches, and recovers panics raised inside filter expressions as no
// match.
package hostre2

import (
	"os"
	"regexp/syntax"
	"runtime"
	"unsafe"

	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
)

// exit ends the process. Tests replace it to observe the exit status.
var exit = os.Exit

func fail() {
	exit(regexabi.GuestBridgeFailureExitCode)
}

// Engine implements the Betterleaks regexp.Engine interface.
type Engine struct{}

// Version reports the engine name the adapter checks.
func (Engine) Version() string { return regexabi.EngineVersion }

// Compile asks the host for the handle of pattern. A pattern the host does
// not hold is a bridge failure.
func (Engine) Compile(pattern string) (blregexp.CompiledRegexp, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil || len(pattern) == 0 || len(pattern) > regexabi.MaxPatternBytes {
		fail()
		return nil, err
	}
	handle := hostCompile(stringPointer(pattern), uint32(len(pattern)))
	if handle < 0 {
		fail()
		return nil, nil
	}
	return &compiled{
		pattern:  pattern,
		handle:   handle,
		subexps:  parsed.MaxCap(),
		capNames: parsed.CapNames(),
	}, nil
}

type compiled struct {
	pattern  string
	handle   int32
	subexps  int
	capNames []string
}

func stringPointer(s string) unsafe.Pointer {
	return unsafe.Pointer(unsafe.StringData(s))
}

// text checks the length bound the host enforces, so that an oversized text
// is reported by the guest rather than refused by the host.
func text(s string) (unsafe.Pointer, uint32) {
	if len(s) > regexabi.MaxTextBytes {
		fail()
		return nil, 0
	}
	return stringPointer(s), uint32(len(s))
}

// findAll returns flat start and end offsets of up to limit matches, or of
// every match when limit is regexabi.UnlimitedMatches.
func (c *compiled) findAll(s string, limit int32) []uint32 {
	// The guest has one thread and no preemption, so a timer, such as the
	// scan deadline, fires only when a goroutine yields. Betterleaks checks
	// its context before each rule, and a rule with a regular expression
	// starts with this call, so yielding here lets the deadline stop a scan
	// at the next rule instead of at the end of the source.
	runtime.Gosched()
	pointer, length := text(s)
	count := hostFindAll(c.handle, pointer, length, limit)
	if count < 0 || count > regexabi.MaxPairs || limit > 0 && count > limit {
		fail()
		return nil
	}
	if count == 0 {
		return nil
	}
	offsets := make([]uint32, 2*int(count))
	if written := hostReadResult(unsafe.Pointer(&offsets[0]), uint32(count)); written != count {
		fail()
		return nil
	}
	for index := 0; index < len(offsets); index += 2 {
		if offsets[index] > offsets[index+1] || offsets[index+1] > length {
			fail()
			return nil
		}
	}
	return offsets
}

func (c *compiled) MatchString(s string) bool {
	pointer, length := text(s)
	result := hostMatch(c.handle, pointer, length)
	if result != 0 && result != 1 {
		fail()
		return false
	}
	return result == 1
}

func (c *compiled) FindString(s string) string {
	offsets := c.findAll(s, 1)
	if len(offsets) != 2 {
		return ""
	}
	return s[offsets[0]:offsets[1]]
}

func (c *compiled) FindStringSubmatch(s string) []string {
	if c.subexps > regexabi.MaxGroups {
		fail()
		return nil
	}
	pointer, length := text(s)
	offsets := make([]int32, 2*(c.subexps+1))
	result := hostSubmatch(c.handle, pointer, length, unsafe.Pointer(&offsets[0]), uint32(len(offsets)))
	if result != 0 && result != 1 {
		fail()
		return nil
	}
	if result == 0 {
		return nil
	}
	groups := make([]string, c.subexps+1)
	for index := range groups {
		start, end := offsets[2*index], offsets[2*index+1]
		switch {
		case start == -1 && end == -1:
		case start >= 0 && start <= end && uint32(end) <= length:
			groups[index] = s[start:end]
		default:
			fail()
			return nil
		}
	}
	return groups
}

// FindAllStringIndex follows the standard library: n == 0 returns nil and a
// negative n returns every match. A limit above regexabi.MaxPairs asks for
// every match, which is the same result unless the text has more matches
// than the host returns, and then the host refuses.
func (c *compiled) FindAllStringIndex(s string, n int) [][]int {
	if n == 0 {
		return nil
	}
	limit := int32(regexabi.UnlimitedMatches)
	if n > 0 && n <= regexabi.MaxPairs {
		limit = int32(n)
	}
	offsets := c.findAll(s, limit)
	if offsets == nil {
		return nil
	}
	matches := make([][]int, len(offsets)/2)
	for index := range matches {
		matches[index] = []int{int(offsets[2*index]), int(offsets[2*index+1])}
	}
	return matches
}

// ReplaceAllString is not part of the interface. No caller in the linked
// Betterleaks code uses it on an engine regexp; the scanner module's tests
// check that, and a call ends the guest.
func (c *compiled) ReplaceAllString(src, repl string) string {
	fail()
	return src
}

func (c *compiled) NumSubexp() int { return c.subexps }

func (c *compiled) SubexpNames() []string { return append([]string(nil), c.capNames...) }

func (c *compiled) String() string { return c.pattern }
