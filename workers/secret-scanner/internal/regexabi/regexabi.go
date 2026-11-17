// Package regexabi defines the WebAssembly import interface through which the
// scanner guest asks its host to run pinned regular expressions. The guest
// passes pointers and lengths into its own linear memory; every argument is an
// i32 and every function returns one i32, where a negative value is an error.
//
//	compile(pattern_ptr, pattern_len) -> handle
//	find_all(handle, text_ptr, text_len, limit) -> number of match pairs held
//	read_result(out_ptr, pairs) -> pairs written as little-endian u32 start, end
//	match(handle, text_ptr, text_len) -> 0 or 1
//	submatch(handle, text_ptr, text_len, out_ptr, out_cap) -> 0 or 1, with
//	    out_cap little-endian i32 offsets written on a match (-1 for a group
//	    that did not participate)
package regexabi

// Import module and function names.
const (
	ModuleName         = "ot_regex"
	FunctionCompile    = "compile"
	FunctionFindAll    = "find_all"
	FunctionReadResult = "read_result"
	FunctionMatch      = "match"
	FunctionSubmatch   = "submatch"
)

// Bounds the host enforces on every call.
const (
	// MaxPatternBytes is the longest pattern text compile accepts.
	MaxPatternBytes = 4096
	// MaxTextBytes is the longest text one call accepts. It equals the
	// scanner's per-source limit, because the longest text a scan matches is
	// one whole source.
	MaxTextBytes = 256 * 1024
	// MaxPairs is the largest number of matches one find_all call returns.
	// A text with more matches is an error, never a truncated result.
	MaxPairs = 65536
	// MaxGroups is the largest number of capture groups submatch reports.
	MaxGroups = 64
	// UnlimitedMatches is the find_all limit that asks for every match.
	UnlimitedMatches = -1
)

// Error results. The codes are coarse on purpose: the guest never learns more
// than which class of rule it broke.
const (
	ErrArgument       int32 = -1
	ErrUnknownPattern int32 = -2
	ErrBudget         int32 = -3
	ErrTooManyMatches int32 = -4
	ErrInternal       int32 = -5
	ErrNoSession      int32 = -6
	ErrCanceled       int32 = -7
)

// EngineVersion is the Betterleaks engine version string of the guest engine
// that uses this interface.
const EngineVersion = "hostre2"

// GuestBridgeFailureExitCode is the exit status of a guest that received an
// error result from any of these functions. The guest exits instead of
// panicking, because Betterleaks recovers panics raised inside filter
// expressions and treats them as no match.
const GuestBridgeFailureExitCode = 71
