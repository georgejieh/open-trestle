//go:build !wasip1

package hostre2

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
)

type exited struct{ code int }

// fakeHost emulates a correct host with the standard library engine over the
// test's own memory, and lets a test override any single function.
type fakeHost struct {
	patterns []*regexp.Regexp
	held     []uint32
	calls    int
}

func installFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	host := &fakeHost{}
	saved := []any{hostCompile, hostFindAll, hostReadResult, hostMatch, hostSubmatch, exit}
	t.Cleanup(func() {
		hostCompile = saved[0].(func(unsafe.Pointer, uint32) int32)
		hostFindAll = saved[1].(func(int32, unsafe.Pointer, uint32, int32) int32)
		hostReadResult = saved[2].(func(unsafe.Pointer, uint32) int32)
		hostMatch = saved[3].(func(int32, unsafe.Pointer, uint32) int32)
		hostSubmatch = saved[4].(func(int32, unsafe.Pointer, uint32, unsafe.Pointer, uint32) int32)
		exit = saved[5].(func(int))
	})
	exit = func(code int) { panic(exited{code}) }
	hostCompile = func(pointer unsafe.Pointer, length uint32) int32 {
		host.calls++
		compiled, err := regexp.Compile(unsafe.String((*byte)(pointer), length))
		if err != nil {
			return regexabi.ErrUnknownPattern
		}
		host.patterns = append(host.patterns, compiled)
		return int32(len(host.patterns) - 1)
	}
	hostFindAll = func(handle int32, pointer unsafe.Pointer, length uint32, limit int32) int32 {
		host.calls++
		found := host.patterns[handle].FindAllStringIndex(unsafe.String((*byte)(pointer), length), int(limit))
		host.held = host.held[:0]
		for _, pair := range found {
			host.held = append(host.held, uint32(pair[0]), uint32(pair[1]))
		}
		return int32(len(found))
	}
	hostReadResult = func(out unsafe.Pointer, pairs uint32) int32 {
		host.calls++
		copy(unsafe.Slice((*uint32)(out), 2*pairs), host.held)
		return int32(pairs)
	}
	hostMatch = func(handle int32, pointer unsafe.Pointer, length uint32) int32 {
		host.calls++
		if host.patterns[handle].MatchString(unsafe.String((*byte)(pointer), length)) {
			return 1
		}
		return 0
	}
	hostSubmatch = func(handle int32, pointer unsafe.Pointer, length uint32, out unsafe.Pointer, capacity uint32) int32 {
		host.calls++
		offsets := host.patterns[handle].FindStringSubmatchIndex(unsafe.String((*byte)(pointer), length))
		if offsets == nil {
			return 0
		}
		destination := unsafe.Slice((*int32)(out), capacity)
		for index, offset := range offsets {
			destination[index] = int32(offset)
		}
		return 1
	}
	return host
}

// exitCode runs call and returns the status it exited with, or -1 when it
// returned.
func exitCode(t *testing.T, call func()) (code int) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			status, ok := recovered.(exited)
			if !ok {
				t.Fatalf("engine panicked instead of exiting: %v", recovered)
			}
			code = status.code
		}
	}()
	call()
	return -1
}

func compileForTest(t *testing.T, pattern string) *compiled {
	t.Helper()
	engine, err := Engine{}.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return engine.(*compiled)
}

func TestEngineResultsEqualStandardLibraryThroughCorrectHost(t *testing.T) {
	installFakeHost(t)
	texts := []string{"", "token=abc123 token=def456", "βeta key=Z9 key=", "no match here"}
	for _, pattern := range []string{`token=([a-z]+)(\d+)`, `key=(?P<value>[A-Z0-9]*)`, `x*`, `(a)|(b)`} {
		engine := compileForTest(t, pattern)
		standard := regexp.MustCompile(pattern)
		if engine.NumSubexp() != standard.NumSubexp() || !reflect.DeepEqual(engine.SubexpNames(), standard.SubexpNames()) || engine.String() != pattern {
			t.Fatalf("%s: group metadata differs", pattern)
		}
		for _, text := range texts {
			for _, n := range []int{-1, 0, 1, 2, 70000} {
				if got, want := engine.FindAllStringIndex(text, n), standard.FindAllStringIndex(text, n); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s on %q n=%d: got %v, want %v", pattern, text, n, got, want)
				}
			}
			if engine.MatchString(text) != standard.MatchString(text) || engine.FindString(text) != standard.FindString(text) {
				t.Fatalf("%s on %q: match or find differs", pattern, text)
			}
			if got, want := engine.FindStringSubmatch(text), standard.FindStringSubmatch(text); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s on %q: submatch got %q, want %q", pattern, text, got, want)
			}
		}
	}
}

func TestFindAllWithZeroLimitMakesNoHostCall(t *testing.T) {
	host := installFakeHost(t)
	engine := compileForTest(t, "a")
	before := host.calls
	if engine.FindAllStringIndex("aaa", 0) != nil || host.calls != before {
		t.Fatal("n == 0 reached the host")
	}
}

func TestEveryHostRefusalExitsWithBridgeFailureCode(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"compile refused": func(t *testing.T) {
			hostCompile = func(unsafe.Pointer, uint32) int32 { return regexabi.ErrUnknownPattern }
			_, _ = Engine{}.Compile("a")
		},
		"find_all refused": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostFindAll = func(int32, unsafe.Pointer, uint32, int32) int32 { return regexabi.ErrTooManyMatches }
			engine.FindAllStringIndex("a", -1)
		},
		"find_all over limit": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostFindAll = func(int32, unsafe.Pointer, uint32, int32) int32 { return 2 }
			engine.FindString("aa")
		},
		"find_all over bound": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostFindAll = func(int32, unsafe.Pointer, uint32, int32) int32 { return regexabi.MaxPairs + 1 }
			engine.FindAllStringIndex("a", -1)
		},
		"read_result short": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostReadResult = func(unsafe.Pointer, uint32) int32 { return regexabi.ErrArgument }
			engine.FindAllStringIndex("aa", -1)
		},
		"read_result offsets outside text": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostReadResult = func(out unsafe.Pointer, pairs uint32) int32 {
				copy(unsafe.Slice((*uint32)(out), 2*pairs), []uint32{0, 9, 1, 2})
				return int32(pairs)
			}
			engine.FindAllStringIndex("aa", -1)
		},
		"match refused": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostMatch = func(int32, unsafe.Pointer, uint32) int32 { return regexabi.ErrBudget }
			engine.MatchString("a")
		},
		"match not boolean": func(t *testing.T) {
			engine := compileForTest(t, "a")
			hostMatch = func(int32, unsafe.Pointer, uint32) int32 { return 2 }
			engine.MatchString("a")
		},
		"submatch refused": func(t *testing.T) {
			engine := compileForTest(t, "(a)")
			hostSubmatch = func(int32, unsafe.Pointer, uint32, unsafe.Pointer, uint32) int32 { return regexabi.ErrCanceled }
			engine.FindStringSubmatch("a")
		},
		"submatch offsets outside text": func(t *testing.T) {
			engine := compileForTest(t, "(a)")
			hostSubmatch = func(_ int32, _ unsafe.Pointer, _ uint32, out unsafe.Pointer, capacity uint32) int32 {
				copy(unsafe.Slice((*int32)(out), capacity), []int32{0, 1, 3, 4})
				return 1
			}
			engine.FindStringSubmatch("a")
		},
		"text over bound": func(t *testing.T) {
			engine := compileForTest(t, "a")
			engine.MatchString(strings.Repeat("a", regexabi.MaxTextBytes+1))
		},
		"replace": func(t *testing.T) {
			engine := compileForTest(t, "a")
			engine.ReplaceAllString("a", "b")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			installFakeHost(t)
			if code := exitCode(t, func() { run(t) }); code != regexabi.GuestBridgeFailureExitCode {
				t.Fatalf("exit code %d, want %d", code, regexabi.GuestBridgeFailureExitCode)
			}
		})
	}
}

func TestEngineWithoutHostExits(t *testing.T) {
	saved := exit
	t.Cleanup(func() { exit = saved })
	exit = func(code int) { panic(exited{code}) }
	if code := exitCode(t, func() { _, _ = Engine{}.Compile("a") }); code != regexabi.GuestBridgeFailureExitCode {
		t.Fatalf("compile without a host exited %d", code)
	}
}
