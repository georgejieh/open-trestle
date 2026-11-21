package main

import "fmt"

// writeSetupRedactedFormat renders redacted setup values for fmt verbs.
func writeSetupRedactedFormat(state fmt.State, verb rune, plain, syntax string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = syntax
	}
	_, _ = state.Write([]byte(value))
}
