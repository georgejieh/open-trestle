// Package steps builds tool command lines.
package steps

// Common returns the flags shared by every step.
func Common(verbose bool) []string {
	flags := []string{"-trimpath"}
	if verbose {
		flags = append(flags, "-v")
	}
	return flags
}
