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

// Commands returns the argument lists of the build and test steps, each
// starting with the common flags.
func Commands(verbose bool) (build, test []string) {
	common := make([]string, 0, 8)
	common = append(common, Common(verbose)...)
	build = append(common, "build", "./...")
	test = append(common, "test", "./...")
	return build, test
}
