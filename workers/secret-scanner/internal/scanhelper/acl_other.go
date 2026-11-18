//go:build unix && !darwin

package scanhelper

// accessControlListed reports false: on these systems the owner and mode
// bits describe who can use a directory.
func accessControlListed(string) (bool, error) { return false, nil }
