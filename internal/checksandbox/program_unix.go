//go:build linux || darwin

package checksandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

// findProgram looks name up in the sandbox's search path.
func findProgram(name string, path []string) (string, error) {
	candidates := []string{name}
	if !filepath.IsAbs(name) {
		candidates = candidates[:0]
		for _, directory := range path {
			candidates = append(candidates, filepath.Join(directory, name))
		}
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s is not installed in a place the sandbox can see", name)
}
