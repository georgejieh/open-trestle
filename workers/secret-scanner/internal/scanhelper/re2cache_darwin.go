//go:build darwin

package scanhelper

import "path/filepath"

// On macOS os.UserCacheDir is $HOME/Library/Caches.
func re2CacheEnvironment(directory string) (string, string) {
	return "HOME", filepath.Join(directory, "re2")
}

func re2CacheRoot(directory string) string {
	return filepath.Join(directory, "re2", "Library", "Caches")
}
