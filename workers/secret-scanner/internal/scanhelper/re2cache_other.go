//go:build !darwin && !windows

package scanhelper

// On Linux and the other Unix systems os.UserCacheDir is $XDG_CACHE_HOME
// when it is set.
func re2CacheEnvironment(directory string) (string, string) {
	return "XDG_CACHE_HOME", directory
}

func re2CacheRoot(directory string) string {
	return directory
}
