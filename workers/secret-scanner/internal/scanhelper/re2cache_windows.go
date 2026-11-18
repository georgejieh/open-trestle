//go:build windows

package scanhelper

// On Windows os.UserCacheDir is %LocalAppData%.
func re2CacheEnvironment(directory string) (string, string) {
	return "LocalAppData", directory
}

func re2CacheRoot(directory string) string {
	return directory
}
