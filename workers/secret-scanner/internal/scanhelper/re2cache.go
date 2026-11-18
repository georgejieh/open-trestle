package scanhelper

import (
	"errors"
	"os"
	"path/filepath"
)

var errRE2Cache = errors.New("go-re2 cache directory was not applied")

// UseRE2CacheDirectory makes go-re2 keep its compiled libre2 module under
// directory. go-re2 finds its cache through os.UserCacheDir, which reads the
// environment, and the helper starts with an empty one; without a cache
// every helper process compiles libre2 again. It must run before the first
// regex compile. It changes only this process's environment, not the
// guest's, which is set explicitly per instance.
func UseRE2CacheDirectory(directory string) error {
	variable, value := re2CacheEnvironment(directory)
	if err := os.Setenv(variable, value); err != nil {
		return err
	}
	resolved, err := os.UserCacheDir()
	if err != nil || filepath.Clean(resolved) != filepath.Clean(re2CacheRoot(directory)) {
		return errRE2Cache
	}
	return nil
}
