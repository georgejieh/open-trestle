package main

import (
	"context"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// daemonScanner is the installed scan helper of the daemon. The daemon has
// no review lifetime to tie a helper session to, so each sanitization runs in
// a session of its own. A daemon without a usable helper refuses every
// request that needs a scan.
type daemonScanner struct {
	config secretscan.SessionConfig
	err    error
}

func installedDaemonScanner(getenv func(string) string) daemonScanner {
	config, err := secretscan.InstalledConfig(getenv)
	return daemonScanner{config: config, err: err}
}

// sanitizer is nil when the helper cannot be found.
func (scanner daemonScanner) sanitizer() secretscan.Sanitizer {
	if scanner.err != nil {
		return nil
	}
	return scanner.config.PerCallSanitizer()
}

// prepare fills the helper's cache, with a notice on first use, and says why
// the scanner is unavailable when it is. The daemon calls it once its
// configuration is valid.
func (scanner daemonScanner) prepare(ctx context.Context, stderr io.Writer) {
	err := scanner.err
	if err == nil {
		announce := func() {
			fmt.Fprintln(stderr, "trestled: preparing the secret scanner for first use; this can take a minute")
		}
		err = secretscan.PrepareCache(ctx, scanner.config, announce)
	}
	if err != nil {
		fmt.Fprintf(stderr, "trestled: the secret scanner is unavailable, so requests to models will be refused: %v\n", err)
	}
}
