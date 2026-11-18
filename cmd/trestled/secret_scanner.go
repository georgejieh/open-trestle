package main

import (
	"context"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// daemonSecretScanner returns the scanner of the installed scan helper. The
// daemon has no review lifetime to tie a helper session to, so each
// sanitization runs in a session of its own. The cache is prepared here, with
// a notice on first use. A build that pins no helper returns nil, and every
// request that needs a scan is then refused; an installed helper that fails
// to prepare is reported and still returned, so that its scans fail closed.
func daemonSecretScanner(ctx context.Context, stderr io.Writer) secretscan.Sanitizer {
	config, err := secretscan.InstalledConfig()
	if err != nil {
		return nil
	}
	announce := func() {
		fmt.Fprintln(stderr, "trestled: preparing the secret scanner for first use; this can take a minute")
	}
	if err := secretscan.PrepareCache(ctx, config, announce); err != nil {
		fmt.Fprintf(stderr, "trestled: the secret scanner is not ready, so remote model requests will be refused: %v\n", err)
	}
	return config.PerCallSanitizer()
}
