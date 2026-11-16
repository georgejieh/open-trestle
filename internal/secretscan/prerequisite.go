package secretscan

import "errors"

// Installed-prerequisite refusals. They carry no source or path content.
var (
	ErrScannerDigestsMissing      = errors.New("binary has no injected secret scanner digests; build it with tools/package_secret_scanner.py")
	ErrScannerNotInstalled        = errors.New("secret scanner executables are not installed as root-owned 0555 files matching the injected digests under /usr/local/libexec/open-trestle")
	ErrScannerUnsupportedPlatform = errors.New("sandboxed secret scanner is available only on Linux")
)
