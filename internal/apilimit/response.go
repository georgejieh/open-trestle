package apilimit

import "github.com/georgejieh/open-trestle/diagnostics"

// MaximumResponseBytes allows a maximum diagnostic payload plus bounded API framing.
// Browser clients use the same one MiB payload and four KiB envelope budget.
const MaximumResponseBytes = diagnostics.MaxEncodedSetBytes + (4 << 10)
