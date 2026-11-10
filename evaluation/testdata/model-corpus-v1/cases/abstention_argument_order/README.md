# abstention_argument_order

Kind: abstention. Go semantics: go 1.22, declared in both trees' `go.mod`. Neither tree builds: both require `example.test/platform`, which is deliberately absent.

What changed: The head swaps the order of the two integer arguments `pushAttempts` and `pushBackoffMillis` in the call to `retry.Do`.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
