# abstention_unit_unknown

Kind: abstention. Go semantics: go 1.22, declared in both trees' `go.mod`. Neither tree builds: both require `example.test/kvstore`, which is deliberately absent.

What changed: The head multiplies the TTL passed to `kvstore.Client.PutWithTTL` by 1000.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
