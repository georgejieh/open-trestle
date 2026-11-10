# clean_test_only

Kind: clean. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds `slug_test.go`, a table-driven test of the existing `Make` function. Production code is unchanged.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
