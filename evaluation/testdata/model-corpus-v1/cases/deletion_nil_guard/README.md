# deletion_nil_guard

Kind: deletion defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head removes the three-line nil check from `NewClient` in `client.go`. No line is added; `default.go` is unchanged.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
