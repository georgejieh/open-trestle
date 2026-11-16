# deletion_bounds_check

Kind: deletion defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head removes the three-line position check from `Page.At` in `page.go`. No line is added; `handler.go` is unchanged.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
