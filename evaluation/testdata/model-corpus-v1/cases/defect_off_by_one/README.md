# defect_off_by_one

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds `CountMatches` to `tail.go`. It counts how many of the last n lines of a text contain a substring, using the existing `Tail` helper.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
