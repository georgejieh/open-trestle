# defect_ignored_error

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds `Load`, which reads a JSON configuration file over the defaults returned by `Default`.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
