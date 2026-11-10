# defect_lock_not_released

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds `Refresh`, which extends the lifetime of a stored, unexpired entry.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
