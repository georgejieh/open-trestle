# defect_error_wrap

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds the requested identifier to the error that `Store.Get` returns for a missing item, and reads the path value into a local variable in `ServeHTTP`.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
