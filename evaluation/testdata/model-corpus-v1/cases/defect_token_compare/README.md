# defect_token_compare

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head replaces the `crypto/subtle` comparison in `Authorized` with the `==` operator and drops the import.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
