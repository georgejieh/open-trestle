# deletion_authz_check

Kind: deletion defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head removes the three-line owner-or-administrator check from `Service.Delete`. No line is added.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
