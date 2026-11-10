# defect_path_traversal

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds a `GET /exports/download` endpoint that returns the export file named by the `name` query parameter.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
