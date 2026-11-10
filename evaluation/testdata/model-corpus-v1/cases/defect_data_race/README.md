# defect_data_race

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds `All`, which reads the size of every URL concurrently, one goroutine per URL, and collects the successful sizes.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
