# defect_nil_map_write

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head adds a `failures` map field to `Recorder` and the methods `AddFailure` and `Failures`. `NewRecorder` is unchanged.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
