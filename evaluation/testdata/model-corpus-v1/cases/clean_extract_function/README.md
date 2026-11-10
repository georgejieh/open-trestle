# clean_extract_function

Kind: clean. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head moves the three validation checks of `Queue.Submit` into a new unexported `validate` function, in the same order and with the same errors, and calls it from `Submit`.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
