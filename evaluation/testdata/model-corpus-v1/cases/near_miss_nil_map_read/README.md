# near_miss_nil_map_read

Kind: near miss. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head removes the three-line nil-map check from `Registry.Resolve`. No line is added; the check in `Add` stays.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
