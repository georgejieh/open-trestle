# clean_rename

Kind: clean. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head renames the unexported helper `parseKV` to `splitPair`, updates both call sites, and renames local variables (`number` to `index`, `k` and `v` to `key` and `value`).

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
