# near_miss_time_after_go123

Kind: near miss. Go semantics: the base `go.mod` declares go 1.22 and the head declares go 1.23. Both trees build with the standard library only.

What changed: The head raises the `go` directive in `go.mod` from 1.22 to 1.23 and replaces the reused, manually stopped and reset timer in `Drain` with `time.After(idle)` in the `select`.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
