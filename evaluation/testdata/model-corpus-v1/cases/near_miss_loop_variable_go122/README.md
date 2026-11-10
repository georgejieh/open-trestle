# near_miss_loop_variable_go122

Kind: near miss. Go semantics: the base `go.mod` declares go 1.21 and the head declares go 1.22. Both trees build with the standard library only.

What changed: The head raises the `go` directive in `go.mod` from 1.21 to 1.22 and removes the `i, sub := i, sub` copy inside the loop of `NotifyAll`.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
