# defect_size_overflow

Kind: defect. Go semantics: go 1.22, declared in both trees' `go.mod`. Both trees build with the standard library only.

What changed: The head changes the frame header from one uint32 payload length to a uint32 record count and a uint32 record size, and sizes the payload as their product.

The pending fixture-author labels are in `labels.json`. They have not been independently reviewed.
