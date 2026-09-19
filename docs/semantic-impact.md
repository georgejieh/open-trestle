# Semantic impact profiles

Open Trestle can derive a bounded semantic impact profile from exact base and head snapshots. The first adapter uses Go's syntax tree parser and graph contract `open-trestle/semantic-impact/go-ast-graph/v1`.

The profile records:

- added, modified, and removed top-level functions, methods, types, variables, and constants;
- exported declaration changes and a separate public-API-change flag based on function signatures rather than bodies;
- source ranges and normalized syntax and API digests;
- name-based reference candidates across the head snapshot;
- affected test candidates for references found in `_test.go` files; and
- typed gaps for unsupported languages, unavailable source, parser failure, and resource limits.

Declaration differences have the `structural` evidence grade. References and affected-test links have the `syntactic_candidate` grade because matching an identifier name does not establish symbol resolution, reachability, behavior, or test coverage. These candidates may prioritize context inspection. They cannot independently establish a finding. Context assembly deduplicates exact one-line source ranges before file hashing and retains exact counted omission totals when reference candidates exceed admission bounds.

Every profile binds the exact base snapshot, head snapshot, change model, input file digests, adapter identity, and graph schema. Inputs are order-independent and bounded to 4,096 files per side, 2 MiB per file, and 128 MiB total. Outputs are bounded to 8,192 declaration changes, 32,768 reference candidates, 4,096 gaps, and 16 MiB encoded JSON. Duplicate paths, traversal paths, control characters, malformed digests, identity mismatches, noncanonical ordering, unknown JSON fields, and trailing JSON values are rejected.

Declaration and reference coordinates use physical file positions, ignoring `//line` remapping. Repeated `init` functions are distinguished by declaration order within a file. Blank identifiers do not create named declaration records. Declaration names and keys must fit the profile encoding limits; excessive output fails explicitly instead of returning an unencodable profile.

The Go parser does not type-check packages or resolve identifiers. Build constraints, generated variants, dependency modules, dynamic dispatch, reflection, cgo, code generation, and runtime call paths remain outside this first graph contract. A later approved type-aware adapter may add stronger relationship grades without upgrading existing syntactic candidates.
