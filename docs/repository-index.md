# Repository index

The repository index records every file of a commit and the [syntax analysis](syntax-analysis.md) of its source files, so queries can find definitions, their uses, the tests that use them and what depends on a change. Reviews take their context from it (see [review context](local-model-review.md#review-context)). It reads the commit from the verified Git object store that reviews read, never from the working tree.

## What it holds

For each file of the commit's tree:

- its role: `source`, `test`, `config`, `docs`, `generated`, `vendored` or `other`, set by fixed path rules. A file is also `generated` when its first 2 KiB hold `Code generated ... DO NOT EDIT` or `@generated`;
- its language, when an analyzer supports it;
- its status: `indexed`, or the reason it has no analysis (`not_analysed`, `binary`, `symlink`, `submodule`, `unavailable`, `analysis_failed`, or the limit that left it out); and
- for an indexed file, its definitions, references, imports and coverage gaps.

Only `source`, `test` and `generated` files are analyzed. Vendored code (directories such as `vendor`, `third_party` and `node_modules`), docs, config and other files are listed with their role only. A file with a NUL byte in its first 8,000 bytes is binary and not analyzed.

## Reference candidates

A reference is a candidate for a definition when it has the definition's exact name, is in a file of the same language family, and meets one of these rules. Each answer names the matching scope.

| Scope | Rule | Languages |
| --- | --- | --- |
| `file` | the same file | all |
| `package` | the same package: the directory for Go and Swift, the declared package or namespace for Java, C# and PHP | Go, Java, C#, Swift, PHP |
| `import` | the file imports the definition's file, or its package for a Go or C# import or a Java wildcard, as resolved from the import text, and the definition is exported | all |
| `name` | the definition is exported and the language makes it visible without an import of its file | C, C++, C#, Swift, PHP, Ruby |

In Go, a reference qualified by the name an import binds (its alias, or the package's declared name) matches only that package's top-level definitions, and any other selector matches only methods and fields. A bare name never matches a method or field, and matches nothing when an import binds it. A method or field of another package matches only a selector in a file that imports that package. A value use qualified by a type (see [syntax analysis](syntax-analysis.md#what-is-recorded)) matches only members of that type, and of the types it embeds or is defined from, within its package. A type from outside the repository matches nothing.

Imports resolve by path rules, and an import of a package outside the repository is unresolved and counted:

- Go import paths through the module paths of the commit's `go.mod` files. An import outside them stays unresolved. Only a file under no known module falls back to the directory the path ends with.
- Java class names to their file, and relative JavaScript and TypeScript imports with the usual extensions and `index` files.
- HTML `src`, `href` and `action` values relative to the page.
- Python modules to `.py`, `.pyi` or `__init__.py`.
- C and C++ includes, Rust `use` paths, Ruby and PHP required paths, and PHP namespaced names to files.
- C# `using` to the files that declare the namespace.
Because names are not resolved to declarations, a candidate can belong to another definition with the same name, and a use through a variable, an alias or reflection can be missed.

## Dependents

The dependents of a change start from its changed definitions: each definition, in the head or the base commit, that holds a changed line outside its child definitions. The closure follows reference candidates backwards, breadth first: definitions holding candidates of a changed definition have depth 1, those holding candidates of a depth-1 dependent have depth 2, and so on. It stops at depth 3, 1,000 dependents, 2,000 candidates per definition or 2,000,000 references checked, and records what each limit cut. Changed files without a complete analysis are listed as gaps. A definition in a file the head no longer has is still matched in its package and in the files that imported that file in the base, and a definition that lost its export is still matched in the files that imported it.

`trestle index query dependents` finds the changed files by comparing the two snapshots. A deleted and an added file with the same blob are a move without a change, matched one to one. A deleted and an added file with the same base name, which no other deleted or added file has, are a move with an edit. Any other deletion, while an addition remains, is recorded as a possible move (`unmatched_move`). The changed lines come from diffing each modified file's base and head blobs, up to 256 MiB in all. A file past that budget (`diff_budget`), or one the diff cannot represent (`diff_unavailable`), counts as changed throughout. A review also treats a file moved without an edit as removed from its old path, so the files that imported it there become its dependents.

## Ranking

A ranking is a PageRank personalized to seed files, such as a change's files, over their neighborhood: the files within two links of a seed. A file links to each file whose definitions it holds reference candidates of, and to each file its imports resolve to, weighted by the square root of the count. Only the seeds and the files they link to are walked, so only the definitions those files reference are scored, each by the rank flowing to it from the files that reference it.

A ranking counts at most 500 candidates per definition, checks at most 4,000,000 definitions against references, and holds at most 2,000 files and 100,000 links. A ranking cut by a limit is marked incomplete, which does not make the index incomplete. A review's repository map lists the signatures of the source definitions it scores highest.

## Where it lives

The index lives under `index/` in the setup folder (see [environment variables and files](environment-and-files.md)). It is private to your account: mode `0700` and `0600` on Unix, an owner-only access list on Windows.

- `seg-*.otx` files hold one analysis per blob and language. A blob is analyzed only once per program build, so a new commit's build analyzes only new blobs, and files with the same content share one analysis.
- `snap-*.otx` files hold one commit's file list and coverage.
- `compiled/` holds compiled grammar modules on Linux.

Every file starts with the format and the analysis identity (the SHA-256 of the `trestle` program file), and a build that opens the index removes the files of any other build. Any damage, such as a file that fails its check or a missing record that a snapshot needs, clears the index, and the build or query starts over. Only one process uses the index at a time.

## Limits

| Limit | Default |
| --- | --- |
| Tree entries walked, directories included | 1,000,000 |
| Files analyzed per build | 200,000 |
| Bytes analyzed per build | 2 GiB |
| Analysis time per build | 30 minutes |
| Index size (segments and snapshots) | 1 GiB |
| Commits kept | 8, the newest |

A file left out by a limit keeps the limit as its status, and the next build continues with it. Past the size limit, the oldest commits are dropped first, but the newest is always kept and its files past the limit get `store_limit`. A file whose analysis fails as a whole, for example by its deadline, gets `analysis_failed` and is tried again by the next build. Per-file limits are those of [syntax analysis](syntax-analysis.md#resource-limits).

Files are analyzed in worker processes, one per CPU, within half of the machine's memory (or of the cgroup memory limit on Linux, when that is lower). A worker that crashes, returns malformed output or takes longer than three times the per-file deadline plus five seconds is killed and replaced, and its file gets `analysis_failed`. Workers start with an empty environment.

## Commands

```sh
trestle index build [--commit REF] [--directory PATH]
trestle index status [--commit REF] [--directory PATH]
trestle index query definitions NAME [--commit REF] [--directory PATH]
trestle index query references NAME [--commit REF] [--directory PATH]
trestle index query tests NAME [--commit REF] [--directory PATH]
trestle index query imports PATH [--commit REF] [--directory PATH]
trestle index query dependents --base REF [--commit REF] [--directory PATH]
```

`--commit` defaults to `HEAD`, and `--directory` names the setup folder. `build` and `status` print counts only. A query first indexes the commits it needs, then prints JSON in which every name and path is a JSON string, with control, format and bidirectional characters escaped.

Each answer has a `coverage` object: the build's coverage, the files by status, the files with each kind of analysis gap, and `complete`. `complete` is false when the tree was cut, a path or a `go.mod` file was left out, a file that should have an analysis has none, or an analysis has a gap. For `dependents` it is also false when a change was approximated or a limit cut the closure, because a reference in such a place is not seen.
