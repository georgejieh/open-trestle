# Repository index

The repository index records every file of a commit and the [syntax analysis](syntax-analysis.md) of its source files, so that a query can find definitions, their uses, the tests that use them and what depends on a change. Reviews do not use it yet.

## What it holds

For each file of the commit's tree:

- its role: `source`, `test`, `config`, `docs`, `generated`, `vendored` or `other`, from fixed rules on the path, and `generated` also when the first 2 KiB hold `Code generated ... DO NOT EDIT` or `@generated`;
- its language, when an analyzer supports it;
- its status: `indexed`, or why it has no analysis (`not_analysed`, `binary`, `symlink`, `submodule`, `unavailable`, `analysis_failed`, or the limit that left it out); and
- for an indexed file, its definitions, references, imports and coverage gaps.

Files of the roles `source`, `test` and `generated` are analysed. Vendored code (directories such as `vendor`, `third_party` and `node_modules`), docs, config and other files are listed with their role only. A file whose first 8,000 bytes hold a NUL byte is binary and is not analysed.

The index reads the commit from the verified Git object store that reviews read, never from the working tree.

## Reference candidates

A reference is a candidate for a definition when it has the definition's exact name, is in a file of the same language family, and one of these holds. The scope in each answer says which.

| Scope | Rule | Languages |
| --- | --- | --- |
| `file` | the same file | all |
| `package` | the same package: the directory for Go and Swift, the declared package or namespace for Java, C# and PHP | Go, Java, C#, Swift, PHP |
| `import` | the file imports the definition's file, or its package for a Go or C# import or a Java wildcard, as resolved from the import text, and the definition is exported | all |
| `name` | the definition is exported and the language makes it visible without an import of its file | C, C++, C#, Swift, PHP, Ruby |

In Go, a reference qualified by the name an import binds (its alias, or the package's declared name) matches only that package's top-level definitions, and a method or field of another package matches only a selector in a file that imports that package.

Imports resolve by path rules: Go import paths through the module paths of the commit's `go.mod` files (an import outside them stays unresolved; only a file under no known module falls back to the directory the path ends with), Java class names to their file, relative JavaScript and TypeScript imports with the usual extensions and `index` files, HTML `src`, `href` and `action` values relative to the page, Python modules to `.py`, `.pyi` or `__init__.py`, C and C++ includes, Rust `use` paths, Ruby and PHP required paths and PHP namespaced names to files, and C# `using` to the files declaring the namespace. An import of a package outside the repository is unresolved and counted.

Names are not resolved to declarations, so a candidate can belong to another definition with the same name, and a use through a variable, an alias or reflection can be missed.

## Dependents

The dependents of a change start from its changed definitions: each definition, in the head or the base commit, that holds a changed line outside its child definitions. The closure then follows reference candidates backwards, breadth first: the definitions holding candidates of a changed definition have depth 1, those holding candidates of a depth-1 dependent depth 2, and so on. It stops at depth 3, 1,000 dependents, 2,000 candidates per definition and 2,000,000 references checked, and records what each limit cut. Changed files without a complete analysis are listed as gaps. A definition of a file the head no longer has is still matched in its package and in the files that imported that file in the base, and a definition that lost its export is still matched in the files that imported it.

`trestle index query dependents` finds the changed files by comparing the two snapshots. A deleted and an added file with the same blob are a move without a change, matched one to one; a deleted and an added file with the same base name, when no other deleted or added file has it, are a move with an edit. Any other deletion while an addition is left is recorded as a possible move (`unmatched_move`). Each modified file's base and head blobs are diffed, up to 256 MiB in all, to find the changed lines; a file past that budget (`diff_budget`) or that the diff cannot represent (`diff_unavailable`) counts as changed throughout.

## Where it lives

The index lives in the setup folder (see [environment variables and files](environment-and-files.md)), under `index/`: a folder and files that only your account can use (mode `0700` and `0600` on Unix, an owner-only access list on Windows).

- `seg-*.otx` files hold one analysis per blob and language. A blob analysed once is never analysed again for that program build, so a build of a new commit analyses only new blobs, and files with the same content share one analysis.
- `snap-*.otx` files hold one commit's file list and coverage.
- `compiled/` holds compiled grammar modules on Linux.

Every file starts with the format and the analysis identity, the SHA-256 of the `trestle` program file. A different build removes the files of another one when it opens the index. Any damage, a file that fails its check or a record a snapshot needs that is missing, clears the index, and the build or query starts over. One process uses the index at a time.

## Limits

| Limit | Default |
| --- | --- |
| Tree entries walked, directories included | 1,000,000 |
| Files analysed per build | 200,000 |
| Bytes analysed per build | 2 GiB |
| Analysis time per build | 30 minutes |
| Index size (segments and snapshots) | 1 GiB |
| Commits kept | 8, the newest |

A file a limit leaves out keeps the limit as its status, and the next build continues with it. Past the size limit, the oldest commits are dropped first; the newest is always kept, and its files past the limit get `store_limit`. A file whose analysis fails as a whole, for example by its deadline, gets `analysis_failed` and is tried again by the next build. Per-file limits are those of [syntax analysis](syntax-analysis.md#resource-limits).

Files are analysed in worker processes, one per CPU within half of the memory (the cgroup memory limit on Linux when it is lower). A worker that takes longer than three times the per-file deadline plus five seconds, crashes or answers malformed output is killed and replaced, and its file gets `analysis_failed`. Workers start with an empty environment.

## Commands

```sh
trestle index build [--commit REF] [--directory PATH]
trestle index status [--commit REF] [--directory PATH]
trestle index query definitions NAME [--commit REF]
trestle index query references NAME [--commit REF]
trestle index query tests NAME [--commit REF]
trestle index query imports PATH [--commit REF]
trestle index query dependents --base REF [--commit REF]
```

`--commit` defaults to `HEAD`; `--directory` names the setup folder. `build` and `status` print counts only. Queries print JSON, in which every name and path is a JSON string, with control, format and bidirectional characters escaped. Each answer has a `coverage` object: the build's coverage, the files by status, the files with each kind of analysis gap, and `complete`. `complete` is false when the tree was cut, a path or a `go.mod` file was left out, a file that should have an analysis has none or an analysis has a gap, and for `dependents` also when a change was approximated or a limit cut the closure: a reference in such a place is not seen. A query indexes the commits it needs first.
