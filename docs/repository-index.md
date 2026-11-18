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
| `import` | the file imports the definition's file or package, as resolved from the import text, and the definition is exported | all |
| `name` | the definition is exported and the language makes it visible without an import of its file | C, C++, C#, Swift, PHP, Ruby |

In Go, a reference qualified by an imported package's name matches only that package's top-level definitions, and a method or field of another package matches only a selector in a file that imports that package.

Imports resolve by path rules: Go import paths through the module paths of the commit's `go.mod` files, or else to the directory they end with, Java class names to their file, relative JavaScript and TypeScript imports with the usual extensions and `index` files, HTML `src`, `href` and `action` values relative to the page, Python modules to `.py`, `.pyi` or `__init__.py`, C and C++ includes, Rust `use` paths, Ruby and PHP required paths and PHP namespaced names to files, and C# `using` to the files declaring the namespace. An import of a package outside the repository is unresolved and counted.

Names are not resolved to declarations, so a candidate can belong to another definition with the same name, and a use through a variable, an alias or reflection can be missed.

## Dependents

The dependents of a change start from its changed definitions: each definition, in the head or the base commit, that holds a changed line outside its child definitions. The closure then follows reference candidates backwards, breadth first: the definitions holding candidates of a changed definition have depth 1, those holding candidates of a depth-1 dependent depth 2, and so on. It stops at depth 3, 1,000 dependents and 2,000 candidates per definition, and records what each limit cut. Changed files without a complete analysis are listed as gaps.

## Where it lives

The index lives in the setup folder (see [environment variables and files](environment-and-files.md)), under `index/`: a `0700` folder of `0600` files.

- `seg-*.otx` files hold one analysis per blob and language. A blob analysed once is never analysed again for that program build, so a build of a new commit analyses only new blobs, and files with the same content share one analysis.
- `snap-*.otx` files hold one commit's file list and coverage.
- `compiled/` holds compiled grammar modules on Linux.

Every file starts with the format and the analysis identity, the SHA-256 of the `trestle` program file. A different build removes the files of another one when it opens the index. One process uses the index at a time. The index is not available on Windows yet, because its protected-file checks need owner and mode bits.

## Limits

| Limit | Default |
| --- | --- |
| Tree entries listed | 1,000,000 |
| Files analysed per build | 200,000 |
| Bytes analysed per build | 2 GiB |
| Analysis time per build | 30 minutes |
| Index size (segments and snapshots) | 1 GiB |
| Commits kept | 8, the newest |

A file a limit leaves out keeps the limit as its status, and the next build continues with it. Past the size limit, the oldest commits are dropped first; the newest is always kept, and its files past the limit get `store_limit`. A file whose analysis fails as a whole, for example by its deadline, gets `analysis_failed` and is tried again by the next build. Per-file limits are those of [syntax analysis](syntax-analysis.md#resource-limits).

Files are analysed in worker processes, one per CPU within half of the physical memory. A worker that takes longer than three times the per-file deadline plus five seconds, crashes or answers malformed output is killed and replaced, and its file gets `analysis_failed`. Workers start with an empty environment.

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

`--commit` defaults to `HEAD`; `--directory` names the setup folder. `build` and `status` print counts only. Queries print JSON, in which every name and path is a JSON string; a query indexes the commits it needs first. `dependents` diffs each changed file's base and head blobs to find the changed lines.
