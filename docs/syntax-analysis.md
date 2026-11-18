# Syntax analysis

Open Trestle analyses source files one at a time into a language-neutral record model, the `syntaxanalysis` package. Each `FileAnalysis` lists:

- definitions, with kind, name, source range, the range of the name, the enclosing definition and an exported flag;
- references and call sites, with the called or used name, an optional qualifier such as the receiver, and the enclosing definition;
- imports, with the module or path as written and, for member imports, the imported name and local alias; and
- coverage gaps: parse-error regions, unsupported languages, languages without a query pack, resource limits, the per-file deadline and analysis failures.

`FileAnalysis.EnclosingDefinition` returns the innermost definition at any byte offset, and `QualifiedName` joins a definition with its parents.

All records are syntactic. Names are not resolved to definitions, so a reference is a candidate, as in [semantic impact profiles](semantic-impact.md).

Every name, qualifier and import path is repository text. It is carried as a `syntaxanalysis.Text`, which never prints its contents through `fmt`: the formatting verbs print a placeholder, and `%p` and `%T` an address or the type name. Read it with `Text.Untrusted` and present it as quoted data, never as part of an instruction.

## Analyzers

- Go uses `semanticimpact.GoSyntaxAnalyzer`, built on `go/parser`.
- The other languages use `internal/syntaxwasm`: tree-sitter grammars compiled to WebAssembly and run under wazero. Java, JavaScript, TypeScript, TSX, Python, C and C++ have query packs. C#, Swift, Rust, PHP, Ruby and HTML have grammars in the modules but no query pack yet, so their files get a `no_query_pack` gap.

`syntaxanalysis.NewDispatcher` routes each file to the first analyzer that supports its language.

## Limits

`syntaxanalysis.Limits` bounds the file size (2 MiB by default), the number of records (65,536), the length of each name (1,024 bytes), the number of parse-error regions (256) and the time per file (5 seconds). Reaching a limit adds a `limit_exceeded` or `deadline_exceeded` gap; nothing is cut silently. A failure inside the analyzer becomes an `analysis_failed` gap for that file.

The WebAssembly analyzer also caps the linear memory of each module instance (256 MiB by default) and runs only with wazero's compiler. Where the compiler does not run, files get an `analysis_unavailable` gap. Its compilation cache directory must be private to the current user; it is refused on macOS and Windows, where the analyzer compiles each module once per process instead.

## Adding a language

The grammar of every language listed above is already built into a family module. Adding analysis for one of them takes a query pack and fixtures.

1. Write `internal/syntaxwasm/queries/<language>.scm`, where `<language>` is the `syntaxanalysis.Language` value, such as `rust`. Use only the capture names below. The shim does not evaluate text predicates such as `#eq?`; a query with one is refused.
2. Add the language to `packSpecs` in `internal/syntaxwasm/packs.go`, with a finishing function if the language has rules a query cannot express, such as implicit visibility.
3. Add fixtures under `internal/syntaxwasm/testdata/<language>/`: one realistic file of a few hundred lines that uses the language's main constructs, written for the project, plus small files for edge cases. Name each file with the language's usual extension.
4. Generate the golden files with `go test ./internal/syntaxwasm -run TestGolden -update`, then read every line of the `.golden` files and fix the queries until the records are right.
5. Add the language to the hostile-input tests in `host_test.go`.

Captures:

| Capture | Meaning |
|---|---|
| `@definition.<kind>` | The whole definition. Kinds: `function`, `method`, `constructor`, `class`, `struct`, `interface`, `enum`, `type`, `module`, `constant`, `variable`, `field`, `macro`. |
| `@reference.<kind>` | A use. Kinds: `call`, `construct`, `type`, `inherit`, `decorator`. |
| `@name` | The name of the definition or reference. |
| `@exported` | Marks the definition as exported. |
| `@qualifier` | The expression before a referenced name, such as a receiver. Keep it to identifiers and member chains. |
| `@import` | The whole import, with `@import.source`, and optionally `@import.name` and `@import.alias`. |
| `@export` | An export list entry; a top-level definition with its `@name` is exported. |
| `@container` | The owner named in a definition's name, as in `Owner::name`, when it is not the lexical parent. |
| `@opaque` | A span in which the pack drops type references, because the grammar reads values or macro arguments there as types. |
| `@match.<word>` | Keeps the match only when the captured text is `<word>`, in place of `#eq?`. |
| `@_<anything>` | A helper capture with no meaning. |

Each match must have exactly one of `@definition.*`, `@reference.*`, `@import` or `@export`. When patterns overlap, the analysis merges definitions that share a name, keeping the widest range and the most specific kind, and drops an import or reference that another match describes more completely. A function directly inside a class, struct, interface or enum becomes a method.

## C and C++

Both are analysed from syntax alone, with no preprocessing. Files ending in `.h` are read as C, so C++ code in them gets parse-error gaps; `.hh`, `.hpp` and `.hxx` are read as C++.

- Definitions: functions and prototypes, methods, constructors, structs, unions (as structs), classes, enums and enumerators, typedefs and aliases, namespaces, concepts, `#define` macros, file-scope variables and constants, and data members. A variable or member is a constant when nothing can reassign it: `const` on the declared type or on a pointer, or `constexpr`.
- A definition written as `Owner::name` records the owner as its container, and a constructor is named like its class. A destructor is a method named with its tilde. Conversion operators are not recorded.
- Includes are imports. A system include keeps its angle brackets, `<stdio.h>`; a quoted one is the text inside the quotes. `using` declarations and namespace aliases are imports too.
- References: calls (including macro invocations), constructions with `new`, braces or arguments, type uses, base classes, and attributes. A qualified name records its innermost scope as the qualifier.
- Exported means visible to other files. A function, variable or constant at file or namespace scope is exported unless it is `static` or in an anonymous namespace, and a C++ constant only when it is `extern` or declared in a header. A type, macro or namespace is exported when it is declared in a header. A class member is exported when its class is and its access is public.
- An anonymous namespace is recorded as a module named `namespace`.
- Macros are not expanded. What a macro generates is not seen, and a macro invocation that parses as a declaration or a block, such as a test-framework case, gives no definition. Locals are never recorded. A declaration such as `Foo x(y);` is ambiguous in C++ syntax; inside a function its names are not recorded as types.

## Rebuilding the modules

`tools/build_syntax_modules.py` builds the family modules from the inputs pinned in `internal/syntaxwasm/modules/manifest.json`: the wasi-sdk release archive, the tree-sitter runtime, each grammar and the wasi-libc license sources, each by commit and SHA-256 digest. The C shim is `internal/syntaxwasm/shim/analyze.c`. The script needs Linux on x86-64, Python 3.12, Git and network access. The wasi-sdk archive it downloads is about 190 MB.

```sh
python3 tools/build_syntax_modules.py             # rebuild twice and compare with the committed modules
python3 tools/build_syntax_modules.py --update    # rebuild and write modules, digests and license texts
python3 tools/build_syntax_modules.py --committed # check the committed modules only
```

Every build compiles the modules twice, in separate directories from separate copies of the sources, and fails unless the two are byte-identical. To change a pin, edit the commit or archive entry in the manifest, run `--update`, and review the diff of the manifest and of `THIRD_PARTY_LICENSES/syntax-analysis`. The modules may link only wasi-libc and its startup file; the script refuses any other library, because its license texts are not shipped.

A grammar that is not in a family yet needs a `sources` entry, a `grammars` entry, a place in a family, a `licenses` entry and a `syntaxanalysis.Language` value before its query pack.
