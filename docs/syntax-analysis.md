# Syntax analysis

Open Trestle analyzes source files one at a time into a language-neutral record model, the `syntaxanalysis` package. Each `FileAnalysis` lists:

- definitions, with kind, name, source range, the range of the name, the enclosing definition, an optional container and an exported flag;
- references and call sites, with the called or used name, an optional qualifier such as the receiver, and the enclosing definition;
- imports, with the module or path as written and, for member imports, the imported name and local alias; and
- coverage gaps: parse-error regions, unsupported languages, languages without a query pack, resource limits, the per-file deadline and analysis failures.

`FileAnalysis.EnclosingDefinition` returns the innermost definition at any byte offset, and `QualifiedName` joins a definition with its parents.

All records are syntactic. Names are not resolved to definitions, so a reference is only a candidate, as in [semantic impact profiles](semantic-impact.md).

Every name, qualifier and import path is repository text, carried as a `syntaxanalysis.Text` that never prints its contents through `fmt`: the formatting verbs print a placeholder, and `%p` and `%T` an address or the type name. Read it with `Text.Untrusted` and present it as quoted data, never as part of an instruction.

## Supported languages

- Go uses `semanticimpact.GoSyntaxAnalyzer`, built on `go/parser`. The package clause is a module definition.
- Java, JavaScript, TypeScript, TSX, Python, C, C++, C#, Rust, Swift, PHP, Ruby and HTML use `internal/syntaxwasm`: tree-sitter grammars compiled to WebAssembly and run under wazero, with a query pack per language.

`syntaxanalysis.NewDispatcher` routes each file to the first analyzer that supports its language.

## What is recorded

Every pack records the language's definitions, calls and constructions, type uses, base types, attributes or decorators, and imports, with the parent of each record. A function directly inside a class, struct, interface or enum is a method. A definition is exported when the language's visibility rules make it visible outside its file or module and its parent is exported. Namespaces, Rust impl blocks and Swift extensions have no visibility of their own and count as exported.

Only Go records `value` references, uses of a name outside a call or type position, and `syntaxanalysis.RecordsValueUses` says which languages do.

- Go value uses: reads and writes of package-level variables and constants, functions and methods used as values, selectors such as field reads, and composite literal keys. A selector or key is qualified by its type, written `T` or `pkg.T`, when the file declares it (a receiver, parameter, variable, composite literal, `new`, a function of the file or a range over one of these), and otherwise by the expression before the name. No record of any kind is made for names that `go/parser` binds to a local declaration or a label, defining names, field and method names in declarations, package and import names, the blank identifier, `nil`, `true`, `false` and `iota`, or fields of an anonymous or local struct type. Type arguments, the type argument of `make` and `new`, conversions such as `[]T(x)` and type switch cases are type uses.
- Java: packages, classes, interfaces, enums, records, annotations, methods, constructors, fields and constants. Interface and annotation members and enum constants take their implicit visibility. A wildcard import keeps the asterisk as its name.
- JavaScript, TypeScript and TSX: functions, classes, methods, constructors and module-level bindings. TypeScript adds interfaces, type aliases, enums, namespaces and the members of interfaces and object type aliases. Static imports, re-exports, and `import()` and `require()` with a literal are imports, and JSX elements are constructions.
- Python: functions, classes, methods, and module and class level bindings. `__init__` is the constructor and an upper-case module binding a constant. A name is exported when `__all__` lists it or, without `__all__`, when it does not start with an underscore.
- C and C++: functions and prototypes, methods, constructors, structs, unions, classes, enums and enumerators, typedefs and aliases, namespaces, concepts, `#define` macros, file and namespace variables and constants, and data members. A definition written as `Owner::name` records `Owner` as its container. Includes, `using` declarations and namespace aliases are imports, and a system include keeps its angle brackets. Exported means visible to other files: not `static`, not in an anonymous namespace, a C++ constant only when `extern` or in a header, and a type or macro only in a header.
- C#: namespaces, classes, structs, records, interfaces, enums, delegates, methods, constructors, operators, properties, events, indexers and fields. A file-scoped namespace covers the rest of the file.
- Rust: modules, structs, unions, enums and variants, traits, type aliases, functions, constants, statics, macros and named fields. An `impl` block is a class named after the type it implements, so its functions are methods of that type. A `use` list is one import per member.
- Swift: classes, structs, enums and their cases, actors, protocols, extensions, functions, initializers, subscripts, type aliases, properties and top-level constants. An extension is a class named after the extended type. Members of a protocol, an enum or a public extension take their owner's visibility.
- PHP: namespaces, classes, traits (as classes), interfaces, enums, functions, methods, properties, constants and file-level variables. A property declared in a constructor's parameter list is a field of the class, which it names as its container. A namespace without braces covers the file up to the next namespace declaration. `use` imports and `require` or `include` of a literal path are imports.
- Ruby: modules, classes, methods, aliases, constants and class variables. A constant bound to `Struct.new`, `Class.new` or `Data.define` is a class. `attr_reader`, `attr_writer`, `attr_accessor` and `attr` record a method per name, and `define_method` and `alias_method` record their first argument. `class A::B` is `B` with container `A`. The visibility keywords set the exported flag, and `class << self` adds its methods to the enclosing class. `require`, `require_relative`, `load` and `autoload` with a literal path are imports.
- HTML: an element with an `id` is a variable named by the id, spanning its start tag. A custom element tag is a construction, and `src`, `href` and `action` values naming a resource are imports. Attribute names match in any case. The text of an inline `script` is analyzed as JavaScript, or as TypeScript or TSX when its `lang` or `type` attribute says so, within the file's deadline. Its definitions are at file level, and nothing in it is exported.

## Limits per language

- C and C++: no preprocessing, so what a macro generates is not seen, and a macro invocation that parses as a declaration or a block, such as a test case, gives no definition. Locals and conversion operators are not recorded. A `.h` file is parsed as both C and C++ within its deadline, and is analyzed and reported as C++ when the C++ parse has fewer error regions, or as many and more definitions.
- C#: both sides of a `#if` are read as written.
- Rust: macro arguments are not parsed, so calls and definitions inside a macro are not recorded, but the macro call is.
- Swift: a call of a type name is recorded as a call, because the syntax does not distinguish it from a function call. A generic type constructed through a qualifier, as in `Foo.Bar<Int>(x: 1)`, is not read by the grammar and gives no record.
- PHP: the HTML around the PHP code is not analyzed. `self`, `static` and `parent` are not references.
- Ruby: a bare identifier is not a call, because it may be a local variable. An `attr_writer` method is recorded without its `=`. A method name built by interpolation is not recorded.
- HTML: a script of another type, such as JSON, an import map or a template, is not analyzed, whatever its `lang` says, and neither is `style` text. Elements are not nested, so an id is recorded on its start tag only. `srcset`, `formaction` and `poster` are not imports, and neither are fragment-only values or the `javascript:`, `data:`, `mailto:`, `tel:`, `sms:`, `blob:` and `about:` schemes.

## Resource limits

`syntaxanalysis.Limits` bounds the file size (2 MiB by default), the number of records (65,536), the length of each name (1,024 bytes), the number of parse-error regions (256) and the time per file (5 seconds). Reaching a limit adds a `limit_exceeded` or `deadline_exceeded` gap, so nothing is cut silently. A failure inside the analyzer becomes an `analysis_failed` gap for that file.

The WebAssembly analyzer also caps the linear memory of each module instance (256 MiB by default) and runs only with wazero's compiler. Where the compiler does not run, files get an `analysis_unavailable` gap. The compilation cache directory must be private to the current user. It is refused on macOS and Windows, where each module is compiled once per process instead.

The deadline covers the parse and the host work after it. A watchdog abandons a guest that ignores its stop checks at twice the deadline and stops it at its next check. Later analyses in its family then use code compiled with wazero's termination checks. A guest that loops without reaching a stop check keeps a goroutine and its CPU until the process exits. `Analyzer.AbandonedCalls` counts such calls, so a host that runs analysis in a worker process can replace the worker.

## Adding a language

A language needs a grammar in a family module (see below), a query pack and fixtures.

1. Write `internal/syntaxwasm/queries/<language>.scm`, where `<language>` is the `syntaxanalysis.Language` value, such as `rust`. Use only the capture names below. The shim does not evaluate text predicates such as `#eq?` and refuses a query that has one.
2. Add the language to `packSpecs` in `internal/syntaxwasm/packs.go`, with a finishing function if it has rules a query cannot express, such as implicit visibility.
3. Add fixtures under `internal/syntaxwasm/testdata/<language>/`: one realistic file of 300 to 400 lines, written for the project, that uses the language's main constructs, and small files for edge cases, each with the language's usual extension. The realistic file must parse with no error regions.
4. Generate the golden files with `go test ./internal/syntaxwasm -run TestGolden -update`. Then read every line of the `.golden` files and fix the queries until the records are right.
5. Add the language to `hostileInputs` in `hostile_test.go` and to `gateFixtures` in `gate_test.go`, and run the gate: `OPEN_TRESTLE_SYNTAX_GATE=1 go test -run '^TestSyntaxGate$' -v ./internal/syntaxwasm/`.

Captures:

| Capture | Meaning |
|---|---|
| `@definition.<kind>` | The whole definition. Kinds: `function`, `method`, `constructor`, `class`, `struct`, `interface`, `enum`, `type`, `module`, `constant`, `variable`, `field`, `macro`. |
| `@reference.<kind>` | A use. Kinds: `call`, `construct`, `type`, `inherit`, `decorator`, `value`. |
| `@name` | The name of the definition or reference. |
| `@symbol` | A name written as a symbol, such as Ruby's `:name`, without the leading colon. |
| `@exported` | Marks the definition as exported. |
| `@qualifier` | The expression before a referenced name, such as a receiver. Keep it to identifiers and member chains. |
| `@container` | The owner named in a definition's name, as in `Owner::name`, when it is not the lexical parent. |
| `@import` | The whole import, with `@import.source`, and optionally `@import.name` and `@import.alias`. |
| `@export` | An export list entry. A top-level definition with its `@name` is exported. |
| `@opaque` | A span in which type references are dropped, because the grammar reads values or macro arguments there as types. |
| `@local` | A span, such as a block, whose variables and function declarations are locals and are not recorded. |
| `@embedded` | Code in another language, such as an HTML script, with `@embedded.tag` for the start tag that names the language. |
| `@match.<word>` | Keeps the match only when the captured text is `<word>`, in place of `#eq?`. |
| `@nocase.<word>` | Keeps the match only when the captured text is `<word>` in any ASCII case. |
| `@_<anything>` | A helper capture with no meaning. |

Each match must have exactly one of `@definition.*`, `@reference.*`, `@import` or `@export`, unless it only marks `@opaque`, `@local` or `@embedded` spans. When patterns overlap, the analysis merges definitions that share a name, keeping the widest range and the most specific kind, and drops an import or reference that another match describes more completely.

## Rebuilding the modules

`tools/build_syntax_modules.py` builds the family modules from the inputs pinned in `internal/syntaxwasm/modules/manifest.json`: the wasi-sdk release archive, the tree-sitter runtime, each grammar and the wasi-libc license sources, all by commit and SHA-256 digest. The C shim is `internal/syntaxwasm/shim/analyze.c`. The script needs Linux on x86-64, Python 3.12, Git and network access, and the wasi-sdk archive it downloads is about 190 MB.

```sh
python3 tools/build_syntax_modules.py             # rebuild twice and compare with the committed modules
python3 tools/build_syntax_modules.py --update    # rebuild and write modules, digests and license texts
python3 tools/build_syntax_modules.py --committed # check the committed modules only
```

Every build compiles the modules twice, in separate directories from separate copies of the sources, and fails unless the two results are byte-identical. To change a pin, edit the commit or archive entry in the manifest, run `--update`, and review the diff of the manifest and of `THIRD_PARTY_LICENSES/syntax-analysis`. The modules may link only wasi-libc and its startup file. The script refuses any other library, because its license texts are not shipped.

A grammar not yet in a family needs a `sources` entry, a `grammars` entry, a place in a family, a `licenses` entry and a `syntaxanalysis.Language` value before its query pack.
