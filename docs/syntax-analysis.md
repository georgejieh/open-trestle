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
- The other languages use `internal/syntaxwasm`: tree-sitter grammars compiled to WebAssembly and run under wazero. Java, JavaScript, TypeScript, TSX, Python, C, C++, C#, Rust, Swift, PHP, Ruby and HTML have query packs.

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
| `@local` | A span, such as a block, in which variables and function declarations are locals and are not recorded. |
| `@symbol` | A name written as a symbol, such as Ruby's `:name`; the leading colon is left out of the name. |
| `@match.<word>` | Keeps the match only when the captured text is `<word>`, in place of `#eq?`. |
| `@_<anything>` | A helper capture with no meaning. |

Each match must have exactly one of `@definition.*`, `@reference.*`, `@import` or `@export`. When patterns overlap, the analysis merges definitions that share a name, keeping the widest range and the most specific kind, and drops an import or reference that another match describes more completely. A function directly inside a class, struct, interface or enum becomes a method.

## C and C++

Both are analysed from syntax alone, with no preprocessing. `.hh`, `.hpp` and `.hxx` files are C++. A `.h` file is C unless its first 256 KiB use syntax that C does not have, such as a namespace, a template, a class or the `::` operator; it is then analysed and reported as C++.

- Definitions: functions and prototypes, methods, constructors, structs, unions (as structs), classes, enums and enumerators, typedefs and aliases, namespaces, concepts, `#define` macros, file-scope variables and constants, and data members. A variable or member is a constant when nothing can reassign it: `const` on the declared type or on a pointer, or `constexpr`.
- A definition written as `Owner::name` records the owner as its container, and a constructor is named like its class. A destructor is a method named with its tilde. Conversion operators are not recorded.
- Includes are imports. A system include keeps its angle brackets, `<stdio.h>`; a quoted one is the text inside the quotes. `using` declarations and namespace aliases are imports too.
- References: calls (including macro invocations), constructions with `new`, braces or arguments, type uses, base classes, and attributes. A qualified name records its innermost scope as the qualifier.
- Exported means visible to other files. A function, variable or constant at file or namespace scope is exported unless it is `static` or in an anonymous namespace, and a C++ constant only when it is `extern` or declared in a header. A type, macro or namespace is exported when it is declared in a header. A class member is exported when its class is and its access is public.
- An anonymous namespace is recorded as a module named `namespace`.
- Macros are not expanded. What a macro generates is not seen, and a macro invocation that parses as a declaration or a block, such as a test-framework case, gives no definition. Locals are never recorded. A declaration such as `Foo x(y);` is ambiguous in C++ syntax; inside a function its names are not recorded as types.

## C#, Rust and Swift

These packs record definitions, calls and constructions, type uses, base types and conformances, attributes, and imports.

- C# records namespaces (a file-scoped namespace covers the rest of the file), classes, structs, records, interfaces, enums, delegates, methods, constructors, operators, properties, events, indexers and fields. `public` makes a definition exported, and members of an interface or enum take the visibility of their owner. Both sides of a `#if` are read as written.
- Rust records modules, structs, unions, enums and variants, traits, type aliases, functions, constants, statics, macros and named fields. An `impl` block is recorded as a class named after the type it implements, so its functions are methods of that type and a trait impl is exported. `pub` makes a definition exported, and a `use` list is recorded as one import per member. The arguments of a macro are not parsed, so calls and definitions written inside macros are not recorded, but the macro call itself is.
- Swift records classes, structs, enums and their cases, actors, protocols, extensions, functions, initializers, subscripts, type aliases, properties and top-level constants. An extension is recorded as a class named after the extended type. `public` and `open` make a definition exported, and members of a protocol, an enum, or a public extension take the visibility of their owner. A call of a type name is recorded as a call, because the syntax does not tell it from a function call.

## Rebuilding the modules

`tools/build_syntax_modules.py` builds the family modules from the inputs pinned in `internal/syntaxwasm/modules/manifest.json`: the wasi-sdk release archive, the tree-sitter runtime, each grammar and the wasi-libc license sources, each by commit and SHA-256 digest. The C shim is `internal/syntaxwasm/shim/analyze.c`. The script needs Linux on x86-64, Python 3.12, Git and network access. The wasi-sdk archive it downloads is about 190 MB.

```sh
python3 tools/build_syntax_modules.py             # rebuild twice and compare with the committed modules
python3 tools/build_syntax_modules.py --update    # rebuild and write modules, digests and license texts
python3 tools/build_syntax_modules.py --committed # check the committed modules only
```

Every build compiles the modules twice, in separate directories from separate copies of the sources, and fails unless the two are byte-identical. To change a pin, edit the commit or archive entry in the manifest, run `--update`, and review the diff of the manifest and of `THIRD_PARTY_LICENSES/syntax-analysis`. The modules may link only wasi-libc and its startup file; the script refuses any other library, because its license texts are not shipped.

A grammar that is not in a family yet needs a `sources` entry, a `grammars` entry, a place in a family, a `licenses` entry and a `syntaxanalysis.Language` value before its query pack.

## PHP, Ruby and HTML

PHP records namespaces, classes, interfaces, enums, functions, methods, properties, constants and file-level variables, and traits as classes. A member is exported unless it is private or protected; interface members and anything at file or namespace level are exported. A namespace without braces covers the file up to the next namespace declaration. A property declared in a constructor's parameter list is a field of the class, which it names as its container. Calls, `new`, type uses, `extends`, `implements`, trait `use`, attributes, `use` imports and `require` or `include` of a literal path are recorded. The names `self`, `static` and `parent` are not references.

Ruby records modules, classes, methods, aliases, constants and class variables. A constant bound to `Struct.new`, `Class.new` or `Data.define` is a class, and one bound to `Module.new` is a module. A name such as `class A::B` is recorded as `B` with `A` as its container. `private`, `protected`, `public`, `module_function`, `private_constant` and `private_class_method` set the exported flag, and a `class << self` block adds its methods to the class around it. `attr_reader`, `attr_writer`, `attr_accessor` and `attr` record a method per name, and `define_method` and `alias_method` their first argument, when it is a symbol or a plain string; an `attr_writer` method is recorded without its `=`. Calls, `Name.new`, superclasses, `include`, `extend`, `prepend`, `rescue` types and `require`, `require_relative`, `load` and `autoload` with a literal path are recorded. A bare identifier is not a call, because it may be a local variable.

HTML has no functions or types. An element with an `id` is recorded as a variable named by the id, nested by element. A tag name with a hyphen is recorded as a construction of that custom element. The `src`, `href` and `action` attributes are recorded as imports with the value as written, except the `href` of `base`. Fragment-only values and the `javascript:`, `data:`, `mailto:`, `tel:`, `sms:`, `blob:` and `about:` schemes are left out, and so are `srcset`, `formaction` and `poster`. The code inside `script` and `style` elements is not analysed.
