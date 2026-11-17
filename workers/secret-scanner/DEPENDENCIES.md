# Secret scanner dependencies

The secret scanner is an isolated Go module. It builds with Go 1.26.11 and does not add dependencies to the repository root module.

## Betterleaks pin

| Property | Value |
| --- | --- |
| Module | `github.com/betterleaks/betterleaks v1.8.1` |
| Module sum | `h1:tTSQAdQe+S4MF69o6VtpRDlml1b73F1xNUUA3PcrHiI=` |
| go.mod sum | `h1:M8pR9QvWFx+iWcRH2HG6Qe1wP9DLXhHt75iMNyZ7Y+s=` |
| Commit | `5eab48332cc48565864514e3bc6de89df091a7c4` |
| Source archive SHA-256 | `6cafe624ef2c8929e438268edc82fdfa498af19bb738b8fc698d7a6e39e30066` |
| Upstream go.mod SHA-256 | `e2cbda3d2af2f268f995ada686b1c78b8c96a18f237289e7520904c7029f45ca` |
| License | MIT |
| License SHA-256 | `caea114592a8f8e5e05a116d63a99e0ccd79a3ff74f4ddf270bcf4c929eb021e` |
| Default ruleset SHA-256 | `27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42` |
| Default rule count | 417 |

The adapter selects Betterleaks RE2 before parsing the embedded default config. It uses only `detect.Run` with a private in-memory source. Validation, decoding, filesystem sources, archives, remote sources, baselines, ignore files, reporting, diagnostics, and Betterleaks logging are disabled or unused.

## Patched copies for the scan guest

The scan guest (`guest/`, a separate Go module) links patched copies of two modules. The copies are in `third_party/`, each with the patch that produced it. The guest's `go.mod` replaces the upstream modules with the copies. This module's `go.mod` has no replace directive, so the native worker links the unmodified upstream modules.

| Copy | Upstream | Patch | License |
| --- | --- | --- | --- |
| `third_party/betterleaks` | `github.com/betterleaks/betterleaks v1.8.1` | `third_party/betterleaks-v1.8.1.patch` | MIT, upstream `LICENSE` kept |
| `third_party/tiktoken-go` | `github.com/pkoukk/tiktoken-go v0.1.8` | `third_party/tiktoken-go-v0.1.8.patch` | MIT, upstream `LICENSE` kept |

Each copy holds only the directories the guest builds, with every upstream file of those directories except tests and dot files. The Betterleaks copy keeps only `LICENSE`, `go.mod` and `go.sum` from its root directory. Betterleaks has no NOTICE file.

Changes in the Betterleaks patch:

- `regexp`: exports `CompiledRegexp`, an alias of the internal compiled-regexp interface, so that an engine can be implemented outside Betterleaks. Adds `PatternRecorder`; `Compile` passes every pattern text to an engine that implements it.
- `regexp/filterpatterns` (new): `Collect` lists, without evaluating anything, the joined patterns of every `matchesAny` and `findMatch` call in the ruleset's filter expressions. It fails when a pattern argument is neither a string literal nor a list of string literals.
- `detect`: the tokenizer loads its BPE ranks through the `BpeLoader` variable, which defaults to the upstream loader.

Changes in the tiktoken-go patch: `NewCoreBPE` no longer builds the decoder map, which is built on the first decode, or the sorted token list, which nothing reads. The check that no two tokens share a rank moved out of `NewCoreBPE`; the guest's flat table rejects repeated ranks when it loads.

`go test ./third_party` checks that every copied file equals the upstream file from the module cache, with the patch applied without fuzz, that no upstream file of a copied directory is missing, that `THIRD_PARTY_LICENSES/secret-scanner/MODULES.json` records each copy and the SHA-256 of its patch under `patched_copies`, and that every module the guest and the helper link has a reviewed entry there. To change a copy, edit it, regenerate its patch with `diff -ruN` between the upstream files and the copy, and update the digest in `MODULES.json`.

## Scan helper and guest build

`cmd/open-trestle-scan-helper` embeds the guest. The committed `cmd/open-trestle-scan-helper/guest.wasm` is empty, and a helper built from it exits 70. Build a working helper with:

```text
go run ./internal/cmd/build-scan-helper -o <directory>
```

It builds the guest with `GOOS=wasip1 GOARCH=wasm`, substitutes it for the empty `guest.wasm` through a `go build -overlay` file, and pins its SHA-256 with `-ldflags -X main.expectedGuestSHA256=<hex>`. The helper checks the embedded guest against the pin before compiling it. Tests build both once per test binary through `internal/helperbuild`.

Two generated files are checked by tests in the guest module:

- `internal/regexhost/pinned-patterns.json`, the patterns the host compiles for a guest. Regenerate it with `go test ./internal/pinnedpatterns -run TestHostTableEqualsRulesetPatterns -update` in `guest/` and set `PinnedPatternsSHA256` in `internal/regexhost/pinned.go` to its new digest.
- `guest/internal/bpe/cl100k_base.bin`, the flat cl100k_base BPE table. Regenerate it with `go test ./internal/bpe -run TestFlatTableEqualsUpstreamRanks -update` in `guest/`.

## Launcher toolchain and static runtime

The production launcher uses only the official Zig 0.14.1 x86_64 Linux archive pinned in `launcher/toolchain-v1.json`. The verified archive and extracted-tree digests bind the compiler, bundled LLD linker, headers, x86_64 musl sysroot, and generated static libraries. The fixed target is `x86_64-linux-musl`; host GCC, host libc, `PATH`, and a mutable sysroot are not build inputs.

The linked launcher contains musl 1.2.5 and Zig compiler-rt 0.14.1. Both are MIT licensed. Their complete legal texts and reviewed component inventory are in `THIRD_PARTY_LICENSES/secret-scanner-launcher/`. Linux UAPI headers from the same pinned archive are compile-time inputs under `GPL-2.0 WITH Linux-syscall-note`; no Linux kernel code is linked into the launcher.

## Module inventory input

The following versions are the unique module inputs reported by:

```text
GOWORK=off GOTOOLCHAIN=go1.26.11 go list -deps -f '{{with .Module}}{{if .Version}}{{.Path}} {{.Version}}{{end}}{{end}}' ./internal/adapter
```

- `dario.cat/mergo v1.0.2`
- `github.com/andybalholm/brotli v1.2.7`
- `github.com/betterleaks/betterleaks v1.8.1`
- `github.com/betterleaks/go-re2 v1.11.0-betterleaks.3`
- `github.com/bodgit/plumbing v1.3.0`
- `github.com/bodgit/sevenzip v1.6.2`
- `github.com/bodgit/windows v1.0.1`
- `github.com/charlievieth/fastwalk v1.0.14`
- `github.com/dlclark/regexp2 v1.11.5`
- `github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707`
- `github.com/expr-lang/expr v1.17.8`
- `github.com/fatih/semgroup v1.2.0`
- `github.com/gitleaks/go-gitdiff v0.9.1`
- `github.com/google/go-github/v72 v72.0.0`
- `github.com/google/go-querystring v1.1.0`
- `github.com/google/uuid v1.6.0`
- `github.com/go-sprout/sprout v1.0.3`
- `github.com/h2non/filetype v1.1.3`
- `github.com/hashicorp/golang-lru/v2 v2.0.7`
- `github.com/hashicorp/go-version v1.7.0`
- `github.com/klauspost/compress v1.20.2`
- `github.com/klauspost/pgzip v1.2.6`
- `github.com/Masterminds/semver/v3 v3.4.0`
- `github.com/mattn/go-colorable v0.1.14`
- `github.com/mattn/go-isatty v0.0.20`
- `github.com/mholt/archives v0.1.6-0.20260429171216-ef71b7a32fae`
- `github.com/mikelolasagasti/xz v1.0.1`
- `github.com/minio/minlz v1.1.1`
- `github.com/mitchellh/copystructure v1.2.0`
- `github.com/mitchellh/reflectwalk v1.0.2`
- `github.com/nwaples/rardecode/v2 v2.2.2`
- `github.com/pelletier/go-toml/v2 v2.3.1`
- `github.com/pierrec/lz4/v4 v4.1.26`
- `github.com/pkoukk/tiktoken-go v0.1.8`
- `github.com/rrethy/ahocorasick v1.0.0`
- `github.com/rs/zerolog v1.33.0`
- `github.com/shurcooL/githubv4 v0.0.0-20260209031235-2402fdf4a9ed`
- `github.com/shurcooL/graphql v0.0.0-20240915155400-7ee5256398cf`
- `github.com/sorairolake/lzip-go v0.3.8`
- `github.com/spf13/afero v1.15.0`
- `github.com/spf13/cast v1.10.0`
- `github.com/STARRY-S/zip v0.2.3`
- `github.com/tetratelabs/wazero v1.12.0`
- `github.com/ulikunitz/xz v0.5.15`
- `github.com/wasilibs/wazero-helpers v0.0.0-20250123031827-cd30c44769bb`
- `go4.org v0.0.0-20260112195520-a5071408f32f`
- `golang.org/x/crypto v0.53.0`
- `golang.org/x/exp v0.0.0-20250218142911-aa4b98e5adaa`
- `golang.org/x/sync v0.22.0`
- `golang.org/x/sys v0.46.0`
- `golang.org/x/text v0.41.0`
- `go.yaml.in/yaml/v3 v3.0.4`

`go.mod` and `go.sum` are authoritative for module resolution and checksums. `THIRD_PARTY_LICENSES/secret-scanner/MODULES.json` binds the reviewed license and notice files to every module in the linked production binary. `tools/package_secret_scanner.py` derives the final inventory with `go version -m` and fails on any missing, unknown, replaced, or changed module or legal file.
