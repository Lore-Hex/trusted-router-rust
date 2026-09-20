# Rust consumer DX

Worktree-only changes; no commit and no new runtime dependencies. There is no SDK CLI.

## Artifact and metadata

The exact `cargo package --list -p trusted-router` output is captured in
[package-before.txt](package-before.txt) (29 files) and
[package-after.txt](package-after.txt) (26 files; `--allow-dirty` for this worktree).
The removed members are `examples/chat.rs`, `examples/responses.rs`, and
`examples/streaming.rs`. The final archive contains 19 library source files,
`build.rs` (required to compile the telemetry runtime identity), README, LICENSE,
and four Cargo-generated manifest/lock/VCS files. Tests, fixture keys, scripts,
CI files, examples and scratch files are absent.

The manifest now uses `include = ["src/**", "build.rs", "LICENSE", "README.md"]`
instead of `exclude = ["tests/**"]`. The contract test builds the actual `.crate`,
compares tar members to Cargo's listing, checks required members and rejects
unexpected files, including non-Rust files anywhere under `src/`.

| Metadata | Before | After |
| --- | --- | --- |
| description | Official Rust SDK for TrustedRouter | unchanged |
| license | Apache-2.0 | unchanged; packaged license compared with workspace license |
| repository | https://github.com/Lore-Hex/trusted-router-rust | unchanged |
| homepage | https://trustedrouter.com | unchanged |
| documentation | absent | https://docs.rs/trusted-router |
| keywords | ai, llm, openai, api, attestation | unchanged |
| categories | api-bindings, web-programming::http-client | unchanged |
| rust-version | 1.88 | unchanged; checked with installed Rust 1.88.0 |

## Documentation and coverage

The public crate denies `missing_docs` and `rustdoc::broken_intra_doc_links`.
Existing public symbols already had documentation; no missing API documentation
needed filling. The shipped README is included in the crate's rustdoc. A
feature-dependent intra-doc link uses code formatting so the feature-disabled
build also documents cleanly. The newly included README needed one Clippy
`doc_markdown` correction.

The documentation test discovers root Markdown files, both READMEs, and every
Markdown guide under `docs/`. It feeds their complete text to rustdoc in a
scratch crate depending on the extracted package, checks the exact test count,
and rejects ignored or `compile_fail` examples. All nine existing Rust Markdown
examples are checked (eight in the root README and one in the shipped README).
Network examples compile with `no_run`; the orchestration example executes.
The formerly ignored receipt example now has imports and a typed async wrapper.
Shell fences contain installation/build commands and are operational recipes,
not Rust doctests. The C example is compiled as C11 and C++17 by the existing CI.

| Surface | Before | After |
| --- | --- | --- |
| CLI command × option | N/A: no CLI | N/A: no CLI added |
| Root README Rust examples | 0 checked; receipt ignored | 8 checked, none ignored |
| Shipped README Rust examples | 0 checked | 1 checked in native and consumer doctests |
| Future `docs/**/*.md` Rust examples | no discovery | automatic discovery and compile check |
| Archive file policy | key/secret extension check in CI | built archive/list equality and allowlist test |
| Scratch consumer | none | typed `ModelList` call over loopback from extracted `.crate` |

## Scratch consumer commands

Run the complete reproducible recipe from the repository root:

```sh
export PATH="/opt/homebrew/bin:$PATH"
python3 scripts/test_consumer.py
```

The suite prints exact Cargo commands and temporary paths. It builds with
`cargo package -p trusted-router --locked --allow-dirty --no-verify`, extracts the
archive outside the repository, writes a temporary Cargo manifest whose
`trusted-router.path` is that extracted directory, and copies
`scripts/consumer_smoke.rs` to `src/main.rs`. The separate full CI package check
runs verification without `--no-verify`. The consumer makes a real authenticated
`GET /v1/models` request to a hand-rolled `std::net::TcpListener`; it verifies the
request and checks the typed returned model name. Both API planes point to the
fake and telemetry is disabled. No wiremock dependency is used by the consumer.
All temporary sources are removed on completion; Cargo caches live in `target/`.

## Change locations

- `crates/trusted-router/Cargo.toml:7`: package allowlist and documentation URL.
- `crates/trusted-router/src/lib.rs:5`: feature-independent intro, README inclusion and public documentation denies.
- `crates/trusted-router/README.md:25`: rustdoc-compatible product-name formatting.
- `README.md:244`: compiling receipt verification example.
- `scripts/test_consumer.py:23`: reproducible command runner and diagnostics.
- `scripts/test_consumer.py:33`: artifact policy assertion.
- `scripts/test_consumer.py:49`: package, inspect and extract outside the repo.
- `scripts/test_consumer.py:75`: refresh normalized archive timestamps so Cargo cannot reuse stale compiler/rustdoc output.
- `scripts/test_consumer.py:93`: archive, metadata, public docs, Markdown and consumer tests.
- `scripts/consumer_smoke.rs:7`: typed consumer and bounded loopback fake.
- `scripts/consumer_mutation_check.py:19`: focused negative-test runner.
- `scripts/consumer_mutation_check.py:28`: mutation catalog, isolated copies, baseline checks and restoration.
- `.github/workflows/ci.yml:35`: Python version, consumer tests and mutation gate.
- `CONTRIBUTING.md:14`: local consumer/doc commands and workflow description.
- `docs/consumer-dx/package-before.txt:1`, `docs/consumer-dx/package-after.txt:1`: exact artifact listings.
- `docs/consumer-dx/results.md:1`: this audit and reproduction report.

For a minimal consumer with only the SDK as a direct dependency, the following
commands were also run (the package verification command appears in the CI list):

```sh
export PATH="/opt/homebrew/bin:$PATH"
repo="$PWD"
cargo package -p trusted-router --locked --allow-dirty
scratch=$(mktemp -d /tmp/tr-rust2-smoke.XXXXXX)
tar -xzf "$repo/target/package/trusted-router-0.3.0.crate" -C "$scratch"
mkdir -p "$scratch/consumer/src"
printf '[package]\nname = "packaged-smoke"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\ntrusted-router = { path = "%s" }\n' "$scratch/trusted-router-0.3.0" > "$scratch/consumer/Cargo.toml"
cp scripts/consumer_smoke.rs "$scratch/consumer/src/main.rs"
cp "$scratch/trusted-router-0.3.0/Cargo.lock" "$scratch/consumer/Cargo.lock"
CARGO_TARGET_DIR="$repo/target/consumer-dx" cargo run --manifest-path "$scratch/consumer/Cargo.toml"
```

## Verification

Toolchain: Homebrew Cargo 1.97.1 (`/opt/homebrew/bin` first in PATH); Python 3.12
locally, Python 3.11 selected for the consumer suite in CI. The following checks
passed locally on macOS:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`: 164 passed, three existing live-service smoke tests ignored.
- `cargo test --doc`: one packaged README doctest passed.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
- `cargo doc -p trusted-router --no-deps --no-default-features`
- `python3 scripts/test_consumer.py`: five tests passed, including nine Markdown examples and the fake-server call from the extracted artifact.
- `python3 scripts/test_mutation_check.py`: five wave 1 mutation-runner tests passed.
- `cargo package -p trusted-router --locked --allow-dirty`: complete package verification; dirty-tree allowance is needed because this task explicitly prohibits committing.
- `cmp crates/trusted-router/LICENSE LICENSE`
- `cargo build --release -p trusted-router-ffi`
- `cc -std=c11 -Wall -Wextra -Werror -c examples/c/chat.c -I crates/trusted-router-ffi/include -o /tmp/rust2-chat.o`
- `c++ -std=c++17 -Wall -Wextra -Werror -x c++ -c examples/c/chat.c -I crates/trusted-router-ffi/include -o /tmp/rust2-chat-cpp.o`
- `RUSTC=/Users/jperla/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin/rustc CARGO_TARGET_DIR="$PWD/target/msrv" /Users/jperla/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin/cargo check --workspace --all-features --locked`
- `CARGO_HOME=/tmp/rust2-audit-cargo /Users/jperla/.cargo/bin/cargo-audit audit --db /tmp/rust2-advisory-db`: freshly fetched advisory database and crates.io index, no findings. The temporary Cargo home avoids the sandbox's read-only home directory.
- `../../conf-venv/bin/tr-conformance --sdk rust --sdk-root rust="$PWD" --json-report docs/consumer-dx/conformance.json`: **25 passed, zero failed, zero skipped**. Loopback binding worked; not sandbox-blocked.
- `git diff --check`

Conformance evidence: [conformance.json](conformance.json). No live-service
credentials were used. Other OS matrix jobs and publication steps were not run
locally; the complete local test, lint, documentation, package, MSRV, audit and
C/C++ command set was run.

Minimal scratch directory used: `/tmp/tr-rust2-smoke.yULhHt`. Its output was `packaged consumer: GET /v1/models -> Fake`.

The exact commands and generated temporary paths from the automated consumer
suite are preserved in [consumer-commands.log](consumer-commands.log).

During the negative sweep, the undocumented-public-function mutation initially
survived because Cargo reused rustdoc output for files extracted with normalized
tar timestamps. Refreshing extracted file timestamps fixed the test harness;
the complete consumer suite and negative sweep were then rerun. This changes
only scratch file mtimes, never published contents.

## Mutation proof

`python3 scripts/mutation_check.py --report docs/consumer-dx/boundary-mutations.json`
passed: **25 behavioral mutations killed and 11 static probes rejected** in
630.871 seconds. All focused baselines passed. The existing runner
requires the named test to report failure; compilation failures do not count
as behavioral kills. Raw results: [boundary-mutations.json](boundary-mutations.json).

The consumer runner builds and tests an isolated source copy, checks every
positive baseline first, requires exactly one focused failure with the expected
diagnostic, and restores original bytes in `finally`. Setup/package errors,
unrelated errors, missing tests and survivors fail the sweep. For doctest, type
and rustdoc lint mutations, the expected compilation diagnostic is the tested
contract. CLI exit/shape mutations are N/A because the SDK has no CLI.

`python3 scripts/consumer_mutation_check.py --report docs/consumer-dx/mutations.json`
passed: **23/23 consumer mutations killed** in 183.339 seconds.
All five focused baselines passed. Each mutation below produced its expected
failure; original source bytes were restored on the isolated copy. Raw diagnostics
and timings: [mutations.json](mutations.json).

| Mutation | Guard location | Expected failure (observed) | Result |
| --- | --- | --- | --- |
| stray-artifact-file | `scripts/test_consumer.py:93` | unexpected package files: ['src/stray.txt'] | killed |
| revert-package-allowlist | `scripts/test_consumer.py:93` | unexpected package files: ['examples/chat.rs' | killed |
| root-readme-compile | `scripts/test_consumer.py:110` | missing_example | killed |
| shipped-readme-compile | `scripts/test_consumer.py:110` | missing_example | killed |
| new-guide-compile | `scripts/test_consumer.py:110` | mismatched types | killed |
| ignored-readme-example | `scripts/test_consumer.py:110` | example must compile | killed |
| readme-doctest-wiring | `scripts/test_consumer.py:110` | 0 passed | killed |
| missing-public-docs | `scripts/test_consumer.py:105` | missing documentation for a function | killed |
| broken-public-link | `scripts/test_consumer.py:105` | unresolved link to NoSuchConsumerType | killed |
| consumer-editor-type | `scripts/test_consumer.py:137` | mismatched types | killed |
| consumer-wire-result | `scripts/test_consumer.py:137` | left: "Wrong" | killed |
| packaged-license | `scripts/test_consumer.py:97` | AssertionError | killed |
| metadata-description | `scripts/test_consumer.py:97` | missing package metadata: description | killed |
| metadata-license | `scripts/test_consumer.py:97` | missing package metadata: license | killed |
| metadata-repository | `scripts/test_consumer.py:97` | missing package metadata: repository | killed |
| metadata-url-repository | `scripts/test_consumer.py:97` | Regex didn't match | killed |
| metadata-homepage | `scripts/test_consumer.py:97` | missing package metadata: homepage | killed |
| metadata-url-homepage | `scripts/test_consumer.py:97` | Regex didn't match | killed |
| metadata-documentation | `scripts/test_consumer.py:97` | missing package metadata: documentation | killed |
| metadata-url-documentation | `scripts/test_consumer.py:97` | Regex didn't match | killed |
| metadata-rust-version | `scripts/test_consumer.py:97` | missing package metadata: rust-version | killed |
| metadata-keywords | `scripts/test_consumer.py:97` | missing package metadata: keywords | killed |
| metadata-categories | `scripts/test_consumer.py:97` | missing package metadata: categories | killed |

Additional evidence files: `docs/consumer-dx/consumer-commands.log:1`,
`docs/consumer-dx/conformance.json:1`, `docs/consumer-dx/boundary-mutations.json:1`,
and `docs/consumer-dx/mutations.json:1`. No source mutations remain in the worktree.
