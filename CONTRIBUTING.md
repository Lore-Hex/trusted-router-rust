# Contributing

1. Create a focused branch.
2. Keep prompt traffic on the inference plane and management traffic on the
   control plane.
3. Do not add request-body, response-body, API-key, or BYOK logging.
4. Add deterministic tests for every protocol or retry change.
5. Run the complete local gate:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo package -p trusted-router
```

Changes to `trusted_router.h` must preserve existing ownership and symbol
semantics or explicitly document a major ABI version.

Boundary changes must keep `docs/boundary-audit.md` and the focused mutation
catalog in `scripts/mutations.json` current. Run `python3 scripts/test_mutation_check.py`
and `python3 scripts/mutation_check.py` after the normal workspace checks. The
runner builds an isolated source copy, requires each focused test to pass first,
and fails for stale patterns, compile failures, missing tests, or surviving
mutations. It restores original bytes in `finally` and keeps its build cache in
`target/mutation-check`. Both LF and CRLF checkouts are supported.

Production panic/indexing exceptions must name a proved invariant in an inline
lint `reason`. Test-only exceptions are scoped to test modules or integration-test
crates. CI also checks that each configured boundary lint rejects a negative probe.
