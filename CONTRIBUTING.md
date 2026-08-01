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
