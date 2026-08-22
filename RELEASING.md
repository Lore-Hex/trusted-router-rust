# Releasing

Releases are **tag-triggered**. Pushing an annotated tag `vX.Y.Z` runs
`.github/workflows/release.yml`, which publishes the `trusted-router` crate to
crates.io from the protected `crates-io` environment and attaches the FFI
artifacts to a GitHub Release. Nobody runs `cargo publish` by hand: a manual
publish followed by the tag makes the workflow's own publish fail with
`crate version already uploaded`.

Only `trusted-router` is published to crates.io. `trusted-router-ffi` is
`publish = false`; it ships as the C library and header attached to the GitHub
Release.

## 1. Prepare the release commit

1. Bump the single `[workspace.package] version` in the root `Cargo.toml` — both
   crates inherit it via `version.workspace = true` — then refresh the lockfile
   so `Cargo.lock` carries the new version. The `User-Agent` and
   `trusted_router::VERSION` derive from `CARGO_PKG_VERSION`, so the parity
   tests fail until the manifest and lockfile agree.
2. Move the `Unreleased` entries in `CHANGELOG.md` under `## X.Y.Z — YYYY-MM-DD`.
   Call out anything visible on the wire (for example a `User-Agent` change).
3. Run the complete local gate from `CONTRIBUTING.md`:

   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   cargo doc --workspace --all-features --no-deps
   cargo package -p trusted-router --locked
   ```

4. Confirm the package contents. `cargo package -p trusted-router --locked --list`
   must show no credentials, private fixtures, or local configuration — only
   source, the license, and the manifest. `--locked` is what the workflow uses;
   if it fails locally it will fail in the workflow.
5. Open the release PR (`release/X.Y.Z`). It must be green on every CI job —
   the three-OS test matrix, `msrv`, `package`, `audit`, and the SDK conformance
   harness — before it merges. Merge it to `main`.

## 2. Tag the merge commit

Tag the **merge commit on `main`**, never the PR branch head, with an annotated
tag in the `vX.Y.Z` form the workflow matches (`tags: ["v*"]`):

```sh
git fetch origin main
git tag -a vX.Y.Z <merge-commit-sha> -m "TrustedRouter Rust and C SDK X.Y.Z"
git push origin vX.Y.Z
```

The tag push triggers the `Release` workflow:

- `crates-io` — checks out the tag and runs `cargo publish -p trusted-router --locked`
  with `CARGO_REGISTRY_TOKEN` from the `crates-io` environment. If the secret is
  not configured the job **skips publication with a notice** and still
  succeeds, so a green workflow is not proof of a crates.io release: check the
  job log, then `https://crates.io/crates/trusted-router`.
- `ffi` — builds `trusted-router-ffi` in release mode on Linux x86_64, macOS
  (universal source), and Windows x86_64, and uploads the library plus
  `crates/trusted-router-ffi/include/trusted_router.h` for each.
- `github-release` — packages each platform artifact as a `.tar.gz`, writes
  `SHA256SUMS`, and creates the GitHub Release for the tag with generated notes
  and those files attached.

## 3. Verify

- crates.io lists `trusted-router` at the new version.
- The GitHub Release for `vX.Y.Z` exists with three platform archives and
  `SHA256SUMS`.
- A fresh `cargo add trusted-router@X.Y.Z` in a scratch project resolves.

## If publication did not happen

- **Secret missing** (the `crates-io` job reported the notice): add
  `CARGO_REGISTRY_TOKEN` to the `crates-io` environment, then **re-run that
  tag's `Release` workflow run** from the Actions tab. Do not push a new tag
  for the same version and do not publish by hand.
- **Publish failed** for another reason: fix forward with a new patch version.
  A crates.io version can be yanked but never replaced, and a tag that has been
  pushed must not be moved.

## Rules that do not change

- Never publish from a dirty tree; the workflow publishes exactly the tagged
  commit, and your local gate must have run on that same tree.
- Do not bypass the attestation and credential-boundary tests to get a release
  out. If they fail, the release waits.
- `workflow_dispatch` exists for diagnosing the workflow on a branch; it does
  not create a GitHub Release (that job requires a tag ref) and must not be used
  to publish.
