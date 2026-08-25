# Releasing

1. Update `CHANGELOG.md` and the workspace version. `[workspace.package]
   version` in the root `Cargo.toml` is the only place to change: everything
   that reports a version derives it from `CARGO_PKG_VERSION`, and
   `trusted-router-ffi` inherits it.
2. Run the full gate in `CONTRIBUTING.md` on Linux, macOS, and Windows CI.
3. Merge, then push tag `vX.Y.Z`. The release workflow is the ONLY publish
   path: it publishes to crates.io from the protected `crates-io` environment,
   and builds the C libraries and headers with checksums. Do not run
   `cargo publish` by hand — the tag-triggered job would then attempt the same
   version and fail, because a crates.io version can never be re-uploaded.
4. Confirm the new version on crates.io itself. A green release run is not
   sufficient evidence on its own, and historically was not: `v0.1.0` and
   `v0.2.0` both ran green while publishing nothing, because the registry
   token was absent and the job skipped itself. That path now fails loudly.

The packaged archive must contain no credentials or private fixtures. CI
enforces this on every pull request, rather than leaving it to this checklist.

Never publish from a dirty tree or bypass the attestation and
credential-boundary tests.
