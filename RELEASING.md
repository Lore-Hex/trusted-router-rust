# Releasing

1. Update `CHANGELOG.md` and the workspace version.
2. Run the full gate in `CONTRIBUTING.md` on Linux, macOS, and Windows CI.
3. Confirm `cargo package -p trusted-router` includes no credentials or private
   fixtures.
4. Publish with `cargo publish -p trusted-router` using the protected crates.io
   environment.
5. Push tag `vX.Y.Z`. The release workflow builds C libraries and headers for
   supported desktop targets and attaches checksums.

Never publish from a dirty tree or bypass the attestation and credential-boundary
tests.
