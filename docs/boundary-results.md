# Boundary audit results

Implementation stays in the worktree: no commit, public API type changes, or runtime dependencies. The full original-site inventory is in [boundary-audit.md](boundary-audit.md); it was written before source edits and later annotated with completed verdicts.

## Findings and changes

| Area | Result |
| --- | --- |
| Panics/indexing | Classified all 187 original unwrap/expect/panic-macro lines: 183 embedded-test sites and four proved production expect invariants. Bounded production indexing is narrowly allowed with proofs; the chat example now uses first(). |
| Auth wire | Optional exchange identity/data validate record shapes; known identity strings validate without closing the record. Userinfo requires data and accepts legacy null sub. Exchange still accepts missing data. All producer fields and unknown nested metadata survive. |
| Attestation | Wrong-typed image claims, exp, iss and nonce elements return Attestation errors. Effective pins must be nonempty; an empty pin cannot match a missing image claim. |
| Headers | Each public string-map layer becomes HeaderMap; repeated case variants survive within a layer and per-call names replace defaults case-insensitively. An empty workspace override removes custom workspace headers. |
| SSE | Consumed event/error/type/status and chat text/container shapes return Serialization errors. Absent/null text remains optional. Unknown event metadata remains untouched. |
| Gates | Existing Clippy CI step precedes tests. Python mutation and gate-self-tests run immediately after cargo test. |

## Static rule set and limits

`Cargo.toml` denies `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented`, `indexing_slicing`, and `unwrap_in_result`; `as_conversions` warns and therefore fails CI under `-D warnings`. `allow_attributes_without_reason` is also denied. Existing all/pedantic rules and their six style/API exceptions remain unchanged (module_name_repetitions, must_use_candidate, return_self_not_must_use, missing_errors_doc, missing_panics_doc, needless_pass_by_value; see Cargo.toml for the exact table).

`clippy.toml` permits unwrap/expect in tests. Integration-test crates additionally permit helper unwrap/expect, panic, indexing, unwrap_in_result, and casts; embedded test-module exceptions are scoped under cfg(test). Production exceptions are listed individually below.

Clippy does not infer producer guarantees, distinguish pass-through metadata from consumed fields, prove HeaderMap merge semantics, detect case-sensitive credential stripping, or recognize semantic laundering through defaults. No claim is made that it does: those cases are covered by the explicit site review, literal fixtures and 25 behavioral mutations. No requested Clippy rule is left off. There is no deny_unknown_fields attribute, production header parse unwrap, ignored serde_json parse result, or lossy wire-integer cast. The remaining public BTreeMap header fields are API-compatible staging containers, not lookup/merge engines; repeated identical spelling retains the existing builder/map replacement semantics.

## Verification

- Toolchain: Homebrew cargo 1.97.1 with `/opt/homebrew/bin` first in PATH.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo test --workspace --all-features`: 163 passed; three pre-existing live smoke tests remain ignored.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`: passed.
- `python3 scripts/test_mutation_check.py`: five passed; stale patterns, survivors, compile failures and missing tests fail, and restoration preserves CRLF bytes.
- Conformance command: `tr-conformance --sdk rust --sdk-root rust=$PWD`: 25 passed, 0 failed, 0 skipped. Loopback binding worked; not sandbox-blocked.
- `git diff --check`: passed.

## Shared fixture

`crates/trusted-router/tests/fixtures/auth-wire-fixtures.json` was copied verbatim, verified with byte comparison, and has SHA-256:
`ba492afe81f7616bca062ab7ed35f70d42042e6f6f60794ac9e2a599574df1d2`

The `shared_auth_wire_fixtures` HTTP test exercises all six accepts and twelve rejects via exchange_oauth_key/user_info, compares consumed fields and every producer field, and checks typed Serialization errors. It separately pins unknown userinfo metadata preservation.

## Mutation proof

Wall time: **327.081 seconds**, including baseline checks, compilation and static probes. Each behavioral mutation compiles and its named focused test reports FAILED; compile errors and zero selected tests are not kills. Baselines all pass. Every mutation runs on an isolated source copy, with original bytes restored from memory in finally; LF/CRLF checkouts are supported. No git checkout is used.

Raw results: [mutation-results.json](mutation-results.json). Recorded before/after patterns: [mutations.json](../scripts/mutations.json). Stale or nonunique patterns fail before compilation. The fixture-overconstraint mutation specifically makes exchange data required.

| Mutation / fixed guard | Current source | Focused test | Result | Seconds |
| --- | --- | --- | --- | --- |
| exchange-record-shape | `crates/trusted-router/src/oauth.rs:108` | `shared_auth_wire_fixtures` | killed | 10.999 |
| exchange-identity-validation | `crates/trusted-router/src/oauth.rs:119` | `shared_auth_wire_fixtures` | killed | 10.774 |
| userinfo-record-shape | `crates/trusted-router/src/oauth.rs:133` | `shared_auth_wire_fixtures` | killed | 12.859 |
| identity-known-string-fields | `crates/trusted-router/src/oauth.rs:136` | `shared_auth_wire_fixtures` | killed | 13.263 |
| userinfo-requires-data | `crates/trusted-router/src/types.rs:686` | `shared_auth_wire_fixtures` | killed | 10.383 |
| fixture-exchange-must-not-require-data | `crates/trusted-router/src/oauth.rs:95` | `shared_auth_wire_fixtures` | killed | 11.668 |
| attestation-image_digest | `crates/trusted-router/src/attestation.rs:396` | `attestation::tests::malformed_attestation_claims_are_not_defaulted` | killed | 7.831 |
| attestation-image_reference | `crates/trusted-router/src/attestation.rs:397` | `attestation::tests::malformed_attestation_claims_are_not_defaulted` | killed | 7.933 |
| attestation-exp-type | `crates/trusted-router/src/attestation.rs:401` | `attestation::tests::malformed_attestation_claims_are_not_defaulted` | killed | 8.193 |
| attestation-iss-type | `crates/trusted-router/src/attestation.rs:405` | `attestation::tests::malformed_attestation_claims_are_not_defaulted` | killed | 9.286 |
| attestation-nonce-elements | `crates/trusted-router/src/attestation.rs:556` | `attestation::tests::malformed_attestation_claims_are_not_defaulted` | killed | 9.233 |
| attestation-nonce-shape | `crates/trusted-router/src/attestation.rs:565` | `attestation::tests::malformed_attestation_claims_are_not_defaulted` | killed | 9.916 |
| header-repeated-values | `crates/trusted-router/src/transport/headers.rs:37` | `header_layers_preserve_values_and_suppress_workspace` | killed | 11.128 |
| header-case-insensitive-layer-override | `crates/trusted-router/src/transport/headers.rs:40` | `header_layers_preserve_values_and_suppress_workspace` | killed | 18.191 |
| header-empty-workspace-suppression | `crates/trusted-router/src/transport/headers.rs:60` | `header_layers_preserve_values_and_suppress_workspace` | killed | 13.649 |
| sse-object-shape | `crates/trusted-router/src/sse.rs:464` | `sse_consumed_fields_reject_wrong_shapes` | killed | 10.29 |
| sse-event-type | `crates/trusted-router/src/sse.rs:469` | `sse_consumed_fields_reject_wrong_shapes` | killed | 9.2 |
| sse-error-shape | `crates/trusted-router/src/sse.rs:473` | `sse_consumed_fields_reject_wrong_shapes` | killed | 10.353 |
| sse-error-status-type | `crates/trusted-router/src/sse.rs:484` | `sse_consumed_fields_reject_wrong_shapes` | killed | 11.217 |
| text-choices-shape | `crates/trusted-router/src/sse.rs:499` | `chat_text_rejects_malformed_consumed_fields` | killed | 10.985 |
| text-choice-shape | `crates/trusted-router/src/sse.rs:505` | `chat_text_rejects_malformed_consumed_fields` | killed | 11.279 |
| text-delta-shape | `crates/trusted-router/src/sse.rs:511` | `chat_text_rejects_malformed_consumed_fields` | killed | 13.477 |
| text-content-type | `crates/trusted-router/src/sse.rs:517` | `chat_text_rejects_malformed_consumed_fields` | killed | 13.968 |
| attestation-nonempty-effective-pin | `crates/trusted-router/src/attestation.rs:53` | `release_whose_lists_hold_only_empty_strings_is_refused` | killed | 10.893 |
| attestation-empty-pin-missing-claim | `crates/trusted-router/src/attestation.rs:584` | `attestation::tests::empty_image_pin_cannot_match_a_missing_claim` | killed | 7.231 |

Static negative probes exercise all requested lint families, including caller HeaderValue parsing and JSON shape unwraps. Each must emit its intended Clippy error code, not merely any compiler error.

| Static probe | Result | Seconds |
| --- | --- | --- |
| static-1-unwrap_used | rejected | 3.209 |
| static-2-expect_used | rejected | 2.695 |
| static-3-panic | rejected | 2.698 |
| static-4-unreachable | rejected | 2.65 |
| static-5-todo | rejected | 2.677 |
| static-6-unimplemented | rejected | 2.702 |
| static-7-indexing_slicing | rejected | 2.897 |
| static-8-unwrap_in_result | rejected | 3.429 |
| static-9-as_conversions | rejected | 2.605 |
| static-10-unwrap_used | rejected | 3.111 |
| static-11-unwrap_used | rejected | 3.326 |

## Every inline suppression

| Site | Lints | Exact reason |
| --- | --- | --- |
| `crates/trusted-router/src/attestation.rs:359` | `clippy::too_many_lines` | Keep the ordered protocol checks together for review |
| `crates/trusted-router/src/attestation.rs:611` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/oauth.rs:320` | `clippy::indexing_slicing` | AsyncRead returns at most the supplied buffer length |
| `crates/trusted-router/src/receipts.rs:285` | `clippy::too_many_lines` | Keep the ordered protocol checks together for review |
| `crates/trusted-router/src/receipts.rs:539` | `clippy::expect_used, clippy::unwrap_in_result, clippy::indexing_slicing` | Receipt bytes were checked ASCII; split parts are checked to have length three before indexing |
| `crates/trusted-router/src/receipts.rs:694` | `clippy::expect_used, clippy::unwrap_in_result` | Host presence is checked before canonicalization |
| `crates/trusted-router/src/receipts.rs:1060` | `clippy::indexing_slicing` | Offset starts at zero and advances only to a delimiter end within this same stream |
| `crates/trusted-router/src/receipts.rs:1468` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/telemetry/reporter.rs:298` | `clippy::struct_excessive_bools` | Mirrors Python's orthogonal bounded reporter flags. |
| `crates/trusted-router/src/telemetry/reporter.rs:1168` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/telemetry/reporter.rs:1335` | `clippy::too_many_lines` | One ordered scenario pins all three fold fallbacks. |
| `crates/trusted-router/src/telemetry/reporter.rs:1596` | `clippy::too_many_lines` | One wire capture audits every nested schema boundary. |
| `crates/trusted-router/src/telemetry/wire.rs:449` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/telemetry.rs:164` | `dead_code` | Closed wire vocabulary; not every class is observable in reqwest. |
| `crates/trusted-router/src/telemetry.rs:224` | `dead_code` | Closed wire vocabulary; control calls are intentionally unrecorded. |
| `crates/trusted-router/src/telemetry.rs:271` | `dead_code` | Closed wire vocabulary; this SDK has no whole-call deadline. |
| `crates/trusted-router/src/telemetry.rs:876` | `clippy::struct_excessive_bools` | Independent contract facts, not one state machine. |
| `crates/trusted-router/src/telemetry.rs:1356` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/transport/engine.rs:178` | `clippy::indexing_slicing` | plane_urls returns a nonempty list and CandidateCursor never advances past its last index |
| `crates/trusted-router/src/transport/engine.rs:274` | `clippy::too_many_arguments` | Parameters mirror the transport or C ABI boundary |
| `crates/trusted-router/src/transport/engine.rs:430` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/transport/engine.rs:895` | `deprecated` | Test deliberately requests a TCP reset using set_linger |
| `crates/trusted-router/src/transport/policy.rs:193` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/transport/policy.rs:349` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/transport/routing.rs:163` | `clippy::indexing_slicing` | Loop bounds check index and both escape bytes before indexing |
| `crates/trusted-router/src/transport/routing.rs:189` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/src/types.rs:162` | `clippy::expect_used` | ChatMessage contains only JSON Values and string-keyed maps; its derived serializer is infallible |
| `crates/trusted-router/src/types.rs:705` | `clippy::expect_used` | ChatMessage contains only JSON Values and string-keyed maps; its derived serializer is infallible |
| `crates/trusted-router/tests/alias_failover.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/attestation_contract.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/attestation_contract.rs:10` | `missing_docs` | Integration test helpers are not public SDK API |
| `crates/trusted-router/tests/attestation_properties.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/client_contract.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/client_contract.rs:10` | `missing_docs` | Integration test helpers are not public SDK API |
| `crates/trusted-router/tests/deep_conformance.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/deep_conformance.rs:10` | `missing_docs` | Integration test helpers are not public SDK API |
| `crates/trusted-router/tests/live_smoke.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/oauth_contract.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/oauth_contract.rs:10` | `missing_docs` | Integration test helpers are not public SDK API |
| `crates/trusted-router/tests/receipt_live_smoke.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/telemetry_header.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/telemetry_header.rs:17` | `missing_docs` | Integration test helpers are not public SDK API |
| `crates/trusted-router/tests/tools_contract.rs:1` | `clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |
| `crates/trusted-router/tests/tools_contract.rs:10` | `missing_docs` | Integration test helpers are not public SDK API |
| `crates/trusted-router-ffi/src/lib.rs:106` | `clippy::too_many_arguments` | Parameters mirror the transport or C ABI boundary |
| `crates/trusted-router-ffi/src/lib.rs:361` | `clippy::indexing_slicing, clippy::panic, clippy::unwrap_in_result, clippy::as_conversions` | Test assertions and fixture construction deliberately fail loudly |

## Change locations

Every changed hunk is indexed below using current worktree line numbers. The mutation and suppression tables above explain the behavioral and lint changes; remaining changes are fixture, test, CI and development documentation plumbing.

| File | Changed hunk start lines |
| --- | --- |
| `.github/workflows/ci.yml` | `.github/workflows/ci.yml:31` |
| `.gitignore` | `.gitignore:10` |
| `CONTRIBUTING.md` | `CONTRIBUTING.md:20` |
| `Cargo.toml` | `Cargo.toml:57` |
| `crates/trusted-router-ffi/src/lib.rs` | `crates/trusted-router-ffi/src/lib.rs:106`, `crates/trusted-router-ffi/src/lib.rs:361` |
| `crates/trusted-router/examples/chat.rs` | `crates/trusted-router/examples/chat.rs:17` |
| `crates/trusted-router/src/attestation.rs` | `crates/trusted-router/src/attestation.rs:53`, `crates/trusted-router/src/attestation.rs:359`, `crates/trusted-router/src/attestation.rs:396`, `crates/trusted-router/src/attestation.rs:405`, `crates/trusted-router/src/attestation.rs:446`, `crates/trusted-router/src/attestation.rs:450`, `crates/trusted-router/src/attestation.rs:466`, `crates/trusted-router/src/attestation.rs:537`, `crates/trusted-router/src/attestation.rs:544`, `crates/trusted-router/src/attestation.rs:554`, `crates/trusted-router/src/attestation.rs:558`, `crates/trusted-router/src/attestation.rs:565`, `crates/trusted-router/src/attestation.rs:581`, `crates/trusted-router/src/attestation.rs:611`, `crates/trusted-router/src/attestation.rs:698` |
| `crates/trusted-router/src/client.rs` | `crates/trusted-router/src/client.rs:257` |
| `crates/trusted-router/src/oauth.rs` | `crates/trusted-router/src/oauth.rs:92`, `crates/trusted-router/src/oauth.rs:95`, `crates/trusted-router/src/oauth.rs:102`, `crates/trusted-router/src/oauth.rs:320` |
| `crates/trusted-router/src/receipts.rs` | `crates/trusted-router/src/receipts.rs:285`, `crates/trusted-router/src/receipts.rs:539`, `crates/trusted-router/src/receipts.rs:694`, `crates/trusted-router/src/receipts.rs:1060`, `crates/trusted-router/src/receipts.rs:1468` |
| `crates/trusted-router/src/sse.rs` | `crates/trusted-router/src/sse.rs:86`, `crates/trusted-router/src/sse.rs:464`, `crates/trusted-router/src/sse.rs:494` |
| `crates/trusted-router/src/telemetry.rs` | `crates/trusted-router/src/telemetry.rs:164`, `crates/trusted-router/src/telemetry.rs:224`, `crates/trusted-router/src/telemetry.rs:271`, `crates/trusted-router/src/telemetry.rs:876`, `crates/trusted-router/src/telemetry.rs:1236`, `crates/trusted-router/src/telemetry.rs:1356` |
| `crates/trusted-router/src/telemetry/reporter.rs` | `crates/trusted-router/src/telemetry/reporter.rs:298`, `crates/trusted-router/src/telemetry/reporter.rs:1168`, `crates/trusted-router/src/telemetry/reporter.rs:1335`, `crates/trusted-router/src/telemetry/reporter.rs:1596` |
| `crates/trusted-router/src/telemetry/wire.rs` | `crates/trusted-router/src/telemetry/wire.rs:449` |
| `crates/trusted-router/src/transport/engine.rs` | `crates/trusted-router/src/transport/engine.rs:178`, `crates/trusted-router/src/transport/engine.rs:274`, `crates/trusted-router/src/transport/engine.rs:430`, `crates/trusted-router/src/transport/engine.rs:895` |
| `crates/trusted-router/src/transport/headers.rs` | `crates/trusted-router/src/transport/headers.rs:23`, `crates/trusted-router/src/transport/headers.rs:39`, `crates/trusted-router/src/transport/headers.rs:59` |
| `crates/trusted-router/src/transport/policy.rs` | `crates/trusted-router/src/transport/policy.rs:193`, `crates/trusted-router/src/transport/policy.rs:349` |
| `crates/trusted-router/src/transport/routing.rs` | `crates/trusted-router/src/transport/routing.rs:163`, `crates/trusted-router/src/transport/routing.rs:189` |
| `crates/trusted-router/src/types.rs` | `crates/trusted-router/src/types.rs:162`, `crates/trusted-router/src/types.rs:685`, `crates/trusted-router/src/types.rs:705` |
| `crates/trusted-router/tests/alias_failover.rs` | `crates/trusted-router/tests/alias_failover.rs:1` |
| `crates/trusted-router/tests/attestation_contract.rs` | `crates/trusted-router/tests/attestation_contract.rs:1` |
| `crates/trusted-router/tests/attestation_properties.rs` | `crates/trusted-router/tests/attestation_properties.rs:1`, `crates/trusted-router/tests/attestation_properties.rs:139` |
| `crates/trusted-router/tests/client_contract.rs` | `crates/trusted-router/tests/client_contract.rs:1`, `crates/trusted-router/tests/client_contract.rs:330` |
| `crates/trusted-router/tests/deep_conformance.rs` | `crates/trusted-router/tests/deep_conformance.rs:1` |
| `crates/trusted-router/tests/live_smoke.rs` | `crates/trusted-router/tests/live_smoke.rs:1` |
| `crates/trusted-router/tests/oauth_contract.rs` | `crates/trusted-router/tests/oauth_contract.rs:1`, `crates/trusted-router/tests/oauth_contract.rs:79` |
| `crates/trusted-router/tests/receipt_live_smoke.rs` | `crates/trusted-router/tests/receipt_live_smoke.rs:1` |
| `crates/trusted-router/tests/telemetry_header.rs` | `crates/trusted-router/tests/telemetry_header.rs:1`, `crates/trusted-router/tests/telemetry_header.rs:17` |
| `crates/trusted-router/tests/tools_contract.rs` | `crates/trusted-router/tests/tools_contract.rs:1` |
| `.gitattributes` | `.gitattributes:1` (new file) |
| `clippy.toml` | `clippy.toml:1` (new file) |
| `crates/trusted-router/tests/fixtures/auth-wire-fixtures.json` | `crates/trusted-router/tests/fixtures/auth-wire-fixtures.json:1` (new file) |
| `scripts/mutation_check.py` | `scripts/mutation_check.py:1` (new file) |
| `scripts/mutations.json` | `scripts/mutations.json:1` (new file) |
| `scripts/test_mutation_check.py` | `scripts/test_mutation_check.py:1` (new file) |
| `docs/boundary-audit.md` | `docs/boundary-audit.md:1` (new file) |
| `docs/mutation-results.json` | `docs/mutation-results.json:1` (new file) |
| `docs/boundary-results.md` | `docs/boundary-results.md:1` (new file) |
