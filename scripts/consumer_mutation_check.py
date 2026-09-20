#!/usr/bin/env python3
"""Prove consumer guards fail on isolated mutations, with diagnostic matching."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

import test_consumer

ROOT = Path(__file__).resolve().parents[1]


def focused(name):
    result = unittest.TestResult()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        unittest.TestSuite([test_consumer.ConsumerContract(name)]).run(result)
    diagnostics = output.getvalue() + "\n".join(detail for _, detail in result.errors + result.failures)
    return result, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    results = []
    manifest = "crates/trusted-router/Cargo.toml"
    lib = "crates/trusted-router/src/lib.rs"
    mutations = [
        ("stray-artifact-file", "crates/trusted-router/src/stray.txt", None, "scratch data\n", "test_archive", "unexpected package files: ['src/stray.txt']"),
        ("revert-package-allowlist", manifest, 'include = ["src/**", "build.rs", "LICENSE", "README.md"]', 'exclude = ["tests/**"]', "test_archive", "unexpected package files: ['examples/chat.rs'"),
        ("root-readme-compile", "README.md", "ChatRequest::user(FAST_MODEL, \"Reply with PONG\")", "ChatRequest::missing_example(FAST_MODEL, \"Reply with PONG\")", "test_examples", "missing_example"),
        ("shipped-readme-compile", "crates/trusted-router/README.md", "ChatRequest::user", "ChatRequest::missing_example", "test_examples", "missing_example"),
        ("new-guide-compile", "docs/consumer-probe.md", None, "```rust\nlet _: u8 = \"broken\";\n```\n", "test_examples", "mismatched types"),
        ("ignored-readme-example", "README.md", "```rust\n", "```rust,ignore\n", "test_examples", "example must compile"),
        ("readme-doctest-wiring", lib, '#![doc = include_str!("../README.md")]', "", "test_examples", "0 passed"),
        ("missing-public-docs", lib, None, "\npub fn undocumented_consumer_probe() {}\n", "test_public_docs", "missing documentation for a function"),
        ("broken-public-link", lib, None, "\n/// See [`NoSuchConsumerType`].\npub fn documented_consumer_probe() {}\n", "test_public_docs", "unresolved link to `NoSuchConsumerType`"),
        ("consumer-editor-type", "scripts/consumer_smoke.rs", "let name: &str = &model.name;", "let name: u64 = &model.name;", "test_consumer", "mismatched types"),
        ("consumer-wire-result", "scripts/consumer_smoke.rs", '"name":"Fake"', '"name":"Wrong"', "test_consumer", 'left: "Wrong"'),
        ("packaged-license", "crates/trusted-router/LICENSE", None, "\nincorrect license text\n", "test_metadata", "AssertionError"),
    ]
    package_lines = (ROOT / manifest).read_text().splitlines(keepends=True)
    for field in ("description", "license", "repository", "homepage", "documentation", "rust-version", "keywords", "categories"):
        before, = [line for line in package_lines if line.startswith((field + " =", field + ".workspace"))]
        mutations.append(("metadata-" + field, manifest, before, "", "test_metadata", "missing package metadata: " + field))
        if field in ("repository", "homepage", "documentation"):
            mutations.append(("metadata-url-" + field, manifest, before, field + ' = "not-a-url"\n', "test_metadata", "Regex didn't match"))
    with tempfile.TemporaryDirectory(prefix="trusted-router-consumer-mutations-") as temporary:
        work = Path(temporary)
        for path in ROOT.glob("*.md"):
            shutil.copy2(path, work / path.name)
        for name in ("Cargo.toml", "Cargo.lock", "LICENSE", "clippy.toml", "rustfmt.toml"):
            shutil.copy2(ROOT / name, work / name)
        for name in ("crates", "scripts", "docs", "tests"):
            shutil.copytree(ROOT / name, work / name)
        test_consumer.ROOT = work
        os.environ["CONSUMER_TARGET_DIR"] = str(ROOT / "target/consumer-mutations")
        # Avoid stale artifacts from an earlier isolated root with copy2 mtimes.
        for source in (work / "crates").rglob("*.rs"):
            source.touch()
        for name in sorted({mutation[4] for mutation in mutations}):
            result, output = focused(name)
            if not result.wasSuccessful() or result.testsRun != 1:
                raise RuntimeError(f"baseline {name} failed:\n{output}")
            print(f"baseline passed: {name}", flush=True)
        for name, file, before, after, test, expected in mutations:
            path = work / file
            original = path.read_bytes() if path.exists() else None
            start = time.monotonic()
            try:
                if before is None:
                    path.write_bytes((original or b"") + after.encode())
                else:
                    before_bytes, after_bytes = before.encode(), after.encode()
                    if b"\r\n" in original:
                        before_bytes = before_bytes.replace(b"\n", b"\r\n")
                        after_bytes = after_bytes.replace(b"\n", b"\r\n")
                    if original.count(before_bytes) != 1:
                        raise RuntimeError(f"stale/nonunique mutation: {name}")
                    path.write_bytes(original.replace(before_bytes, after_bytes, 1))
                result, output = focused(test)
                # Setup/packaging failures and unrelated diagnostics are not kills.
                if result.testsRun != 1 or result.errors or len(result.failures) != 1 or expected not in output:
                    raise RuntimeError(f"mutation {name} did not fail its guard ({expected}):\n{output}")
                record = {"name": name, "file": file, "test": test, "diagnostic": expected,
                          "result": "killed", "seconds": round(time.monotonic() - start, 3)}
                results.append(record)
                print(json.dumps(record), flush=True)
            finally:
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(original)
    report = {"wall_seconds": round(time.monotonic() - started, 3), "results": results}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(results)} consumer mutations killed", flush=True)


if __name__ == "__main__":
    main()
