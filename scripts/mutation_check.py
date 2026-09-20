#!/usr/bin/env python3
"""Compile and kill recorded boundary mutations on an isolated source copy.

Only Python's standard library is needed. Never modifies the user's source files;
original bytes on the copy are restored in finally, including on interruption.
A compile error, missing/filtered test, stale pattern, or surviving mutant fails.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(command, work, env):
    result = subprocess.run(command, cwd=work, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace", timeout=600)
    return result.returncode, result.stdout


def mutation_bytes(original, mutation):
    """Match the recorded pattern in the checkout's LF or CRLF convention."""
    before = mutation["before"].encode()
    after = mutation["after"].encode()
    if b"\r\n" in original:
        before = before.replace(b"\n", b"\r\n")
        after = after.replace(b"\n", b"\r\n")
    if original.count(before) != 1:
        raise RuntimeError(f"stale/nonunique before pattern: {mutation['name']}")
    if before == after:
        raise RuntimeError(f"ineffective mutation: {mutation['name']}")
    return before, after


def test_command(name):
    return ["cargo", "test", "-p", "trusted-router", "--all-features", name, "--", "--exact"]


def assert_test(output, name, outcome):
    # A cargo compile failure or zero selected tests is not a mutation kill.
    if not re.search(r"^test " + re.escape(name) + r" \.\.\. " + outcome + r"$", output, re.M):
        raise RuntimeError(f"focused test {name!r} did not report {outcome}:\n{output}")


def static_probes(work, env, results):
    probes = [
        ("unwrap_used", "fn boundary_probe(v: Option<u8>) -> u8 { v.unwrap() }"),
        ("expect_used", 'fn boundary_probe(v: Option<u8>) -> u8 { v.expect("wire value") }'),
        ("panic", 'fn boundary_probe() { panic!("wire value") }'),
        ("unreachable", 'fn boundary_probe() { unreachable!("wire value") }'),
        ("todo", "fn boundary_probe() { todo!() }"),
        ("unimplemented", "fn boundary_probe() { unimplemented!() }"),
        ("indexing_slicing", "fn boundary_probe(v: &[u8], i: usize) -> u8 { v[i] }"),
        ("unwrap_in_result", 'fn boundary_probe(v: std::result::Result<u8, &str>) -> std::result::Result<u8, &str> { Ok(v.unwrap()) }'),
        ("as_conversions", "fn boundary_probe(v: u64) -> u8 { v as u8 }"),
        ("unwrap_used", 'fn boundary_probe(v: &str) -> http::HeaderValue { http::HeaderValue::from_str(v).unwrap() }'),
        ("unwrap_used", "fn boundary_probe(v: &serde_json::Value) -> &str { v.as_str().unwrap() }"),
    ]
    path = work / "crates/trusted-router/src/lib.rs"
    original = path.read_bytes()
    for index, (lint, source) in enumerate(probes, 1):
        start = time.monotonic()
        try:
            path.write_bytes(original + ('\n#[allow(dead_code, reason = "Static gate negative probe")]\n' + source + '\n').encode())
            code, output = run(["cargo", "clippy", "-p", "trusted-router", "--lib", "--all-features",
                                "--message-format=json", "--", "-D", "warnings"], work, env)
            diagnostics = []
            for line in output.splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                message = item.get("message", {})
                if isinstance(message, dict) and message.get("level") == "error":
                    diagnostics.append((message.get("code") or {}).get("code"))
            if code == 0 or f"clippy::{lint}" not in diagnostics:
                raise RuntimeError(f"static probe {index}/{lint} missed its lint:\n{output}")
            result = {"name": f"static-{index}-{lint}", "result": "rejected", "seconds": round(time.monotonic()-start, 3)}
            results.append(result)
            print(json.dumps(result), flush=True)
        finally:
            path.write_bytes(original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write a JSON result report")
    args = parser.parse_args()
    started = time.monotonic()
    results = []
    mutations = json.loads((ROOT / "scripts/mutations.json").read_text())
    # Validate every recorded pattern before spending time on any compilation.
    for mutation in mutations:
        source = (ROOT / mutation["file"]).read_bytes()
        mutation_bytes(source, mutation)
    env = dict(os.environ)
    # A dedicated cache keeps this isolated copy independent of normal cargo work.
    env["CARGO_TARGET_DIR"] = str(ROOT / "target/mutation-check")
    env["CARGO_TERM_COLOR"] = "never"
    with tempfile.TemporaryDirectory(prefix="trusted-router-mutations-") as temporary:
        work = Path(temporary)
        for name in ["Cargo.toml", "Cargo.lock", "clippy.toml", "rustfmt.toml", "LICENSE"]:
            shutil.copy2(ROOT / name, work / name)
        for name in ["crates", "tests"]:
            shutil.copytree(ROOT / name, work / name)
        # copy2 preserves old mtimes; the shared cargo cache may otherwise reuse
        # an artifact from a previous temporary root. Force baseline recompilation.
        for source in (work / "crates").rglob("*.rs"):
            source.touch()
        for name in sorted({mutation["test"] for mutation in mutations}):
            code, output = run(test_command(name), work, env)
            if code:
                raise RuntimeError(f"baseline failed: {name}\n{output}")
            assert_test(output, name, "ok")
            print(f"baseline passed: {name}", flush=True)
        for mutation in mutations:
            path = work / mutation["file"]
            original = path.read_bytes()
            before, after = mutation_bytes(original, mutation)
            start = time.monotonic()
            try:
                path.write_bytes(original.replace(before, after, 1))
                code, output = run(test_command(mutation["test"]), work, env)
                if code == 0:
                    raise RuntimeError(f"SURVIVED: {mutation['name']}\n{output}")
                assert_test(output, mutation["test"], "FAILED")
                result = {"name": mutation["name"], "test": mutation["test"], "result": "killed",
                          "seconds": round(time.monotonic()-start, 3)}
                results.append(result)
                print(json.dumps(result), flush=True)
            finally:
                path.write_bytes(original)
        static_probes(work, env, results)
    report = {"wall_seconds": round(time.monotonic()-started, 3), "results": results}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(mutations)} mutations killed; 11 static probes rejected; wall time {report['wall_seconds']}s")


if __name__ == "__main__":
    main()
