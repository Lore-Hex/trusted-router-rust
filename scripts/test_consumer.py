#!/usr/bin/env python3
"""Consumer contract tests. Run with Python 3.11+ and Cargo on PATH.

Builds a .crate, inspects its actual tar members, extracts it outside the repo,
then compiles documentation and runs a typed consumer against a std fake server.
Only Python's standard library and existing Rust dependencies are used.
"""
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd, env):
    print(f"cd {shlex.quote(str(cwd))} && {shlex.join(command)}", flush=True)
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=600)
    if result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {shlex.join(command)}\n{result.stdout}")
    return result.stdout


def assert_archive(files):
    """Allow library sources, the required build script, docs and Cargo metadata."""
    required = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "LICENSE", "README.md", "build.rs", "src/lib.rs"}
    allowed = required | {".cargo_vcs_info.json"}
    assert required <= files, f"missing package files: {required - files}"
    forbidden = {"tests", "fixtures", "scripts", "examples", ".github", "scratch"}
    unexpected = {
        name for name in files
        if name not in allowed and not (
            name.startswith("src/") and name.endswith(".rs")
            and not (set(PurePosixPath(name).parts) & forbidden)
        )
    }
    assert not unexpected, f"unexpected package files: {sorted(unexpected)}"


class ConsumerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="trusted-router-consumer-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name).resolve()
        assert not cls.work.is_relative_to(ROOT), "consumer must be outside the repository"
        cls.env = dict(os.environ)
        cls.env["CARGO_TARGET_DIR"] = str(Path(os.environ.get(
            "CONSUMER_TARGET_DIR", ROOT / "target/consumer-dx")).resolve())
        cls.env["CARGO_TERM_COLOR"] = "never"
        listing = run(["cargo", "package", "--list", "-p", "trusted-router", "--locked", "--allow-dirty"], ROOT, cls.env)
        cls.listing = set(listing.strip().splitlines())
        run(["cargo", "package", "-p", "trusted-router", "--locked", "--allow-dirty", "--no-verify"], ROOT, cls.env)
        package = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]
        name = f"trusted-router-{package['version']}"
        archive = Path(cls.env["CARGO_TARGET_DIR"]) / "package" / f"{name}.crate"
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            cls.files = {member.name.removeprefix(name + "/") for member in members}
            # Never let an unexpected archive member escape the scratch directory.
            for member in members:
                destination = (cls.work / member.name).resolve()
                assert destination.is_relative_to(cls.work) and member.isfile(), member.name
            tar.extractall(cls.work, members=members)
        cls.artifact = cls.work / name
        # Cargo normalizes tar timestamps. A shared target directory can otherwise
        # reuse rustdoc/compiler output from a different extracted archive.
        for source in cls.artifact.rglob("*"):
            if source.is_file():
                source.touch()
        cls.metadata = tomllib.loads((cls.artifact / "Cargo.toml").read_text())
        cls.consumer = cls.work / "consumer"
        (cls.consumer / "src").mkdir(parents=True)
        dependencies = cls.metadata["dependencies"]
        (cls.consumer / "Cargo.toml").write_text(
            '[package]\nname = "consumer-smoke"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\ntrusted-router = { path = ' + json.dumps(cls.artifact.as_posix()) + ' }\n'
            'tokio = { version = ' + json.dumps(dependencies["tokio"]["version"]) + ', features = ["macros", "rt-multi-thread"] }\n'
            'futures-util = ' + json.dumps(dependencies["futures-util"]["version"]) + '\n')
        shutil.copy2(ROOT / "scripts/consumer_smoke.rs", cls.consumer / "src/main.rs")
        # Reuse the checked-in dependency resolution, including MSRV pins.
        shutil.copy2(cls.artifact / "Cargo.lock", cls.consumer / "Cargo.lock")

    def test_archive(self):
        self.assertEqual(self.files, self.listing, "built archive differs from cargo package --list")
        assert_archive(self.files)

    def test_metadata(self):
        package = self.metadata["package"]
        for field in ("description", "license", "repository", "homepage", "documentation", "rust-version", "keywords", "categories"):
            self.assertTrue(package.get(field), f"missing package metadata: {field}")
        for field in ("repository", "homepage", "documentation"):
            self.assertRegex(package[field], r"^https://[^/]+", field)
        self.assertEqual((self.artifact / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())

    def test_public_docs(self):
        # These crate-level denies work without relying on CI's RUSTDOCFLAGS.
        run(["cargo", "doc", "--no-deps", "--all-features"], self.artifact, self.env)
        self.assertTrue((Path(self.env["CARGO_TARGET_DIR"]) / "doc/trusted_router/struct.Client.html").is_file())

    def test_examples(self):
        # The shipped README is also the public crate documentation.
        output = run(["cargo", "test", "--doc", "--all-features"], self.artifact, self.env)
        self.assertRegex(output, r"test result: ok\. [1-9]\d* passed")
        # Discover every Markdown guide so new docs automatically get checked.
        guides = sorted({*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md"),
                         ROOT / "crates/trusted-router/README.md"})
        modules = []
        count = 0
        for index, guide in enumerate(guides):
            markdown = guide.read_text()
            fences = re.findall(r"^```([^\n]*)\n(.*?)^```\s*$", markdown, re.M | re.S)
            for language, _ in fences:
                if language.startswith("rust") or not language:
                    self.assertNotRegex(language, r"ignore|compile_fail", f"example must compile: {guide}")
                    count += 1
                else:
                    self.assertIn(language, ("sh", "text", "json", "console"), f"unhandled example language: {guide}")
            copied = self.consumer / f"guide_{index}.md"
            copied.write_text(markdown)
            modules.append(f'#[doc = include_str!("../guide_{index}.md")]\npub mod guide_{index} {{}}\n')
        self.assertGreater(count, 0, "no Rust documentation examples discovered")
        (self.consumer / "src/lib.rs").write_text("".join(modules))
        output = run(["cargo", "test", "--doc"], self.consumer, self.env)
        self.assertRegex(output, rf"test result: ok\. {count} passed; 0 failed; 0 ignored", output)
        print(f"compiled/executed {count} Markdown examples; shell blocks are CI/install recipes", flush=True)

    def test_consumer(self):
        output = run(["cargo", "run", "--quiet"], self.consumer, self.env)
        self.assertIn("packaged consumer: GET /v1/models -> Fake", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
