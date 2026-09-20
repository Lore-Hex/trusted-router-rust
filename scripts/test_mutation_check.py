#!/usr/bin/env python3
"""Negative checks for the gate itself, using simulated cargo outcomes."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import mutation_check as gate


class MutationGateTests(unittest.TestCase):
    def exercise(self, outcome, before="original\nvalue"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            work = Path(temporary) / "copy"
            work.mkdir()
            (root / "scripts").mkdir(parents=True)
            (root / "crates/trusted-router/src").mkdir(parents=True)
            (root / "tests").mkdir()
            relative = "crates/trusted-router/src/lib.rs"
            original = b"original\r\nvalue\r\n"  # restoration must preserve bytes, including CRLF
            (root / relative).write_bytes(original)
            for name in ["Cargo.toml", "Cargo.lock", "clippy.toml", "rustfmt.toml", "LICENSE"]:
                (root / name).write_text("")
            (root / "scripts/mutations.json").write_text(json.dumps([{
                "name": "probe", "file": relative, "before": before,
                "after": "mutation\nvalue", "test": "focused_probe",
            }]))
            error = None
            with patch.object(gate, "ROOT", root), \
                    patch("sys.argv", ["mutation_check.py"]), \
                    patch.object(gate.tempfile, "TemporaryDirectory", return_value=contextlib.nullcontext(str(work))), \
                    patch.object(gate, "run", side_effect=[(0, "test focused_probe ... ok\n"), outcome]) as cargo, \
                    patch.object(gate, "static_probes"), \
                    contextlib.redirect_stdout(io.StringIO()):
                try:
                    gate.main()
                except RuntimeError as caught:
                    error = str(caught)
            self.assertEqual((root / relative).read_bytes(), original)
            if (work / relative).exists():
                self.assertEqual((work / relative).read_bytes(), original)
            return error, cargo.call_count

    def test_stale_pattern_fails_before_cargo(self):
        error, calls = self.exercise((0, ""), before="stale pattern")
        self.assertIn("stale/nonunique", error)
        self.assertEqual(calls, 0)

    def test_survivor_fails_and_restores_original_bytes(self):
        error, _ = self.exercise((0, "test focused_probe ... ok\n"))
        self.assertIn("SURVIVED", error)

    def test_compile_failure_is_not_a_kill(self):
        error, _ = self.exercise((101, "error: could not compile\n"))
        self.assertIn("did not report FAILED", error)

    def test_filtered_out_test_is_not_a_kill(self):
        error, _ = self.exercise((101, "running 0 tests\n"))
        self.assertIn("did not report FAILED", error)

    def test_real_test_failure_is_a_kill(self):
        error, _ = self.exercise((101, "test focused_probe ... FAILED\n"))
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
