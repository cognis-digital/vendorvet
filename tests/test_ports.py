"""Cross-language port parity: every *installed* port must score the demo
questionnaires identically to the Python reference (same residual score, tier,
answered count) and return the same CI exit code.

Ports whose toolchain is not installed are skipped, never failed — so the suite
stays green offline with stdlib while CI (ports.yml) exercises all of them.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendorvet.core import assess_questionnaire  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = ["01-basic", "03-mixed", "07-startup-unanswered"]


def _q(name):
    return os.path.join(_ROOT, "demos", name, "questionnaire.json")


def _py_ref(name):
    with open(_q(name), encoding="utf-8") as fh:
        r = assess_questionnaire(json.load(fh))
    return {
        "residual_score": r.residual_score,
        "tier": r.tier.value,
        "answered": r.answered,
        "total_controls": r.total_controls,
    }


def _run(cmd):
    p = subprocess.run(cmd, cwd=_ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout


class TestPyReference(unittest.TestCase):
    """Sanity-check the reference values the ports are compared against."""

    def test_basic_moderate(self):
        self.assertEqual(_py_ref("01-basic")["tier"], "moderate")

    def test_startup_high(self):
        ref = _py_ref("07-startup-unanswered")
        self.assertEqual(ref["tier"], "high")
        self.assertEqual(ref["answered"], 3)

    def test_mixed_moderate(self):
        self.assertEqual(_py_ref("03-mixed")["tier"], "moderate")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestNodePort(unittest.TestCase):
    def _node(self, name):
        rc, out = _run(["node", "ports/javascript/index.js",
                        "questionnaire", _q(name), "--format", "json"])
        return rc, json.loads(out)

    def test_parity_all_demos(self):
        for name in DEMOS:
            with self.subTest(demo=name):
                ref = _py_ref(name)
                _, got = self._node(name)
                self.assertEqual(got["residual_score"], ref["residual_score"])
                self.assertEqual(got["tier"], ref["tier"])
                self.assertEqual(got["answered"], ref["answered"])
                self.assertEqual(got["total_controls"], ref["total_controls"])

    def test_exit_code_high_is_2(self):
        rc, _ = self._node("07-startup-unanswered")
        self.assertEqual(rc, 2)

    def test_exit_code_moderate_is_0(self):
        rc, _ = self._node("01-basic")
        self.assertEqual(rc, 0)

    def test_bad_classification_errors(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"vendor": "X", "data_classification": "top-secret",
                       "answers": {}}, fh)
            path = fh.name
        try:
            rc, _ = _run(["node", "ports/javascript/index.js",
                          "questionnaire", path])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(path)


@unittest.skipUnless(shutil.which("jq"), "jq not installed (shell port)")
class TestShellPort(unittest.TestCase):
    def _sh(self, name):
        rc, out = _run(["sh", "ports/shell/vendorvet.sh",
                        "questionnaire", _q(name), "--format", "json"])
        return rc, json.loads(out)

    def test_parity_all_demos(self):
        for name in DEMOS:
            with self.subTest(demo=name):
                ref = _py_ref(name)
                _, got = self._sh(name)
                self.assertEqual(got["residual_score"], ref["residual_score"])
                self.assertEqual(got["tier"], ref["tier"])
                self.assertEqual(got["answered"], ref["answered"])

    def test_exit_code_high_is_2(self):
        rc, _ = self._sh("07-startup-unanswered")
        self.assertEqual(rc, 2)

    def test_exit_code_moderate_is_0(self):
        rc, _ = self._sh("01-basic")
        self.assertEqual(rc, 0)

    def test_bad_classification_errors(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"vendor": "X", "data_classification": "top-secret",
                       "answers": {}}, fh)
            path = fh.name
        try:
            rc, _ = _run(["sh", "ports/shell/vendorvet.sh",
                          "questionnaire", path])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(path)


@unittest.skipUnless(shutil.which("go"), "go not installed")
class TestGoPort(unittest.TestCase):
    def test_parity(self):
        for name in DEMOS:
            with self.subTest(demo=name):
                ref = _py_ref(name)
                p = subprocess.run(
                    ["go", "run", ".", "questionnaire",
                     os.path.join("..", "..", "demos", name, "questionnaire.json"),
                     "--format", "json"],
                    cwd=os.path.join(_ROOT, "ports", "go"),
                    capture_output=True, text=True,
                )
                got = json.loads(p.stdout)
                self.assertEqual(got["residual_score"], ref["residual_score"])
                self.assertEqual(got["tier"], ref["tier"])


@unittest.skipUnless(shutil.which("cargo"), "cargo not installed")
class TestRustPort(unittest.TestCase):
    def test_parity(self):
        for name in DEMOS:
            with self.subTest(demo=name):
                ref = _py_ref(name)
                p = subprocess.run(
                    ["cargo", "run", "-q", "--", "questionnaire",
                     os.path.join("..", "..", "demos", name, "questionnaire.json"),
                     "--format", "json"],
                    cwd=os.path.join(_ROOT, "ports", "rust"),
                    capture_output=True, text=True,
                )
                got = json.loads(p.stdout)
                self.assertEqual(got["residual_score"], ref["residual_score"])
                self.assertEqual(got["tier"], ref["tier"])


if __name__ == "__main__":
    unittest.main()
