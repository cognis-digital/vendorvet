"""Tests for the SARIF 2.1.0 exporter and demo fixtures. Stdlib only, no network."""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendorvet.core import assess_vendor  # noqa: E402
from vendorvet.sarif import to_sarif, questionnaire_to_sarif, sbom_to_sarif  # noqa: E402
from vendorvet.cli import main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")
DEMO1 = os.path.join(DEMOS, "01-basic")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class TestSarifStructure(unittest.TestCase):
    def setUp(self):
        self.q = _load(os.path.join(DEMO1, "questionnaire.json"))
        self.sbom = _load(os.path.join(DEMO1, "sbom.json"))
        self.adv = _load(os.path.join(DEMO1, "advisories.json"))

    def test_sarif_envelope(self):
        log = to_sarif(assess_vendor(self.q, self.sbom, self.adv))
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("$schema", log)
        self.assertEqual(len(log["runs"]), 1)
        driver = log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "vendorvet")
        self.assertTrue(driver["version"])

    def test_results_have_required_fields(self):
        log = to_sarif(assess_vendor(self.q, self.sbom, self.adv))
        results = log["runs"][0]["results"]
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertIn("ruleId", r)
            self.assertIn(r["level"], ("none", "note", "warning", "error"))
            self.assertIn("text", r["message"])
            loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(loc)

    def test_rules_match_results(self):
        log = to_sarif(assess_vendor(self.q, self.sbom, self.adv))
        run = log["runs"][0]
        rule_ids = {ru["id"] for ru in run["tool"]["driver"]["rules"]}
        for r in run["results"]:
            self.assertIn(r["ruleId"], rule_ids)

    def test_critical_cve_is_error_with_security_severity(self):
        log = to_sarif(assess_vendor(self.q, self.sbom, self.adv))
        results = log["runs"][0]["results"]
        cve = next(r for r in results if r["ruleId"] == "CVE-2021-44228")
        self.assertEqual(cve["level"], "error")
        self.assertEqual(cve["properties"]["security-severity"], "10.0")

    def test_questionnaire_only_helper(self):
        log = questionnaire_to_sarif(self.q)
        self.assertEqual(log["version"], "2.1.0")
        rule_ids = {r["ruleId"] for r in log["runs"][0]["results"]}
        self.assertIn("VEN-Q-RESIDUAL", rule_ids)
        # no SBOM CVEs present
        self.assertFalse(any(r.startswith("CVE-") for r in rule_ids))

    def test_sbom_only_helper(self):
        log = sbom_to_sarif(self.sbom, self.adv)
        rule_ids = {r["ruleId"] for r in log["runs"][0]["results"]}
        self.assertIn("CVE-2021-44228", rule_ids)
        self.assertFalse(any(r.startswith("VEN-Q-") for r in rule_ids))


class TestSarifCli(unittest.TestCase):
    def test_cli_sarif_assess_is_valid_json(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--format", "sarif", "assess",
                       os.path.join(DEMO1, "questionnaire.json"),
                       "--sbom", os.path.join(DEMO1, "sbom.json"),
                       "--advisories", os.path.join(DEMO1, "advisories.json")])
        self.assertEqual(rc, 2)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")

    def test_cli_sarif_questionnaire(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--format", "sarif", "questionnaire",
                  os.path.join(DEMO1, "questionnaire.json")])
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")

    def test_cli_sarif_sbom(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--format", "sarif", "sbom",
                  os.path.join(DEMO1, "sbom.json"),
                  os.path.join(DEMO1, "advisories.json")])
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")


class TestDemoFixtures(unittest.TestCase):
    """Every demo with inputs must parse and produce output without error."""

    def test_all_questionnaires_assess(self):
        files = glob.glob(os.path.join(DEMOS, "*", "questionnaire.json"))
        self.assertGreaterEqual(len(files), 6)
        for f in files:
            doc = _load(f)
            r = assess_vendor(questionnaire=doc)
            self.assertIsNotNone(r.questionnaire, f)
            self.assertIn(r.overall_tier.value,
                          ("low", "moderate", "high", "critical"), f)

    def test_all_sbom_pairs_crossref(self):
        for d in sorted(glob.glob(os.path.join(DEMOS, "*"))):
            sbom_p = os.path.join(d, "sbom.json")
            adv_p = os.path.join(d, "advisories.json")
            if os.path.exists(sbom_p) and os.path.exists(adv_p):
                r = assess_vendor(sbom=_load(sbom_p), advisories=_load(adv_p))
                self.assertIsNotNone(r.sbom, d)

    def test_every_demo_dir_has_scenario(self):
        for d in sorted(glob.glob(os.path.join(DEMOS, "*"))):
            if os.path.isdir(d):
                self.assertTrue(os.path.exists(os.path.join(d, "SCENARIO.md")),
                                f"{d} missing SCENARIO.md")


if __name__ == "__main__":
    unittest.main()
