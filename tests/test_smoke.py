"""Smoke tests for VENDORVET. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendorvet import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    RiskTier,
    assess_questionnaire,
    assess_vendor,
    crossref_sbom,
)
from vendorvet.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos", "01-basic")


def _load(name):
    with open(os.path.join(DEMO, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestMeta(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "vendorvet")
        self.assertTrue(TOOL_VERSION)


class TestQuestionnaire(unittest.TestCase):
    def test_clean_vendor_is_low(self):
        doc = {
            "vendor": "Good Co", "data_classification": "internal",
            "answers": {k: (k not in ("shares_data_with_third_parties", "prior_breach_24mo"))
                        for k in [
                            "soc2_type2", "iso27001", "encryption_at_rest",
                            "encryption_in_transit", "mfa_enforced", "pentest_annual",
                            "incident_response_plan", "breach_notification_sla",
                            "subprocessor_list", "data_retention_policy",
                            "vuln_mgmt_program", "employee_security_training",
                            "shares_data_with_third_parties", "prior_breach_24mo"]},
        }
        r = assess_questionnaire(doc)
        self.assertEqual(r.tier, RiskTier.LOW)
        self.assertEqual(r.residual_score, 0.0)
        self.assertEqual(r.gaps, [])

    def test_demo_questionnaire_flags_gaps(self):
        r = assess_questionnaire(_load("questionnaire.json"))
        self.assertGreater(r.residual_score, 0.0)
        self.assertTrue(any("MFA" in g for g in r.gaps))
        self.assertTrue(any("pen test" in g.lower() for g in r.gaps))

    def test_unanswered_is_half_penalty(self):
        r = assess_questionnaire({"vendor": "X", "data_classification": "internal", "answers": {}})
        self.assertEqual(r.answered, 0)
        self.assertEqual(len(r.gaps), r.total_controls)

    def test_bad_classification_raises(self):
        with self.assertRaises(ValueError):
            assess_questionnaire({"vendor": "X", "data_classification": "top-secret", "answers": {}})

    def test_inherent_multiplier_increases_risk(self):
        base = {"vendor": "X", "answers": {"mfa_enforced": False}}
        lo = assess_questionnaire({**base, "data_classification": "public"})
        hi = assess_questionnaire({**base, "data_classification": "restricted"})
        self.assertGreater(hi.residual_score, lo.residual_score)


class TestSbom(unittest.TestCase):
    def test_finds_known_vuln(self):
        r = crossref_sbom(_load("sbom.json"), _load("advisories.json"))
        self.assertEqual(r.max_cvss, 10.0)
        self.assertEqual(r.severity, "critical")
        cves = {c.cve for c in r.vulnerable}
        self.assertIn("CVE-2021-44228", cves)

    def test_clean_sbom_no_match(self):
        r = crossref_sbom({"components": [{"name": "requests", "version": "2.31.0"}]},
                          {"requests": [{"cve": "X", "cvss": 5.0, "versions": ["2.30.0"]}]})
        self.assertEqual(r.vulnerable, [])
        self.assertEqual(r.severity, "none")

    def test_missing_components_raises(self):
        with self.assertRaises(ValueError):
            crossref_sbom({}, {})


class TestAssess(unittest.TestCase):
    def test_sbom_critical_dominates(self):
        r = assess_vendor(_load("questionnaire.json"), _load("sbom.json"), _load("advisories.json"))
        self.assertEqual(r.overall_tier, RiskTier.CRITICAL)
        self.assertEqual(r.overall_score, 100.0)
        self.assertIn("Reject", r.recommendation)

    def test_questionnaire_only(self):
        r = assess_vendor(_load("questionnaire.json"))
        self.assertIsNone(r.sbom)
        self.assertIsNotNone(r.questionnaire)


class TestCli(unittest.TestCase):
    def test_high_risk_exit_code_2(self):
        rc = main(["--format", "json", "assess",
                   os.path.join(DEMO, "questionnaire.json"),
                   "--sbom", os.path.join(DEMO, "sbom.json"),
                   "--advisories", os.path.join(DEMO, "advisories.json")])
        self.assertEqual(rc, 2)

    def test_no_command_returns_1(self):
        self.assertEqual(main([]), 1)

    def test_bad_file_returns_1(self):
        self.assertEqual(main(["questionnaire", "/no/such/file.json"]), 1)

    def test_questionnaire_subcommand_runs(self):
        rc = main(["questionnaire", os.path.join(DEMO, "questionnaire.json")])
        self.assertIn(rc, (0, 2))


if __name__ == "__main__":
    unittest.main()
