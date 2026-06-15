"""Tests covering hardened error-handling and edge cases added to VENDORVET."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendorvet.core import (  # noqa: E402
    assess_questionnaire,
    assess_vendor,
    crossref_sbom,
    load_json_file,
)
from vendorvet.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# load_json_file hardening
# ---------------------------------------------------------------------------

class TestLoadJsonFile(unittest.TestCase):
    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError) as ctx:
            load_json_file("/no/such/path/file.json")
        self.assertIn("file not found", str(ctx.exception))

    def test_malformed_json_raises_json_decode_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("{bad json!!!")
            path = fh.name
        try:
            with self.assertRaises(json.JSONDecodeError) as ctx:
                load_json_file(path)
            # The message should mention the file (path may use repr escapes)
            self.assertIn("invalid JSON in", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_json_array_raises_value_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump([1, 2, 3], fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                load_json_file(path)
            self.assertIn("JSON object", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_empty_path_raises(self):
        with self.assertRaises(ValueError):
            load_json_file("")


# ---------------------------------------------------------------------------
# crossref_sbom hardening
# ---------------------------------------------------------------------------

class TestCrossrefSbomHardening(unittest.TestCase):
    def test_non_dict_sbom_raises(self):
        with self.assertRaises(ValueError) as ctx:
            crossref_sbom([{"name": "foo", "version": "1.0"}], {})
        self.assertIn("JSON object", str(ctx.exception))

    def test_non_dict_advisories_raises(self):
        with self.assertRaises(ValueError) as ctx:
            crossref_sbom({"components": []}, ["not", "a", "dict"])
        self.assertIn("JSON object", str(ctx.exception))

    def test_empty_components_list_returns_clean(self):
        r = crossref_sbom({"components": []}, {})
        self.assertEqual(r.components_scanned, 0)
        self.assertEqual(r.vulnerable, [])
        self.assertEqual(r.max_cvss, 0.0)
        self.assertEqual(r.severity, "none")

    def test_non_numeric_cvss_defaults_to_zero(self):
        sbom = {"components": [{"name": "foo", "version": "1.0"}]}
        advisories = {"foo": [{"cve": "CVE-X", "cvss": "oops", "versions": ["1.0"]}]}
        r = crossref_sbom(sbom, advisories)
        self.assertEqual(len(r.vulnerable), 1)
        self.assertEqual(r.vulnerable[0].cvss, 0.0)

    def test_component_without_name_is_skipped(self):
        sbom = {"components": [{"version": "1.0"}, {"name": "", "version": "2.0"}]}
        r = crossref_sbom(sbom, {})
        self.assertEqual(r.components_scanned, 0)
        self.assertEqual(r.vulnerable, [])

    def test_non_dict_component_is_skipped(self):
        sbom = {"components": [None, "string_entry", {"name": "ok", "version": "1.0"}]}
        r = crossref_sbom(sbom, {})
        self.assertEqual(r.components_scanned, 1)

    def test_cvss_clamped_to_ten(self):
        sbom = {"components": [{"name": "x", "version": "1.0"}]}
        advisories = {"x": [{"cve": "C", "cvss": 999.9, "versions": ["1.0"]}]}
        r = crossref_sbom(sbom, advisories)
        self.assertLessEqual(r.max_cvss, 10.0)


# ---------------------------------------------------------------------------
# assess_questionnaire hardening
# ---------------------------------------------------------------------------

class TestAssessQuestionnaireHardening(unittest.TestCase):
    def test_non_dict_raises(self):
        with self.assertRaises(ValueError):
            assess_questionnaire("not a dict")

    def test_non_dict_answers_raises(self):
        with self.assertRaises(ValueError) as ctx:
            assess_questionnaire({
                "vendor": "X", "data_classification": "internal",
                "answers": "yes to all"
            })
        self.assertIn("answers", str(ctx.exception))

    def test_empty_answers_all_half_penalty(self):
        r = assess_questionnaire({
            "vendor": "X", "data_classification": "internal", "answers": {}
        })
        self.assertEqual(r.answered, 0)
        self.assertGreater(r.residual_score, 0.0)
        # every control should appear in gaps
        self.assertEqual(len(r.gaps), r.total_controls)


# ---------------------------------------------------------------------------
# assess_vendor hardening
# ---------------------------------------------------------------------------

class TestAssessVendorHardening(unittest.TestCase):
    def test_no_inputs_raises(self):
        with self.assertRaises(ValueError) as ctx:
            assess_vendor()
        self.assertIn("at least one", str(ctx.exception))

    def test_sbom_only_no_questionnaire(self):
        sbom = {"components": [{"name": "ok", "version": "1.0"}]}
        r = assess_vendor(sbom=sbom, advisories={})
        self.assertIsNone(r.questionnaire)
        self.assertIsNotNone(r.sbom)


# ---------------------------------------------------------------------------
# CLI hardening
# ---------------------------------------------------------------------------

class TestCliHardening(unittest.TestCase):
    def _write_json(self, data) -> str:
        fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(data, fh)
        fh.close()
        return fh.name

    def test_missing_questionnaire_file_returns_1(self):
        rc = main(["questionnaire", "/no/such/file.json"])
        self.assertEqual(rc, 1)

    def test_malformed_json_questionnaire_returns_1(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("{bad!")
            path = fh.name
        try:
            rc = main(["questionnaire", path])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(path)

    def test_sbom_missing_file_returns_1(self):
        adv = self._write_json({})
        try:
            rc = main(["sbom", "/no/such/sbom.json", adv])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(adv)

    def test_json_array_file_returns_1(self):
        """load_json_file must reject a JSON array (not an object)."""
        path = self._write_json([1, 2, 3])
        try:
            rc = main(["questionnaire", path])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(path)

    def test_assess_valid_questionnaire_returns_0_or_2(self):
        q = self._write_json({
            "vendor": "CleanCo",
            "data_classification": "internal",
            "answers": {
                "soc2_type2": True, "iso27001": True,
                "encryption_at_rest": True, "encryption_in_transit": True,
                "mfa_enforced": True, "pentest_annual": True,
                "incident_response_plan": True, "breach_notification_sla": True,
                "subprocessor_list": True, "data_retention_policy": True,
                "vuln_mgmt_program": True, "employee_security_training": True,
                "shares_data_with_third_parties": False,
                "prior_breach_24mo": False,
            },
        })
        try:
            rc = main(["assess", q])
            self.assertIn(rc, (0, 2))
        finally:
            os.unlink(q)


if __name__ == "__main__":
    unittest.main()
