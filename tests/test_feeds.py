"""Offline tests for the OSV + CISA-KEV feed enrichment.

These tests NEVER hit the network: COGNIS_FEEDS_CACHE is pointed at the committed
trimmed fixture cache and all access is forced offline. Any attempt to reach the
network is monkeypatched into a hard failure to prove offline isolation.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
FIXTURE_CACHE = os.path.join(_HERE, "fixtures", "feeds-cache")
DEMO = os.path.join(_ROOT, "demos", "12-feeds-osv-kev")

# Force the feed cache to the committed fixtures BEFORE importing the module.
os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE

from vendorvet import feeds as feedmod  # noqa: E402
from vendorvet import datafeeds  # noqa: E402
from vendorvet.cli import main  # noqa: E402


def _no_network(*a, **k):  # pragma: no cover - guard
    raise AssertionError("network access attempted in an offline test")


class _OfflineBase(unittest.TestCase):
    def setUp(self):
        os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE
        # Hard-block the network for the duration of every test.
        self._orig_fetch = datafeeds.fetch
        datafeeds.fetch = _no_network

    def tearDown(self):
        datafeeds.fetch = self._orig_fetch


class TestCatalog(_OfflineBase):
    def test_only_consumed_feeds_exposed(self):
        ids = {f["id"] for f in feedmod.relevant_catalog()}
        self.assertEqual(ids, {"osv", "cisa-kev"})

    def test_relevant_feeds_constant(self):
        self.assertEqual(set(feedmod.RELEVANT_FEEDS), {"osv", "cisa-kev"})


class TestKev(_OfflineBase):
    def test_kev_index_offline(self):
        idx = feedmod.kev_index(offline=True)
        self.assertIn("CVE-2021-44228", idx)
        self.assertEqual(idx["CVE-2021-44228"]["knownRansomwareCampaignUse"], "Known")


class TestCvss(_OfflineBase):
    def test_log4shell_is_10(self):
        self.assertEqual(
            feedmod._score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            10.0,
        )

    def test_django_xss_is_6_1(self):
        self.assertEqual(
            feedmod._score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            6.1,
        )

    def test_unparseable_vector_is_zero(self):
        self.assertEqual(feedmod._score_from_vector("garbage"), 0.0)


class TestOsvQuery(_OfflineBase):
    def test_offline_hit(self):
        vulns = feedmod.osv_query(
            "django", "3.0", "PyPI", offline=True
        )
        cves = {feedmod._cve_for(v) for v in vulns}
        self.assertIn("CVE-2020-13596", cves)

    def test_offline_miss_raises(self):
        with self.assertRaises(FileNotFoundError):
            feedmod.osv_query("nonexistent-pkg", "9.9.9", "PyPI", offline=True)

    def test_clean_component_no_vulns(self):
        self.assertEqual(
            feedmod.osv_query("requests", "2.31.0", "PyPI", offline=True), []
        )


class TestEnrich(_OfflineBase):
    def _sbom(self):
        with open(os.path.join(DEMO, "sbom.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_kev_escalates_to_critical(self):
        r = feedmod.enrich_sbom(self._sbom(), offline=True)
        self.assertEqual(r.verdict, "critical")
        self.assertGreaterEqual(r.known_exploited_count, 1)
        self.assertEqual(r.max_cvss, 10.0)

    def test_log4shell_flagged_exploited(self):
        r = feedmod.enrich_sbom(self._sbom(), offline=True)
        hits = [f for f in r.findings if f.cve == "CVE-2021-44228"]
        self.assertTrue(hits)
        self.assertTrue(hits[0].known_exploited)
        self.assertEqual(hits[0].cvss, 10.0)

    def test_django_present_but_not_exploited(self):
        r = feedmod.enrich_sbom(self._sbom(), offline=True)
        dj = [f for f in r.findings if f.component == "django"]
        self.assertTrue(dj)
        self.assertTrue(all(not f.known_exploited for f in dj))

    def test_kev_findings_sort_first(self):
        r = feedmod.enrich_sbom(self._sbom(), offline=True)
        self.assertTrue(r.findings[0].known_exploited)

    def test_clean_sbom_low(self):
        r = feedmod.enrich_sbom(
            {"components": [{"name": "requests", "version": "2.31.0",
                             "ecosystem": "PyPI"}]},
            offline=True,
        )
        self.assertEqual(r.verdict, "low")
        self.assertEqual(r.known_exploited_count, 0)

    def test_missing_components_raises(self):
        with self.assertRaises(ValueError):
            feedmod.enrich_sbom({}, offline=True)


class TestCli(_OfflineBase):
    def test_feeds_list(self):
        self.assertEqual(main(["feeds", "list"]), 0)

    def test_feeds_list_json(self):
        self.assertEqual(main(["--format", "json", "feeds", "list"]), 0)

    def test_feeds_get_offline(self):
        self.assertEqual(main(["feeds", "get", "cisa-kev", "--offline"]), 0)

    def test_feeds_get_rejects_foreign_feed(self):
        self.assertEqual(main(["feeds", "get", "gdelt", "--offline"]), 1)

    def test_feeds_update_rejects_foreign_feed(self):
        self.assertEqual(main(["feeds", "update", "gdelt"]), 1)

    def test_enrich_offline_exit_2_on_kev(self):
        rc = main(["feeds", "enrich", os.path.join(DEMO, "sbom.json"), "--offline"])
        self.assertEqual(rc, 2)

    def test_enrich_offline_json(self):
        rc = main(["--format", "json", "feeds", "enrich",
                   os.path.join(DEMO, "sbom.json"), "--offline"])
        self.assertEqual(rc, 2)

    def test_enrich_missing_cache_offline_errors(self):
        # A component with no fixture, offline -> FileNotFoundError -> rc 1.
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"components": [{"name": "zzz-not-cached",
                                       "version": "0.0.0", "ecosystem": "PyPI"}]}, fh)
            path = fh.name
        try:
            self.assertEqual(main(["feeds", "enrich", path, "--offline"]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
