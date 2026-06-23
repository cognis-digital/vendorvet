"""Offline tests for the BUNDLED 262k-vuln DB enrichment (vendorvet.vulnscan).

Every assertion here is grounded in the committed ``cognis_vulndb.jsonl.gz`` —
no network, no cache. These prove real lookups resolve (e.g. CVE-2021-44228 /
log4shell, Heartbleed, Spring4Shell, Struts) against the bundle that ships in
the wheel.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendorvet import vulnscan  # noqa: E402
from vendorvet.vulndb_local import VulnDB  # noqa: E402
from vendorvet.cli import main  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO12 = os.path.join(_ROOT, "demos", "12-feeds-osv-kev")


class TestBundlePresent(unittest.TestCase):
    def test_bundle_loads_262k(self):
        self.assertGreaterEqual(VulnDB().count(), 100000)

    def test_db_singleton_reused(self):
        a = vulnscan.db()
        b = vulnscan.db()
        self.assertIs(a, b)


class TestDirectLookups(unittest.TestCase):
    def test_log4shell_resolves(self):
        recs = vulnscan.lookup_cve("CVE-2021-44228")
        self.assertTrue(recs)
        rec = recs[0]
        self.assertIn("CVE-2021-44228", rec.get("aliases", []))
        self.assertEqual(rec.get("ecosystem"), "Maven")

    def test_log4shell_case_insensitive(self):
        upper = vulnscan.lookup_cve("CVE-2021-44228")
        lower = vulnscan.lookup_cve("cve-2021-44228")
        self.assertEqual(len(upper), len(lower))
        self.assertTrue(lower)

    def test_log4shell_is_critical_score(self):
        rec = vulnscan.lookup_cve("CVE-2021-44228")[0]
        self.assertGreaterEqual(vulnscan._best_cvss(rec), 9.0)

    def test_ghsa_id_lookup(self):
        # log4shell's GHSA id should resolve to the same record set.
        by_cve = vulnscan.lookup_cve("CVE-2021-44228")
        ghsa = by_cve[0]["id"]
        self.assertTrue(ghsa.startswith("GHSA-"))
        self.assertTrue(vulnscan.lookup_cve(ghsa))

    def test_spring4shell_present(self):
        self.assertTrue(vulnscan.lookup_cve("CVE-2022-22965"))

    def test_struts_rce_present(self):
        self.assertTrue(vulnscan.lookup_cve("CVE-2017-5638"))

    def test_unknown_cve_empty(self):
        self.assertEqual(vulnscan.lookup_cve("CVE-1999-00000"), [])

    def test_empty_cve_empty(self):
        self.assertEqual(vulnscan.lookup_cve(""), [])

    def test_package_lookup_log4j(self):
        recs = vulnscan.lookup_package("org.apache.logging.log4j:log4j-core")
        self.assertTrue(recs)
        cves = {a for r in recs for a in r.get("aliases", [])}
        self.assertIn("CVE-2021-44228", cves)

    def test_package_lookup_django(self):
        self.assertTrue(vulnscan.lookup_package("django"))

    def test_package_lookup_ecosystem_filter(self):
        recs = vulnscan.lookup_package("django", "PyPI")
        self.assertTrue(recs)
        self.assertTrue(all(r.get("ecosystem") == "PyPI" for r in recs))

    def test_package_lookup_ecosystem_alias(self):
        # "python" should normalize to "PyPI".
        recs = vulnscan.lookup_package("django", "python")
        self.assertTrue(recs)
        self.assertTrue(all(r.get("ecosystem") == "PyPI" for r in recs))

    def test_package_lookup_unknown_empty(self):
        self.assertEqual(vulnscan.lookup_package("zzz-not-a-real-pkg-xyz"), [])

    def test_cve_for_prefers_cve_alias(self):
        rec = {"id": "GHSA-xxxx", "aliases": ["GHSA-yyyy", "CVE-2020-1234"]}
        self.assertEqual(vulnscan._cve_for(rec), "CVE-2020-1234")

    def test_cve_for_falls_back_to_id(self):
        rec = {"id": "GHSA-zzzz", "aliases": []}
        self.assertEqual(vulnscan._cve_for(rec), "GHSA-zzzz")

    def test_best_cvss_no_severity(self):
        self.assertEqual(vulnscan._best_cvss({}), 0.0)

    def test_best_cvss_numeric_severity(self):
        self.assertEqual(vulnscan._best_cvss({"severity": 7.5}), 7.5)


class TestStats(unittest.TestCase):
    def setUp(self):
        self.s = vulnscan.stats()

    def test_total_records(self):
        self.assertGreaterEqual(self.s["records"], 100000)

    def test_ecosystems_present(self):
        ecos = self.s["ecosystems"]
        self.assertIn("PyPI", ecos)
        self.assertIn("npm", ecos)
        self.assertIn("Maven", ecos)

    def test_ecosystem_counts_positive(self):
        self.assertTrue(all(n > 0 for n in self.s["ecosystems"].values()))

    def test_ecosystem_counts_sum_to_total(self):
        self.assertEqual(sum(self.s["ecosystems"].values()), self.s["records"])

    def test_with_cve_alias_counted(self):
        self.assertGreater(self.s["with_cve_alias"], 1000)

    def test_with_severity_counted(self):
        self.assertGreater(self.s["with_severity"], 1000)


class TestMatchSbom(unittest.TestCase):
    def _sbom(self):
        with open(os.path.join(DEMO12, "sbom.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def setUp(self):
        self.r = vulnscan.match_sbom(self._sbom())

    def test_scanned_count(self):
        self.assertEqual(self.r.components_scanned, 3)

    def test_finds_log4shell(self):
        cves = {f.cve for f in self.r.findings}
        self.assertIn("CVE-2021-44228", cves)

    def test_max_cvss_critical(self):
        self.assertGreaterEqual(self.r.max_cvss, 9.0)
        self.assertEqual(self.r.severity, "critical")

    def test_verdict_critical(self):
        self.assertEqual(self.r.verdict, "critical")

    def test_findings_sorted_desc(self):
        scores = [f.cvss for f in self.r.findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_findings_have_ecosystem(self):
        log4j = [f for f in self.r.findings if "log4j" in f.component]
        self.assertTrue(log4j)
        self.assertEqual(log4j[0].ecosystem, "Maven")

    def test_no_duplicate_cve_per_component(self):
        keys = [(f.component, f.version, f.cve) for f in self.r.findings]
        self.assertEqual(len(keys), len(set(keys)))

    def test_clean_component_no_findings(self):
        r = vulnscan.match_sbom(
            {"components": [{"name": "zzz-not-real-pkg", "version": "1.0",
                             "ecosystem": "PyPI"}]}
        )
        self.assertEqual(r.findings, [])
        self.assertEqual(r.verdict, "low")
        self.assertEqual(r.components_scanned, 1)

    def test_purl_colon_name_falls_back(self):
        # A maven-style coordinate should still match on the short name.
        r = vulnscan.match_sbom(
            {"components": [
                {"name": "org.apache.logging.log4j:log4j-core",
                 "version": "2.14.1", "ecosystem": "Maven"}]}
        )
        self.assertTrue(any(f.cve == "CVE-2021-44228" for f in r.findings))

    def test_missing_components_raises(self):
        with self.assertRaises(ValueError):
            vulnscan.match_sbom({})

    def test_unnamed_component_skipped(self):
        r = vulnscan.match_sbom({"components": [{"version": "1.0"}]})
        self.assertEqual(r.components_scanned, 0)


class TestVulndbCli(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    def test_stats_table(self):
        rc, out = self._run(["vulndb", "stats"])
        self.assertEqual(rc, 0)
        self.assertIn("records", out)

    def test_stats_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "stats"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertGreaterEqual(data["records"], 100000)

    def test_cve_hit_table(self):
        rc, out = self._run(["vulndb", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)
        self.assertIn("Log4j", out)

    def test_cve_hit_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertTrue(data)

    def test_cve_miss_returns_1(self):
        rc, out = self._run(["vulndb", "cve", "CVE-1999-00000"])
        self.assertEqual(rc, 1)

    def test_package_table(self):
        rc, out = self._run(["vulndb", "package", "django", "--ecosystem", "PyPI"])
        self.assertEqual(rc, 0)
        self.assertIn("django", out)

    def test_package_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "package", "django"])
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out))

    def test_match_exit_2_on_critical(self):
        rc, out = self._run(["vulndb", "match", os.path.join(DEMO12, "sbom.json")])
        self.assertEqual(rc, 2)
        self.assertIn("CRITICAL", out)

    def test_match_json(self):
        rc, out = self._run(
            ["--format", "json", "vulndb", "match", os.path.join(DEMO12, "sbom.json")]
        )
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out)["verdict"], "critical")

    def test_match_offline_no_network(self):
        # match never imports/uses datafeeds.fetch — guard it just in case.
        from vendorvet import datafeeds
        orig = datafeeds.fetch
        datafeeds.fetch = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("network attempted"))
        try:
            rc, _ = self._run(["vulndb", "match", os.path.join(DEMO12, "sbom.json")])
            self.assertEqual(rc, 2)
        finally:
            datafeeds.fetch = orig

    def test_no_vulndb_subcommand_returns_1(self):
        rc, _ = self._run(["vulndb"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
