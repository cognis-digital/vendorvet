"""Offline test: bundled vuln DB ships 100k+ real vulns with detailed metadata."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendorvet.vulndb_local import VulnDB, count  # noqa: E402


class TestVulnDB(unittest.TestCase):
    def test_has_100k_plus_vulns(self):
        self.assertGreaterEqual(VulnDB().count(), 100000)

    def test_module_count_helper(self):
        self.assertGreaterEqual(count(), 100000)

    def test_detailed_metadata(self):
        r = next(iter(VulnDB()))
        for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            self.assertIn(f, r)

    def test_cve_lookup_returns_list(self):
        self.assertIsInstance(VulnDB().by_cve("CVE-2021-44228"), list)

    def test_log4shell_resolves(self):
        hits = VulnDB().by_cve("CVE-2021-44228")
        self.assertTrue(hits)
        self.assertIn("CVE-2021-44228", hits[0]["aliases"])

    def test_package_lookup(self):
        db = VulnDB()
        self.assertTrue(db.by_package("lodash") or db.by_package("django"))

    def test_search_substring(self):
        hits = VulnDB().search("remote code", limit=5)
        self.assertTrue(hits)
        self.assertLessEqual(len(hits), 5)

    def test_load_is_cached(self):
        db = VulnDB()
        first = db.load()
        self.assertIs(first, db.load())

    def test_missing_path_iterates_empty(self):
        db = VulnDB(path="/no/such/vulndb.jsonl.gz")
        self.assertEqual(list(db), [])

    def test_unknown_cve_empty(self):
        self.assertEqual(VulnDB().by_cve("CVE-1900-00001"), [])


if __name__ == "__main__":
    unittest.main()
