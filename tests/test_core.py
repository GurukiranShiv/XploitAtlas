"""Offline boundary tests. No example vulnerability catalog is created."""
import math
import tempfile
import unittest
from pathlib import Path
import adapters
from core import merge, number, priority, safe_url, timestamp
from feeds import Client, FeedError
from store import Store

class CoreTests(unittest.TestCase):
    def test_missing_and_invalid_numbers_remain_unknown(self):
        for value in (None, "", True, False, "NaN", "Infinity", float("nan"), -1, 11):
            self.assertIsNone(number(value))
        self.assertEqual(number(0), 0)
        self.assertEqual(number("9.8"), 9.8)
        self.assertIsNone(number(1.01, 1))

    def test_unknown_is_not_a_claim_of_low_risk(self):
        result = priority({})
        self.assertEqual(set(result["missing"]), {"CVSS", "EPSS"})
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["model"], "vulnorbit-1")

    def test_withdrawn_record_requires_verification(self):
        result = priority({"withdrawn": True, "kev": True})
        self.assertEqual(result["band"], "Verify record")
        self.assertEqual(result["score"], 0)

    def test_no_record_can_be_generated_without_a_source(self):
        with self.assertRaises(ValueError):
            merge([])

    def test_invalid_kev_catalog_cannot_be_treated_as_removal(self):
        for payload in ({}, {"count": 0, "vulnerabilities": []},
                        {"count": 1, "vulnerabilities": []}):
            with self.assertRaises(ValueError):
                adapters.cisa(payload, "2026-01-01T00:00:00Z", "https://www.cisa.gov/")

    def test_urls_and_dates_are_bounded(self):
        for value in ("javascript:alert(1)", "data:text/html,test", "file:///etc/passwd",
                      "https://user:secret@example.com", "https://"):
            self.assertIsNone(safe_url(value))
        self.assertEqual(safe_url("https://www.cve.org/"), "https://www.cve.org/")
        self.assertIsNone(timestamp("not-a-date"))
        self.assertEqual(timestamp("2025-01-01"), "2025-01-01T00:00:00Z")

    def test_new_database_contains_no_vulnerabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "empty.sqlite3")
            catalog = store.catalog()
            self.assertEqual(catalog["stats"]["total"], 0)
            self.assertEqual(catalog["records"], [])
            self.assertEqual(store.events(), [])
            self.assertTrue(all(s["lastSuccess"] is None for s in store.sources()))
            with self.assertRaises(ValueError):
                store.ingest("cisa", [], complete_catalog=True)

    def test_upstream_client_rejects_user_selected_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Client(Store(Path(directory)/"empty.sqlite3"), directory)
            for url in ("http://api.osv.dev/v1/query", "https://localhost/api",
                        "https://api.osv.dev.example.com/v1/query",
                        "https://user:password@api.osv.dev/v1/query"):
                with self.assertRaises(FeedError):
                    client.get(url, "osv")

if __name__ == "__main__":
    unittest.main()
