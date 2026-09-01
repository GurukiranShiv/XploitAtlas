"""Opt-in tests against real provider responses in a disposable database.

Run VULNORBIT_LIVE_TESTS=1 python -m unittest discover -s tests -v.
No fixture records or test mutations are ever shipped into the application catalog.
"""
import copy
import gzip
import hashlib
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
import adapters
from core import merge
from feeds import Ingestor
from server import Server
from store import Store

@unittest.skipUnless(os.getenv("VULNORBIT_LIVE_TESTS") == "1", "Opt-in real upstream integration")
class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.store = Store(cls.root / "catalog.sqlite3")
        cls.ingestor = Ingestor(cls.store, cls.root, interval=900)
        if not cls.ingestor.sync():
            raise RuntimeError("No upstream source responded. No substitute dataset is permitted.")
        cls.records = cls.store.export_records()
        cls.statuses = {s["id"]: s for s in cls.store.sources()}
        print("\nREAL-SOURCE VALIDATION:", json.dumps({
            "records": len(cls.records),
            "sources": {key: {"state": value["state"], "count": value["count"], "lastSuccess": value["lastSuccess"]}
                        for key, value in cls.statuses.items()}}), flush=True)
        cls.cisa = [s for r in cls.records for s in cls.store.signals(r["id"]) if s["source"] == "cisa"]
        cls.httpd = Server(("127.0.0.1", 0), cls.store, cls.ingestor, {"127.0.0.1", "localhost"})
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        cls.ingestor.close()
        cls.temp.cleanup()

    def request(self, path, method="GET", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=65)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_real_catalog_and_metrics(self):
        self.assertGreater(len(self.records), 100)
        self.assertGreater(len(self.cisa), 100)
        for source in ("cisa", "nvd", "github", "epss"):
            self.assertEqual(self.statuses[source]["state"], "ok", self.statuses[source]["message"])
        self.assertEqual(len({r["id"] for r in self.records}), len(self.records))
        self.assertTrue(any(r["cvss"] is not None for r in self.records))
        self.assertTrue(any(r["epss"] is not None for r in self.records))
        for r in self.records:
            self.assertTrue(r["sources"])
            if r["cvss"] is not None:
                self.assertTrue(0 <= r["cvss"] <= 10)
            if r["epss"] is not None:
                self.assertTrue(0 <= r["epss"] <= 1)
        nvd_cursor = self.store.state("nvd_published_cursor")
        self.assertIsNotNone(nvd_cursor)
        self.assertGreaterEqual(nvd_cursor["index"], 0)

    def test_raw_responses_have_verifiable_fingerprints(self):
        files = list((self.root / "raw").glob("*/*.json.gz"))
        self.assertGreater(len(files), 0)
        for file in files:
            raw = gzip.decompress(file.read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), file.name.split(".")[0])
            self.assertIsNotNone(json.loads(raw))

    def test_identical_real_observations_do_not_create_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Store(Path(directory)/"repeat.sqlite3")
            observations = self.cisa[:3]
            db.ingest("cisa", observations)
            self.assertEqual(db.events(), [])
            db.ingest("cisa", observations)
            self.assertEqual(db.events(), [])
            self.assertEqual(db.catalog()["stats"]["total"], len(observations))

    def test_cursor_and_observations_roll_back_together(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Store(Path(directory)/"atomic.sqlite3")
            db.set_state("cursor", {"page": 1})
            invalid = {**self.cisa[1], "source": "nvd"}
            with self.assertRaises(ValueError):
                db.ingest("cisa", [self.cisa[0], invalid], checkpoint={"cursor": {"page": 2}})
            self.assertEqual(db.state("cursor"), {"page": 1})
            self.assertEqual(db.catalog()["stats"]["total"], 0)
            self.assertIsNone(next(s for s in db.sources() if s["id"]=="cisa")["lastSuccess"])

    def test_partial_and_complete_catalog_have_different_removal_rules(self):
        # Real source observations are used in an isolated test database.
        with tempfile.TemporaryDirectory() as directory:
            db = Store(Path(directory)/"reconcile.sqlite3")
            observations = self.cisa[:3]
            db.ingest("cisa", observations)
            db.ingest("cisa", observations[:2])
            self.assertTrue(db.record(observations[2]["id"])["kev"])
            db.ingest("cisa", observations[:2], complete_catalog=True)
            self.assertFalse(db.record(observations[2]["id"])["kev"])
            events = db.events(observations[2]["id"])
            self.assertEqual(events[0]["kind"], "catalog_removed")
            self.assertEqual(events[0]["changes"], [{"field": "kev", "before": True, "after": False}])

    def test_change_history_preserves_before_and_after(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Store(Path(directory)/"history.sqlite3")
            observation = self.cisa[0]
            db.ingest("cisa", [observation])
            # Deliberately remove one supplied field to exercise field-level diffs;
            # this validation-only mutation is never served by the app.
            revised = copy.deepcopy(observation)
            revised.pop("requiredAction", None)
            db.ingest("cisa", [revised])
            changes = db.events(observation["id"])
            self.assertEqual(changes[0]["kind"], "remediation_changed")
            field = next(c for c in changes[0]["changes"] if c["field"]=="requiredAction")
            self.assertEqual(field["before"], observation["requiredAction"])
            self.assertIsNone(field["after"])

    def test_different_ids_cannot_be_fused(self):
        with self.assertRaises(ValueError):
            merge(self.cisa[:2])

    def test_on_demand_publisher_and_osv_alias(self):
        record = self.ingestor.enrich("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q")
        self.assertIsNotNone(record)
        self.assertEqual(record["id"], "CVE-2021-44228")
        self.assertIn("cve", {s["id"] for s in record["sources"]})
        self.assertIn("osv", {s["id"] for s in record["sources"]})
        self.assertTrue(any(p.get("fixed") for p in record["packages"]))

    def test_package_match_comes_from_osv(self):
        result = self.ingestor.package("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
        ids = {r["id"] for r in result["records"]}
        self.assertIn("CVE-2021-44228", ids)
        for record in result["records"]:
            self.assertIn("osv", {s["id"] for s in record["sources"]})
        self.assertTrue(any(r["packages"] for r in result["records"]))

    def test_http_catalog_pagination_and_security_headers(self):
        status, headers, raw = self.request("/api/universe?limit=7")
        self.assertEqual(status, 200)
        data = json.loads(raw)
        self.assertEqual(len(data["records"]), 7)
        self.assertGreater(data["matching"], 7)
        self.assertEqual(data["mode"], "real-sources-only")
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        second = json.loads(self.request("/api/universe?limit=7&offset=7")[2])
        self.assertFalse({r["id"] for r in data["records"]} & {r["id"] for r in second["records"]})
        status, _, _ = self.request("/api/universe?limit=-1")
        self.assertEqual(status, 400)
        status, _, _ = self.request("/api/health", headers={"Host": "attacker.example"})
        self.assertEqual(status, 403)

    def test_cross_origin_mutation_is_rejected(self):
        status, _, raw = self.request("/api/package", method="POST", body=b"{}",
            headers={"Content-Type": "application/json", "Origin": "https://attacker.example"})
        self.assertEqual(status, 403)

    def test_static_and_export_routes(self):
        for path in ("/", "/static/app.js", "/static/universe.js", "/static/ui.js", "/static/style.css", "/static/mark.svg"):
            status, _, raw = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertGreater(len(raw), 100)
        self.assertEqual(self.request("/static/../core.py")[0], 404)
        status, _, raw = self.request("/api/export")
        self.assertEqual(status, 200)
        export = json.loads(raw)
        self.assertGreater(len(export["records"]), 100)
        self.assertTrue(all(r["sources"] for r in export["records"]))
        status, _, raw = self.request("/api/export?format=csv")
        self.assertEqual(status, 200)
        self.assertIn(b"sourceUrls", raw)

    def test_download_contains_code_without_runtime_or_secrets(self):
        status, _, raw = self.request("/api/source")
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn("vulnorbit/start.py", archive.namelist())
            self.assertIn("vulnorbit/static/index.html", archive.namelist())
            self.assertFalse(any("/runtime/" in n or n.endswith("/.env") or n.endswith(".sqlite3") for n in archive.namelist()))

if __name__ == "__main__":
    unittest.main()
