"""Unit checks use primitives and this project's actual dependency file.

They contain no vulnerability fixtures, saved catalog, accounts, or network calls.
"""
from __future__ import annotations

import math
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from components import badge_svg, exact_component, record_counts
from manifests import parse_document
from prioritization import priority_band, score_evidence, validate_weights
from taxonomy import Taxonomy, is_attack_taxonomy, local_name, normalize_attack_id, normalize_cwe_id
from mastermonk import sarif


ROOT = Path(__file__).resolve().parents[1]


class PriorityMathTests(unittest.TestCase):
    def test_boundary_bands(self):
        self.assertEqual([priority_band(value) for value in (0, 15, 40, 70, 100)],
                         ["Monitor", "Review", "Investigate", "Act now", "Act now"])

    def test_weighted_points_round_and_cap(self):
        weights = validate_weights()
        half_cvss = score_evidence({"cvss": .5}, weights)
        self.assertEqual((half_cvss["rawScore"], half_cvss["score"], half_cvss["band"]), (10.0, 10, "Monitor"))
        maximum = score_evidence({key: 1 for key in weights}, weights)
        self.assertGreater(maximum["rawScore"], 100)
        self.assertEqual((maximum["score"], maximum["band"]), (100, "Act now"))

    def test_non_finite_and_out_of_range_values_fail_closed(self):
        for value in (-.01, 1.01, math.nan, math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                score_evidence({"epss": value})


class TaxonomyPrimitiveTests(unittest.TestCase):
    def test_official_identifier_formats(self):
        self.assertEqual(normalize_cwe_id("CWE-79"), "CWE-79")
        self.assertEqual(normalize_attack_id("T1059.001"), "T1059.001")
        self.assertTrue(is_attack_taxonomy("MITRE ATT&CK"))

    def test_invalid_identifier_shapes_are_not_mapped(self):
        self.assertEqual(normalize_cwe_id(""), "")
        self.assertEqual(normalize_attack_id("T1059.1"), "")
        self.assertFalse(is_attack_taxonomy("CAPEC"))

    def test_namespace_local_name(self):
        self.assertEqual(local_name("{https://capec.mitre.org/capec-3}Attack_Pattern"), "Attack_Pattern")

    def test_capec_parser_rejects_unsafe_declarations_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "Unexpected XML declaration"):
            Taxonomy._parse(b"<!DOCTYPE catalog>")


class DistributionContractTests(unittest.TestCase):
    def test_actual_dependency_manifest_parses_without_network(self):
        parsed = parse_document("requirements.txt", (ROOT / "requirements.txt").read_text(encoding="utf-8"))
        self.assertEqual([(item["ecosystem"],item["name"],item["version"],item["skipReason"])
                          for item in parsed["components"]], [("PyPI","waitress","3.0.2",None)])

    def test_badge_is_valid_xml_and_never_calls_zero_matches_safe(self):
        component = exact_component({"ecosystem":"PyPI","name":"waitress","version":"3.0.2"})
        view = {"summary":record_counts([]),"partial":False,"recordsTruncated":False,"checkedAt":"not supplied"}
        body = badge_svg(component, view)
        ET.fromstring(body)
        self.assertIn("0 OSV matches", body)
        self.assertNotIn("safe", body.lower())

    def test_sarif_driver_has_no_personal_project_url(self):
        report = {"policy":{"violations":[],"complete":True,"exitCode":0},"checks":[]}
        driver = sarif(report, ROOT / "requirements.txt")["runs"][0]["tool"]["driver"]
        self.assertNotIn("informationUri", driver)


if __name__ == "__main__":
    unittest.main()
