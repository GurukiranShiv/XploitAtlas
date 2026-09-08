"""Exact component evidence shared by the public comparison and SVG badge.

Only OSV package-query responses and already collected enrichment are presented.
An empty result is a source observation, never a declaration that software is safe.
"""
from __future__ import annotations

import copy
import html
import threading
import time
import urllib.parse

from core import now, summary
from manifests import normalize_component


SUPPORTED_ECOSYSTEMS = ("npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "Packagist", "RubyGems")
SEVERITIES = ("Critical", "High", "Medium", "Low", "None", "Unknown")
SEVERITY_ORDER = {value: index for index, value in enumerate(SEVERITIES)}
CACHE_SECONDS = 300
MAX_CACHE_ITEMS = 256
MAX_RESPONSE_RECORDS = 500


def exact_component(values):
    """Return a minimal validated exact-version identity."""
    component = normalize_component(values)
    if not component or component.get("skipReason"):
        raise ValueError("Supply a supported ecosystem, package name, and exact version.")
    result = {key: component[key].strip() for key in ("ecosystem", "name", "version")}
    if not result["name"] or not result["version"]:
        raise ValueError("Supply a supported ecosystem, package name, and exact version.")
    return result


def record_counts(records):
    """Count only supplied collected records; this function never invents rows."""
    counts = {"total": len(records), "kev": sum(bool(record.get("kev")) for record in records)}
    counts["severities"] = {level: sum(record.get("severity") == level for record in records) for level in SEVERITIES}
    return counts


def package_view(result):
    """Bound and normalize an Ingestor.package response for public presentation."""
    raw_records = [record for record in result.get("records", []) if isinstance(record, dict)]
    projected = [summary(record) for record in raw_records]
    projected.sort(key=lambda record: (
        not bool(record.get("kev")),
        SEVERITY_ORDER.get(record.get("severity"), len(SEVERITIES)),
        -float((record.get("priority") or {}).get("score", 0)),
        str(record.get("id", "")),
    ))
    truncated = len(projected) > MAX_RESPONSE_RECORDS
    projected = projected[:MAX_RESPONSE_RECORDS]
    query = result["query"]
    component = exact_component({"ecosystem": query["package"]["ecosystem"],
                                 "name": query["package"]["name"], "version": query["version"]})
    return {"component": component, "checkedAt": result.get("checkedAt"), "partial": bool(result.get("partial")),
            "message": str(result.get("message") or ""), "summary": record_counts(raw_records),
            "records": projected, "recordsTruncated": truncated, "badgePath": badge_path(component)}


def compare_views(left, right):
    """Compare advisory identities returned for two exact package observations."""
    left_records = {record["id"]: record for record in left["records"]}
    right_records = {record["id"]: record for record in right["records"]}

    def group(identifiers, source):
        records = [source[identifier] for identifier in sorted(identifiers)]
        return {"total": len(records), "records": records,
                "recordsTruncated": left.get("recordsTruncated", False) or right.get("recordsTruncated", False)}

    left_ids, right_ids = set(left_records), set(right_records)
    complete = not left["partial"] and not right["partial"] and not left["recordsTruncated"] and not right["recordsTruncated"]
    return {"comparedAt": now(), "complete": complete, "left": left, "right": right,
            "common": group(left_ids & right_ids, left_records),
            "onlyLeft": group(left_ids - right_ids, left_records),
            "onlyRight": group(right_ids - left_ids, right_records),
            "notice": "This compares current OSV exact-version matches. A missing match does not establish that a component is secure, and a one-sided match does not by itself prove remediation."}


def badge_path(component):
    return "/badge/component.svg?" + urllib.parse.urlencode(component)


def badge_status(view):
    counts = view["summary"]
    if view.get("partial") or view.get("recordsTruncated"):
        return (str(counts["total"]) + "+ OSV matches · partial", "#6d5b91")
    if counts["kev"]:
        return (str(counts["kev"]) + " KEV · " + str(counts["total"]) + " OSV", "#c72c59")
    if counts["total"]:
        return (str(counts["total"]) + " OSV match" + ("es" if counts["total"] != 1 else ""), "#a25c16")
    return ("0 OSV matches", "#26708a")


def badge_svg(component, view=None, unavailable=False):
    """Create a script-free SVG whose wording cannot be mistaken for a safety claim."""
    component = exact_component(component)
    label = component["ecosystem"] + " · " + component["name"]
    if len(label) > 34:
        label = label[:33] + "…"
    if unavailable:
        status, color = "source unavailable", "#626b78"
        title = "OSV evidence is temporarily unavailable for " + component["name"] + " " + component["version"]
    else:
        status, color = badge_status(view)
        title = ("MasterMonk OSV evidence for " + component["ecosystem"] + " " + component["name"] + " " +
                 component["version"] + ": " + status + ". Checked " + str(view.get("checkedAt") or "time not supplied") + ".")
    left_width = max(112, min(270, 22 + len(label) * 7))
    right_width = max(116, min(260, 24 + len(status) * 7))
    width = left_width + right_width
    esc = lambda value: html.escape(str(value), quote=True)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{esc(title)}" width="{width}" height="28" viewBox="0 0 {width} 28">'
            f'<title>{esc(title)}</title><rect width="{left_width}" height="28" rx="5" fill="#101b31"/>'
            f'<rect x="{left_width}" width="{right_width}" height="28" rx="5" fill="{color}"/>'
            f'<path d="M{left_width} 0h5v28h-5z" fill="{color}"/>'
            f'<text x="{left_width/2:.1f}" y="18" text-anchor="middle" fill="#f0f5ff" font-family="Arial, sans-serif" font-size="12">{esc(label)}</text>'
            f'<text x="{left_width + right_width/2:.1f}" y="18" text-anchor="middle" fill="#fff" font-family="Arial, sans-serif" font-size="12">{esc(status)}</text></svg>')


class ComponentEvidence:
    """Small time-bounded cache around the actual OSV package query."""
    def __init__(self, ingestor, ttl=CACHE_SECONDS):
        self.ingestor, self.ttl = ingestor, max(1, int(ttl))
        self.lock, self.cache = threading.RLock(), {}

    def query(self, values):
        component = exact_component(values)
        key = tuple(component[name] for name in ("ecosystem", "name", "version"))
        stamp = time.monotonic()
        with self.lock:
            cached = self.cache.get(key)
            if cached and stamp - cached[0] < self.ttl:
                return copy.deepcopy(cached[1])
        result = package_view(self.ingestor.package(component["ecosystem"], component["name"], component["version"]))
        with self.lock:
            self.cache[key] = (stamp, result)
            if len(self.cache) > MAX_CACHE_ITEMS:
                for old_key, _value in sorted(self.cache.items(), key=lambda item: item[1][0])[:len(self.cache)-MAX_CACHE_ITEMS]:
                    self.cache.pop(old_key, None)
        return copy.deepcopy(result)

    def compare(self, left, right):
        left_component, right_component = exact_component(left), exact_component(right)
        left_view = self.query(left_component)
        right_view = left_view if left_component == right_component else self.query(right_component)
        return compare_views(left_view, copy.deepcopy(right_view))
