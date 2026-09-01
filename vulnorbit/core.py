"""Canonical records and explainable triage. No generated vulnerability data."""
from __future__ import annotations
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

SOURCE_META = {
    "cisa": {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
             "coverage": "Complete official Known Exploited Vulnerabilities catalog."},
    "nvd": {"name": "NVD", "url": "https://nvd.nist.gov/",
            "coverage": "KEV enrichment and paginated, incremental modified-CVE imports."},
    "epss": {"name": "FIRST EPSS", "url": "https://www.first.org/epss/",
             "coverage": "Daily exploitation probabilities for the tracked CVEs."},
    "github": {"name": "GitHub Advisory Database", "url": "https://github.com/advisories",
               "coverage": "Reviewed advisories, affected package ranges, and fixed releases."},
    "cve": {"name": "CVE / CNA", "url": "https://www.cve.org/",
            "coverage": "Publisher records and vendor references; refreshed on investigation."},
    "osv": {"name": "OSV", "url": "https://osv.dev/",
            "coverage": "Exact package/version queries and advisory enrichment on demand."},
}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
FIELDS = ("title", "description", "vendor", "product", "cvss", "vector", "cwes",
          "kev", "kevAdded", "ransomware", "requiredAction", "dueDate", "epss",
          "percentile", "epssDate", "packages", "references", "withdrawn", "aliases")

def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def timestamp(value) -> str | None:
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None

def number(value, maximum=10) -> float | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        value = float(value)
        return value if math.isfinite(value) and 0 <= value <= maximum else None
    except (TypeError, ValueError):
        return None

def text(value, limit=6000) -> str:
    return value[:limit] if isinstance(value, str) else ""

def array(value) -> list:
    return value if isinstance(value, list) else []

def safe_url(value) -> str | None:
    if not isinstance(value, str) or len(value) > 3000:
        return None
    try:
        p = urlsplit(value)
        if p.scheme in ("https", "http") and p.hostname and not p.username and not p.password:
            return value
    except ValueError:
        pass
    return None

def refs(url, kind, source):
    return [{"url": url, "kind": kind, "source": source}] if safe_url(url) else []

def unique(values, key=lambda x: json.dumps(x, sort_keys=True)):
    result = {}
    for item in values:
        result[key(item)] = item
    return list(result.values())

def severity(score):
    if score is None:
        return "Unknown"
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "None"

def priority(v: dict) -> dict:
    reasons, missing = [], []
    if v.get("withdrawn"):
        return {"score": 0, "band": "Verify record",
                "reasons": [{"label": "The authoritative record is rejected or withdrawn; inspect source status.", "points": 0}],
                "missing": [], "model": "vulnorbit-1"}
    if v.get("kev"):
        reasons.append({"label": "CISA confirms known exploitation", "points": 60})
    if v.get("ransomware") == "Known":
        reasons.append({"label": "CISA reports known ransomware use", "points": 10})
    cvss = number(v.get("cvss"))
    if cvss is None:
        missing.append("CVSS")
    else:
        reasons.append({"label": f"CVSS {cvss:g} x 2 (rounded)", "points": math.floor(cvss * 2 + 0.5)})
    epss = number(v.get("epss"), 1)
    if epss is None:
        missing.append("EPSS")
    else:
        points = 15 if epss >= 0.5 else 10 if epss >= 0.1 else 5 if epss >= 0.01 else 0
        reasons.append({"label": f"EPSS {epss * 100:.2f}% probability", "points": points})
    if any(r.get("kind") == "exploit" for r in v.get("references", [])):
        reasons.append({"label": "Source-tagged exploit reference; not execution-verified", "points": 5})
    score = min(100, sum(r["points"] for r in reasons))
    return {"score": score,
            "band": "Act now" if v.get("kev") else "Investigate" if score >= 30 else "Review" if score >= 14 else "Monitor",
            "reasons": reasons, "missing": missing, "model": "vulnorbit-1"}

def merge(signals: list[dict]) -> dict:
    if not signals:
        raise ValueError("A real source observation is required.")
    ordering = {"cve": 0, "nvd": 1, "github": 2, "osv": 3, "cisa": 4, "epss": 5}
    ordered = sorted(signals, key=lambda x: (ordering.get(x["source"], 10), x.get("key", "")))
    primary = [x for x in ordered if x["source"] not in ("epss", "cisa")]
    kev = next((x for x in signals if x["source"] == "cisa"), {})
    ep = max((x for x in signals if x["source"] == "epss"), key=lambda x: x.get("epssDate") or "", default={})
    metric = next((x for x in ordered if number(x.get("cvss")) is not None), {})
    authority = next((x for x in ordered if x["source"] in ("cve", "nvd")), None)
    withdrawn = bool(authority.get("withdrawn")) if authority else bool(primary and all(x.get("withdrawn") for x in primary))
    publications = sorted(x["published"] for x in primary if x.get("published"))
    updates = sorted(x["modified"] for x in primary if x.get("modified"))
    def pick(field, default=None):
        return next((x[field] for x in ordered if x.get(field)), default)
    title = next((x.get("title") for source in ("github", "cve", "cisa", "osv", "nvd")
                  for x in ordered if x["source"] == source and x.get("title")), signals[0]["id"])
    record = {
        "id": signals[0]["id"], "title": title, "description": pick("description", "No description supplied."),
        "vendor": kev.get("vendor") or pick("vendor", "Unspecified"),
        "product": kev.get("product") or pick("product", "Unspecified"),
        "published": publications[0] if publications else None,
        "modified": updates[-1] if updates else None,
        "cvss": number(metric.get("cvss")), "cvssSource": metric.get("source"), "vector": metric.get("vector"),
        "severity": severity(number(metric.get("cvss"))),
        "cwes": sorted({c for x in signals for c in x.get("cwes", []) if isinstance(c, str) and re.fullmatch(r"CWE-\d+", c)}),
        "kev": kev.get("kev") is True, "kevAdded": kev.get("kevAdded"), "dueDate": kev.get("dueDate"),
        "ransomware": kev.get("ransomware") or "Unknown", "requiredAction": kev.get("requiredAction"),
        "epss": number(ep.get("epss"), 1), "percentile": number(ep.get("percentile"), 1), "epssDate": ep.get("epssDate"),
        "references": unique([r for x in signals for r in x.get("references", []) if safe_url(r.get("url"))],
                             lambda r: r["url"] + "|" + r["kind"]),
        "packages": unique([p for x in ordered if not x.get("withdrawn") for p in x.get("packages", [])]),
        "aliases": sorted({a for x in signals for a in x.get("aliases", []) if isinstance(a, str)}),
        "sources": [{"id": x["source"], "url": x["url"], "observedAt": x["observedAt"],
                     "modified": x.get("modified"), "key": x.get("key", x["id"]),
                     "cvss": x.get("cvss"), "withdrawn": x.get("withdrawn", False)} for x in ordered],
        "withdrawn": withdrawn, "conflicts": [],
    }
    scores = {x["cvss"] for x in ordered if number(x.get("cvss")) is not None}
    if len(scores) > 1:
        record["conflicts"].append("Sources supply different CVSS scores. The displayed metric prefers CVE/CNA, then NVD, then GitHub.")
    if withdrawn and record["kev"]:
        record["conflicts"].append("A rejected/withdrawn record also appears in KEV. Verify the source records before acting.")
    record["priority"] = priority(record)
    return record

def summary(record):
    keys = ("id", "title", "vendor", "product", "published", "modified", "cvss", "cvssSource",
            "severity", "cwes", "kev", "kevAdded", "ransomware", "epss", "epssDate", "withdrawn", "aliases")
    result = {k: record.get(k) for k in keys}
    result["priority"] = record["priority"]
    result["sourceIds"] = sorted({s["id"] for s in record["sources"]})
    result["packageCount"] = len(record["packages"])
    result["exploitReferences"] = sum(r["kind"] == "exploit" for r in record["references"])
    return result

def differences(before, after):
    return [{"field": f, "before": before.get(f), "after": after.get(f)}
            for f in FIELDS if before.get(f) != after.get(f)]
