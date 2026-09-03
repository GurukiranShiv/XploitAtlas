"""Small, validated records derived only from authoritative upstream payloads."""
from __future__ import annotations
import re
from core import CVE_RE, array, number, refs, text, timestamp

def base(identifier, source, url, observed, key=None):
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._-]{3,120}", identifier):
        raise ValueError("Invalid upstream record identifier.")
    return {"id": identifier, "key": key or identifier, "source": source, "url": url, "observedAt": observed}

def cisa(data, observed, url):
    rows = data.get("vulnerabilities")
    if not isinstance(rows, list) or not rows or data.get("count") != len(rows):
        raise ValueError("CISA sent an empty, incomplete, or invalid catalog; previous evidence retained.")
    if any(not isinstance(v, dict) or not CVE_RE.fullmatch(v.get("cveID", "")) for v in rows):
        raise ValueError("Invalid CISA catalog entry; no catalog removals applied.")
    if len({v["cveID"] for v in rows}) != len(rows):
        raise ValueError("Duplicate identifiers in CISA response.")
    result = []
    for v in rows:
        r = base(v["cveID"], "cisa", url, observed)
        r.update(title=text(v.get("vulnerabilityName"), 500), description=text(v.get("shortDescription")),
                 vendor=text(v.get("vendorProject"), 160), product=text(v.get("product"), 200),
                 kev=True, kevAdded=timestamp(v.get("dateAdded")), dueDate=timestamp(v.get("dueDate")),
                 ransomware=text(v.get("knownRansomwareCampaignUse")) or "Unknown",
                 requiredAction=text(v.get("requiredAction")), cwes=array(v.get("cwes")),
                 references=[ref for u in re.findall(r"https?://[^\s;<>]+", text(v.get("notes")))
                             for ref in refs(u.rstrip(").,"), "reference", "cisa")])
        result.append(r)
    return result

def nvd(data, observed, url):
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("NVD returned an invalid response.")
    result = []
    for item in data["vulnerabilities"]:
        v = item.get("cve", {})
        identifier = v.get("id", "")
        if not CVE_RE.fullmatch(identifier):
            raise ValueError("NVD entry has no valid CVE ID.")
        r = base(identifier, "nvd", f"https://nvd.nist.gov/vuln/detail/{identifier}", observed)
        metrics = v.get("metrics") or {}
        selected = {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            choices = array(metrics.get(key))
            if choices:
                selected = next((m for m in choices if m.get("type") == "Primary"), choices[0]).get("cvssData", {})
                break
        description = next((text(d.get("value")) for d in array(v.get("descriptions")) if d.get("lang") == "en"), "")
        products = [m.get("criteria", "").split(":") for c in array(v.get("configurations"))
                    for n in array(c.get("nodes")) for m in array(n.get("cpeMatch")) if m.get("vulnerable")]
        product = next((p for p in products if len(p) > 4), [])
        references = []
        for ref in array(v.get("references")):
            tags = array(ref.get("tags"))
            kind = "exploit" if "Exploit" in tags else "patch" if "Patch" in tags else "advisory" if "Vendor Advisory" in tags else "reference"
            references += refs(ref.get("url"), kind, "nvd")
        references.sort(key=lambda x: {"exploit": 0, "patch": 1, "advisory": 2, "reference": 3}[x["kind"]])
        r.update(title=re.split(r"(?<=[.!?])\s", description)[0][:240], description=description,
                 published=timestamp(v.get("published")), modified=timestamp(v.get("lastModified")),
                 vendor=product[3].replace("_", " ") if product else "", product=product[4].replace("_", " ") if product else "",
                 cvss=number(selected.get("baseScore")), vector=text(selected.get("vectorString")) or None,
                 cwes=[d.get("value") for w in array(v.get("weaknesses")) for d in array(w.get("description"))],
                 references=references[:40], withdrawn=v.get("vulnStatus") == "Rejected")
        result.append(r)
    return result

def github(data, observed, url):
    if not isinstance(data, list):
        raise ValueError("GitHub returned an invalid advisory list.")
    result = []
    for g in data:
        gid = g.get("ghsa_id")
        r = base(g.get("cve_id") or gid, "github", g["html_url"], observed, key=gid)
        packages = []
        for p in array(g.get("vulnerabilities")):
            patch = p.get("first_patched_version")
            if isinstance(patch, dict):
                patch = patch.get("identifier")
            packages.append({"name": text(p.get("package", {}).get("name"), 200),
                             "ecosystem": text(p.get("package", {}).get("ecosystem"), 80),
                             "affected": text(p.get("vulnerable_version_range"), 1000),
                             "fixed": text(patch, 300) or None, "source": "github", "url": g["html_url"]})
        metric_options = [(g.get("cvss_severities") or {}).get("cvss_v4") or {},
                          (g.get("cvss_severities") or {}).get("cvss_v3") or {}, g.get("cvss") or {}]
        metric = next((m for m in metric_options if number(m.get("score")) is not None), {})
        r.update(title=text(g.get("summary"), 500), description=text(g.get("description")),
                 published=timestamp(g.get("published_at")), modified=timestamp(g.get("updated_at")),
                 cvss=number(metric.get("score")), vector=text(metric.get("vector_string")) or None,
                 vendor=packages[0]["ecosystem"] if packages else "", product=packages[0]["name"] if packages else "",
                 cwes=[c.get("cwe_id") for c in array(g.get("cwes"))], withdrawn=bool(g.get("withdrawn_at")),
                 aliases=[i["value"] for i in array(g.get("identifiers")) if isinstance(i.get("value"), str)],
                 packages=packages, references=(refs(g["html_url"], "advisory", "github") +
                 [r for u in array(g.get("references")) for r in refs(u, "reference", "github")])[:40])
        result.append(r)
    return result

def epss(data, observed, url):
    if not isinstance(data.get("data"), list):
        raise ValueError("FIRST returned an invalid EPSS response.")
    result = []
    for e in data["data"]:
        if not CVE_RE.fullmatch(e.get("cve", "")):
            raise ValueError("Invalid CVE in EPSS response.")
        r = base(e["cve"], "epss", "https://api.first.org/data/v1/epss?cve=" + e["cve"], observed)
        r.update(epss=number(e.get("epss"), 1), percentile=number(e.get("percentile"), 1),
                 epssDate=text(e.get("date"), 10), modified=timestamp(e.get("date")))
        result.append(r)
    return result

def cve(data, observed, url):
    meta, cna = data.get("cveMetadata", {}), data.get("containers", {}).get("cna", {})
    identifier = meta.get("cveId", "")
    if not CVE_RE.fullmatch(identifier):
        raise ValueError("CVE publisher returned an invalid identifier.")
    r = base(identifier, "cve", "https://www.cve.org/CVERecord?id=" + identifier, observed)
    metric = {}
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        metric = next((m[key] for m in array(cna.get("metrics")) if key in m), {})
        if metric:
            break
    affected = array(cna.get("affected"))
    references = []
    for ref in array(cna.get("references")):
        tags = array(ref.get("tags"))
        kind = "exploit" if "exploit" in tags else "patch" if "patch" in tags else "advisory" if "vendor-advisory" in tags else "reference"
        references += refs(ref.get("url"), kind, "cve")
    packages = []
    for p in affected:
        versions = [v for v in array(p.get("versions")) if v.get("status") == "affected"]
        ranges = "; ".join(text(v.get("version"), 120) +
                           (" < " + text(v["lessThan"], 120) if v.get("lessThan") else
                            " <= " + text(v["lessThanOrEqual"], 120) if v.get("lessThanOrEqual") else "") for v in versions)
        packages.append({"name": text(p.get("packageName") or p.get("product"), 200),
                         "ecosystem": "Vendor product", "affected": ranges[:2000] or "See publisher record",
                         "fixed": None, "source": "cve", "url": r["url"]})
    r.update(title=text(cna.get("title"), 500),
             description=next((text(d.get("value")) for d in array(cna.get("descriptions")) if d.get("lang") == "en"), ""),
             published=timestamp(meta.get("datePublished")), modified=timestamp(meta.get("dateUpdated")),
             vendor=text(affected[0].get("vendor"), 160) if affected else "",
             product=text(affected[0].get("product"), 200) if affected else "",
             cvss=number(metric.get("baseScore")), vector=text(metric.get("vectorString")) or None,
             cwes=[d.get("cweId") for p in array(cna.get("problemTypes")) for d in array(p.get("descriptions"))],
             withdrawn=meta.get("state") == "REJECTED", references=references[:40], packages=packages[:40])
    return [r]

def osv(data, observed, url):
    identifier = next((x for x in array(data.get("aliases")) if isinstance(x, str) and CVE_RE.fullmatch(x)), data.get("id"))
    r = base(identifier, "osv", "https://osv.dev/vulnerability/" + str(data.get("id", "")), observed, data.get("id"))
    packages = []
    for affected in array(data.get("affected")):
        ranges, fixed = [], []
        for ran in array(affected.get("ranges")):
            events = []
            for event in array(ran.get("events")):
                for kind in ("introduced", "fixed", "last_affected", "limit"):
                    if kind in event:
                        events.append(f"{kind}: {text(event[kind], 120)}")
                        if kind == "fixed":
                            fixed.append(text(event[kind], 120))
            ranges.append(text(ran.get("type"), 40) + " [" + " -> ".join(events) + "]")
        packages.append({"name": text(affected.get("package", {}).get("name"), 200),
                         "ecosystem": text(affected.get("package", {}).get("ecosystem"), 80),
                         "affected": ("; ".join(ranges) or ", ".join(array(affected.get("versions"))[:50]))[:2400],
                         "fixed": ", ".join(dict.fromkeys(fixed)) or None, "source": "osv", "url": r["url"]})
    r.update(title=text(data.get("summary"), 500), description=text(data.get("details")),
             published=timestamp(data.get("published")), modified=timestamp(data.get("modified")),
             aliases=array(data.get("aliases")) + [data["id"]], withdrawn=bool(data.get("withdrawn")),
             vendor=packages[0]["ecosystem"] if packages else "", product=packages[0]["name"] if packages else "",
             packages=packages[:50], references=[r for x in array(data.get("references"))
                 for r in refs(x.get("url"), "patch" if x.get("type") == "FIX" else
                               "advisory" if x.get("type") == "ADVISORY" else "reference", "osv")][:40])
    return [r]
