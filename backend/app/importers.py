from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from sqlalchemy.orm import Session

from .models import Asset, Finding, ThreatIntel
from .scoring import score_vulnerability

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(value: str | None) -> list[str]:
    if not value:
        return []
    return sorted({match.upper() for match in CVE_REGEX.findall(value)})


def get_or_create_asset(
    db: Session,
    *,
    hostname: str,
    ip_address: str | None = None,
    exposure: str = "internal",
    business_criticality: int = 3,
    environment: str = "production",
) -> Asset:
    asset = db.query(Asset).filter(Asset.hostname == hostname).first()
    if asset:
        if ip_address and not asset.ip_address:
            asset.ip_address = ip_address
        return asset
    asset = Asset(
        hostname=hostname,
        ip_address=ip_address,
        exposure=exposure,
        business_criticality=business_criticality,
        environment=environment,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def upsert_finding(db: Session, *, asset: Asset, intel: ThreatIntel | None, data: dict[str, Any]) -> Finding:
    existing = (
        db.query(Finding)
        .filter(
            Finding.asset_id == asset.id,
            Finding.cve == data["cve"],
            Finding.scanner_plugin_id == data.get("scanner_plugin_id"),
        )
        .first()
    )
    finding = existing or Finding(asset_id=asset.id)
    finding.threat_intel_id = intel.id if intel else None
    finding.cve = data["cve"]
    finding.title = data.get("title") or data["cve"]
    finding.scanner = data.get("scanner") or "manual"
    finding.scanner_plugin_id = data.get("scanner_plugin_id")
    finding.cvss_score = float(data.get("cvss_score") or 0.0)
    finding.severity = data.get("severity") or "unknown"
    finding.port = data.get("port")
    finding.service = data.get("service")
    finding.exploit_maturity = data.get("exploit_maturity") or "none"
    finding.exploit_available = bool(data.get("exploit_available", False))
    finding.description = data.get("description")
    finding.recommendation = data.get("recommendation")

    score = score_vulnerability(
        cvss_score=finding.cvss_score,
        epss_score=intel.epss_score if intel else None,
        is_kev=intel.is_kev if intel else False,
        exploit_maturity=finding.exploit_maturity,
        exploit_available=finding.exploit_available,
        exposure=asset.exposure,
        business_criticality=asset.business_criticality,
        known_ransomware=intel.kev_known_ransomware if intel else None,
    )
    finding.risk_score = score.risk_score
    finding.risk_rating = score.risk_rating
    finding.sla = score.sla
    finding.priority_reason = score.priority_reason
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def parse_nuclei_jsonl(content: bytes) -> list[dict[str, Any]]:
    """Parse nuclei -jsonl output.

    Expected fields can include: host, ip, matched-at, template-id, info.name,
    info.severity, info.classification.cve-id, info.classification.cvss-score, port, type.
    """
    records: list[dict[str, Any]] = []
    for line in content.decode("utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cve_field = classification.get("cve-id") or info.get("tags") or item.get("matcher-name") or item.get("template-id")
        cves = extract_cves(str(cve_field))
        if not cves:
            continue
        tags = str(info.get("tags", "")).lower()
        exploit_maturity = "public" if "kev" in tags or "rce" in tags else "poc" if "cve" in tags else "none"
        for cve in cves:
            records.append(
                {
                    "hostname": item.get("host") or item.get("matched-at") or item.get("ip") or "unknown-host",
                    "ip_address": item.get("ip"),
                    "cve": cve,
                    "title": info.get("name") or item.get("template-id") or cve,
                    "scanner": "nuclei",
                    "scanner_plugin_id": item.get("template-id"),
                    "cvss_score": float(classification.get("cvss-score") or 0.0),
                    "severity": info.get("severity") or "unknown",
                    "port": str(item.get("port")) if item.get("port") else None,
                    "service": item.get("type") or item.get("scheme"),
                    "exploit_maturity": exploit_maturity,
                    "exploit_available": exploit_maturity in {"poc", "public"},
                    "description": info.get("description"),
                    "recommendation": info.get("remediation") or info.get("reference"),
                }
            )
    return records


def parse_openvas_csv(content: bytes) -> list[dict[str, Any]]:
    """Parse common OpenVAS/GVM CSV exports.

    Supported columns: Host, IP, Port, NVT Name, CVEs, CVSS, Severity, Solution.
    Column names are normalized so minor export differences still work.
    """
    text = content.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    records: list[dict[str, Any]] = []
    for row in reader:
        normalized = {k.strip().lower(): v for k, v in row.items() if k}
        cves = extract_cves(" ".join(str(v) for v in normalized.values()))
        if not cves:
            continue
        hostname = normalized.get("host") or normalized.get("hostname") or normalized.get("ip") or "unknown-host"
        cvss = normalized.get("cvss") or normalized.get("cvss base") or normalized.get("cvss base score") or 0
        for cve in cves:
            records.append(
                {
                    "hostname": hostname,
                    "ip_address": normalized.get("ip") or normalized.get("host"),
                    "cve": cve,
                    "title": normalized.get("nvt name") or normalized.get("name") or cve,
                    "scanner": "openvas",
                    "scanner_plugin_id": normalized.get("nvt oid") or normalized.get("oid"),
                    "cvss_score": float(cvss or 0.0),
                    "severity": normalized.get("severity") or "unknown",
                    "port": normalized.get("port"),
                    "service": normalized.get("service"),
                    "exploit_maturity": "none",
                    "exploit_available": False,
                    "description": normalized.get("summary") or normalized.get("description"),
                    "recommendation": normalized.get("solution"),
                }
            )
    return records
