from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .models import ThreatIntel

CACHE_TTL_HOURS = 24


async def fetch_epss(cve: str) -> dict[str, Any]:
    """Fetch EPSS score for one CVE from FIRST's free public API."""
    params = {"cve": cve.upper().strip()}
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(settings.epss_api_url, params=params)
        response.raise_for_status()
        payload = response.json()
    data = payload.get("data") or []
    if not data:
        return {"epss_score": None, "epss_percentile": None}
    item = data[0]
    return {
        "epss_score": float(item.get("epss")) if item.get("epss") is not None else None,
        "epss_percentile": float(item.get("percentile")) if item.get("percentile") is not None else None,
    }


async def fetch_kev_catalog() -> dict[str, dict[str, Any]]:
    """Fetch CISA KEV catalog and return lookup by CVE ID."""
    urls = [settings.cisa_kev_url, settings.cisa_kev_github_fallback_url]
    last_error: Exception | None = None
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", [])
            return {v.get("cveID", "").upper(): v for v in vulnerabilities if v.get("cveID")}
        except Exception as exc:  # pragma: no cover - network fallback
            last_error = exc
            continue
    raise RuntimeError(f"Unable to fetch CISA KEV catalog: {last_error}")


async def enrich_cve(db: Session, cve: str, force_refresh: bool = False) -> ThreatIntel:
    """Create/update threat-intelligence cache entry for a CVE."""
    normalized_cve = cve.upper().strip()
    existing = db.query(ThreatIntel).filter(ThreatIntel.cve == normalized_cve).first()
    if (
        existing
        and not force_refresh
        and existing.last_checked_at
        and existing.last_checked_at > datetime.utcnow() - timedelta(hours=CACHE_TTL_HOURS)
    ):
        return existing

    epss_data = await fetch_epss(normalized_cve)
    kev_lookup = await fetch_kev_catalog()
    kev = kev_lookup.get(normalized_cve)

    intel = existing or ThreatIntel(cve=normalized_cve)
    intel.epss_score = epss_data["epss_score"]
    intel.epss_percentile = epss_data["epss_percentile"]
    intel.is_kev = bool(kev)
    intel.last_checked_at = datetime.utcnow()

    if kev:
        intel.kev_vendor_project = kev.get("vendorProject")
        intel.kev_product = kev.get("product")
        intel.kev_known_ransomware = kev.get("knownRansomwareCampaignUse")
        intel.kev_due_date = kev.get("dueDate")
        intel.kev_short_description = kev.get("shortDescription")
    else:
        intel.kev_vendor_project = None
        intel.kev_product = None
        intel.kev_known_ransomware = None
        intel.kev_due_date = None
        intel.kev_short_description = None

    db.add(intel)
    db.commit()
    db.refresh(intel)
    return intel


def upsert_offline_intel(
    db: Session,
    *,
    cve: str,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
    is_kev: bool = False,
    known_ransomware: str | None = None,
) -> ThreatIntel:
    """Use when importing sample/offline data without internet access."""
    normalized_cve = cve.upper().strip()
    intel = db.query(ThreatIntel).filter(ThreatIntel.cve == normalized_cve).first()
    if not intel:
        intel = ThreatIntel(cve=normalized_cve)
    intel.epss_score = epss_score
    intel.epss_percentile = epss_percentile
    intel.is_kev = is_kev
    intel.kev_known_ransomware = known_ransomware
    intel.last_checked_at = datetime.utcnow()
    db.add(intel)
    db.commit()
    db.refresh(intel)
    return intel
