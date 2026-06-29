from __future__ import annotations

from collections import Counter

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func
from sqlalchemy.orm import Session, joinedload

from .database import Base, engine, get_db
from .enrichment import enrich_cve, upsert_offline_intel
from .importers import get_or_create_asset, parse_nuclei_jsonl, parse_openvas_csv, upsert_finding
from .models import Asset, Finding, ThreatIntel
from .schemas import (
    AssetCreate,
    AssetOut,
    FindingCreate,
    FindingOut,
    ScorePreviewOut,
    ScorePreviewRequest,
    StatsOut,
    ThreatIntelOut,
)
from .scoring import score_vulnerability

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Exploit-Aware Vulnerability Prioritization Platform",
    description="Ranks vulnerabilities using CVSS, EPSS, CISA KEV, exploit maturity, exposure, and asset criticality.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "vuln-prioritizer"}


@app.post("/assets", response_model=AssetOut)
def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    db_asset = Asset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@app.get("/assets", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.hostname).all()


@app.post("/intel/{cve}", response_model=ThreatIntelOut)
async def enrich_single_cve(cve: str, force_refresh: bool = False, db: Session = Depends(get_db)):
    try:
        return await enrich_cve(db, cve, force_refresh=force_refresh)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Threat-intel enrichment failed: {exc}") from exc


@app.post("/score-preview", response_model=ScorePreviewOut)
def score_preview(request: ScorePreviewRequest):
    return score_vulnerability(**request.model_dump()).__dict__


@app.post("/findings", response_model=FindingOut)
async def create_finding(payload: FindingCreate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == payload.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    intel = None
    if payload.enrich_live:
        try:
            intel = await enrich_cve(db, payload.cve)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Threat-intel enrichment failed: {exc}") from exc
    else:
        intel = db.query(ThreatIntel).filter(ThreatIntel.cve == payload.cve.upper()).first()

    finding = upsert_finding(db, asset=asset, intel=intel, data=payload.model_dump())
    return (
        db.query(Finding)
        .options(joinedload(Finding.asset), joinedload(Finding.threat_intel))
        .filter(Finding.id == finding.id)
        .first()
    )


@app.get("/findings", response_model=list[FindingOut])
def list_findings(
    db: Session = Depends(get_db),
    rating: str | None = Query(default=None, description="Critical, High, Medium, Low"),
    kev_only: bool = False,
    internet_exposed_only: bool = False,
    limit: int = Query(default=100, le=500),
):
    query = db.query(Finding).options(joinedload(Finding.asset), joinedload(Finding.threat_intel))
    if rating:
        query = query.filter(Finding.risk_rating == rating)
    if kev_only:
        query = query.join(ThreatIntel, Finding.threat_intel_id == ThreatIntel.id).filter(ThreatIntel.is_kev.is_(True))
    if internet_exposed_only:
        query = query.join(Asset).filter(Asset.exposure.in_(["internet", "external", "dmz"]))
    return query.order_by(desc(Finding.risk_score)).limit(limit).all()


@app.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = (
        db.query(Finding)
        .options(joinedload(Finding.asset), joinedload(Finding.threat_intel))
        .filter(Finding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def import_records(db: Session, records: list[dict], live_enrich: bool) -> dict:
    imported = []
    errors = []
    for record in records:
        try:
            asset = get_or_create_asset(
                db,
                hostname=record.pop("hostname"),
                ip_address=record.pop("ip_address", None),
                exposure=record.pop("exposure", "internal"),
                business_criticality=int(record.pop("business_criticality", 3)),
                environment=record.pop("environment", "production"),
            )
            if live_enrich:
                intel = await enrich_cve(db, record["cve"])
            else:
                intel = db.query(ThreatIntel).filter(ThreatIntel.cve == record["cve"].upper()).first()
            finding = upsert_finding(db, asset=asset, intel=intel, data=record)
            imported.append(finding.id)
        except Exception as exc:  # keep import resilient for messy scanner exports
            errors.append({"record": record, "error": str(exc)})
    return {"imported_count": len(imported), "finding_ids": imported, "errors": errors}


@app.post("/import/nuclei")
async def import_nuclei(
    file: UploadFile = File(...),
    live_enrich: bool = Query(default=False, description="Fetch EPSS/KEV live during import"),
    default_exposure: str = "internal",
    default_business_criticality: int = 3,
    db: Session = Depends(get_db),
):
    content = await file.read()
    records = parse_nuclei_jsonl(content)
    for record in records:
        record["exposure"] = default_exposure
        record["business_criticality"] = default_business_criticality
    return await import_records(db, records, live_enrich)


@app.post("/import/openvas")
async def import_openvas(
    file: UploadFile = File(...),
    live_enrich: bool = Query(default=False, description="Fetch EPSS/KEV live during import"),
    default_exposure: str = "internal",
    default_business_criticality: int = 3,
    db: Session = Depends(get_db),
):
    content = await file.read()
    records = parse_openvas_csv(content)
    for record in records:
        record["exposure"] = default_exposure
        record["business_criticality"] = default_business_criticality
    return await import_records(db, records, live_enrich)


@app.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Finding.id)).scalar() or 0
    counts = Counter(r for (r,) in db.query(Finding.risk_rating).all())
    kev_count = (
        db.query(func.count(Finding.id))
        .join(ThreatIntel, Finding.threat_intel_id == ThreatIntel.id)
        .filter(ThreatIntel.is_kev.is_(True))
        .scalar()
        or 0
    )
    internet_count = (
        db.query(func.count(Finding.id))
        .join(Asset)
        .filter(Asset.exposure.in_(["internet", "external", "dmz"]))
        .scalar()
        or 0
    )
    top_assets_query = (
        db.query(Asset.hostname, func.count(Finding.id).label("finding_count"), func.max(Finding.risk_score).label("max_score"))
        .join(Finding)
        .group_by(Asset.hostname)
        .order_by(desc("max_score"))
        .limit(5)
        .all()
    )
    return {
        "total_findings": total,
        "critical": counts.get("Critical", 0),
        "high": counts.get("High", 0),
        "medium": counts.get("Medium", 0),
        "low": counts.get("Low", 0),
        "kev_count": kev_count,
        "internet_exposed_count": internet_count,
        "top_assets": [
            {"hostname": row.hostname, "finding_count": row.finding_count, "max_score": float(row.max_score or 0)}
            for row in top_assets_query
        ],
    }


def _seed_sample_data(db: Session) -> dict:
    """Load offline sample findings so the project works even without internet."""
    app1 = get_or_create_asset(
        db,
        hostname="prod-web-01",
        ip_address="10.10.10.21",
        exposure="internet",
        business_criticality=5,
    )
    app2 = get_or_create_asset(
        db,
        hostname="internal-jira-01",
        ip_address="10.10.20.15",
        exposure="internal",
        business_criticality=4,
    )
    dev = get_or_create_asset(
        db,
        hostname="dev-api-01",
        ip_address="10.10.40.33",
        exposure="dev",
        business_criticality=2,
    )

    sample_intel = {
        "CVE-2021-44228": {"epss_score": 0.944, "epss_percentile": 0.999, "is_kev": True, "known_ransomware": "Known"},
        "CVE-2023-34362": {"epss_score": 0.972, "epss_percentile": 0.999, "is_kev": True, "known_ransomware": "Known"},
        "CVE-2022-22965": {"epss_score": 0.923, "epss_percentile": 0.998, "is_kev": True, "known_ransomware": "Unknown"},
        "CVE-2024-12345": {"epss_score": 0.081, "epss_percentile": 0.610, "is_kev": False, "known_ransomware": None},
    }
    intel_objects = {cve: upsert_offline_intel(db, cve=cve, **values) for cve, values in sample_intel.items()}

    findings = [
        {
            "asset": app1,
            "intel": intel_objects["CVE-2021-44228"],
            "data": {
                "cve": "CVE-2021-44228",
                "title": "Apache Log4j Remote Code Execution",
                "scanner": "nuclei",
                "scanner_plugin_id": "apache-log4j-rce",
                "cvss_score": 10.0,
                "severity": "critical",
                "port": "443",
                "service": "https",
                "exploit_maturity": "weaponized",
                "exploit_available": True,
                "description": "Internet-facing Log4j indicator detected on production web server.",
                "recommendation": "Upgrade Log4j, validate dependency tree, rotate secrets if exploitation is suspected.",
            },
        },
        {
            "asset": app1,
            "intel": intel_objects["CVE-2023-34362"],
            "data": {
                "cve": "CVE-2023-34362",
                "title": "MOVEit Transfer SQL Injection",
                "scanner": "openvas",
                "scanner_plugin_id": "moveit-sqli",
                "cvss_score": 9.8,
                "severity": "critical",
                "port": "443",
                "service": "https",
                "exploit_maturity": "weaponized",
                "exploit_available": True,
                "description": "Detected vulnerable MOVEit pattern on exposed service.",
                "recommendation": "Isolate server, patch immediately, review data-exfiltration indicators.",
            },
        },
        {
            "asset": app2,
            "intel": intel_objects["CVE-2022-22965"],
            "data": {
                "cve": "CVE-2022-22965",
                "title": "Spring4Shell Remote Code Execution",
                "scanner": "openvas",
                "scanner_plugin_id": "spring4shell-check",
                "cvss_score": 9.8,
                "severity": "critical",
                "port": "8080",
                "service": "http",
                "exploit_maturity": "public",
                "exploit_available": True,
                "description": "Internal application exposes a vulnerable Spring Framework component.",
                "recommendation": "Upgrade Spring Framework and validate servlet container constraints.",
            },
        },
        {
            "asset": dev,
            "intel": intel_objects["CVE-2024-12345"],
            "data": {
                "cve": "CVE-2024-12345",
                "title": "Example low-context library vulnerability",
                "scanner": "manual",
                "scanner_plugin_id": "sample-low-priority",
                "cvss_score": 9.1,
                "severity": "critical",
                "port": "8081",
                "service": "http",
                "exploit_maturity": "none",
                "exploit_available": False,
                "description": "High CVSS but low EPSS, no KEV, and only present on low-criticality dev asset.",
                "recommendation": "Plan remediation in normal sprint unless exposure changes.",
            },
        },
    ]

    ids = []
    for item in findings:
        finding = upsert_finding(db, asset=item["asset"], intel=item["intel"], data=item["data"])
        ids.append(finding.id)
    return {"seeded_findings": ids, "message": "Sample scanner findings loaded. Open /docs or the frontend dashboard."}


@app.post("/seed-sample-data")
def seed_sample_data(db: Session = Depends(get_db)):
    return _seed_sample_data(db)
