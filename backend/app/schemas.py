from datetime import datetime
from pydantic import BaseModel, Field


class AssetBase(BaseModel):
    hostname: str
    ip_address: str | None = None
    environment: str = "production"
    exposure: str = Field(default="internal", description="internet, dmz, internal, or dev")
    business_criticality: int = Field(default=3, ge=1, le=5)
    owner: str | None = None


class AssetCreate(AssetBase):
    pass


class AssetOut(AssetBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatIntelOut(BaseModel):
    cve: str
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_vendor_project: str | None = None
    kev_product: str | None = None
    kev_known_ransomware: str | None = None
    kev_due_date: str | None = None
    kev_short_description: str | None = None
    last_checked_at: datetime | None = None

    class Config:
        from_attributes = True


class FindingCreate(BaseModel):
    asset_id: int
    cve: str
    title: str
    scanner: str = "manual"
    scanner_plugin_id: str | None = None
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity: str = "unknown"
    port: str | None = None
    service: str | None = None
    exploit_maturity: str = "none"
    exploit_available: bool = False
    description: str | None = None
    recommendation: str | None = None
    enrich_live: bool = False


class FindingOut(BaseModel):
    id: int
    asset: AssetOut
    threat_intel: ThreatIntelOut | None = None
    cve: str
    title: str
    scanner: str
    scanner_plugin_id: str | None
    cvss_score: float
    severity: str
    port: str | None
    service: str | None
    exploit_maturity: str
    exploit_available: bool
    description: str | None
    recommendation: str | None
    risk_score: float
    risk_rating: str
    sla: str
    priority_reason: str
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScorePreviewRequest(BaseModel):
    cvss_score: float = Field(ge=0.0, le=10.0)
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    is_kev: bool = False
    exploit_maturity: str = "none"
    exploit_available: bool = False
    exposure: str = "internal"
    business_criticality: int = Field(default=3, ge=1, le=5)
    known_ransomware: str | None = None


class ScorePreviewOut(BaseModel):
    risk_score: float
    risk_rating: str
    sla: str
    priority_reason: str
    components: dict


class StatsOut(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    kev_count: int
    internet_exposed_count: int
    top_assets: list[dict]
