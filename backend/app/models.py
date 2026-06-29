from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[str] = mapped_column(String(64), default="production")
    exposure: Mapped[str] = mapped_column(String(64), default="internal")  # internet, dmz, internal, dev
    business_criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1-5
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_known_ransomware: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kev_short_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="threat_intel")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "cve", "scanner_plugin_id", name="uq_asset_cve_plugin"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    threat_intel_id: Mapped[int | None] = mapped_column(ForeignKey("threat_intel.id"), nullable=True)

    cve: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(500))
    scanner: Mapped[str] = mapped_column(String(64), default="manual")
    scanner_plugin_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(32), default="unknown")
    port: Mapped[str | None] = mapped_column(String(32), nullable=True)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exploit_maturity: Mapped[str] = mapped_column(String(64), default="none")  # none, poc, public, weaponized
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_rating: Mapped[str] = mapped_column(String(32), default="Low", index=True)
    sla: Mapped[str] = mapped_column(String(64), default="90 days")
    priority_reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset: Mapped[Asset] = relationship("Asset", back_populates="findings")
    threat_intel: Mapped[ThreatIntel | None] = relationship("ThreatIntel", back_populates="findings")
