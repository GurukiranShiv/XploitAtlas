from dataclasses import dataclass


EXPOSURE_SCORES = {
    "internet": 100,
    "external": 100,
    "dmz": 80,
    "internal": 50,
    "dev": 30,
    "lab": 20,
}

EXPLOIT_MATURITY_SCORES = {
    "none": 0,
    "unproven": 10,
    "poc": 70,
    "proof-of-concept": 70,
    "public": 85,
    "weaponized": 100,
    "active": 100,
}


@dataclass
class ScoreResult:
    risk_score: float
    risk_rating: str
    sla: str
    priority_reason: str
    components: dict


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def rating(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def remediation_sla(score_rating: str, is_kev: bool, exposure: str) -> str:
    if is_kev and exposure.lower() in {"internet", "external", "dmz"}:
        return "24 hours"
    if is_kev:
        return "72 hours"
    if score_rating == "Critical":
        return "3 days"
    if score_rating == "High":
        return "7 days"
    if score_rating == "Medium":
        return "30 days"
    return "90 days"


def score_vulnerability(
    *,
    cvss_score: float,
    epss_score: float | None,
    is_kev: bool,
    exploit_maturity: str,
    exploit_available: bool,
    exposure: str,
    business_criticality: int,
    known_ransomware: str | None = None,
) -> ScoreResult:
    """Calculate business-aware risk priority.

    This is intentionally explainable for SOC / vulnerability-management interviews.
    It combines technical severity, likelihood of exploitation, confirmed exploitation,
    exposure, asset value, and exploit maturity.
    """

    cvss_norm = clamp((cvss_score or 0) * 10)
    epss_norm = clamp((epss_score or 0) * 100)
    kev_norm = 100 if is_kev else 0
    exposure_norm = EXPOSURE_SCORES.get((exposure or "internal").lower(), 50)
    criticality_norm = clamp(((business_criticality or 3) - 1) / 4 * 100)
    maturity_norm = EXPLOIT_MATURITY_SCORES.get((exploit_maturity or "none").lower(), 0)
    if exploit_available and maturity_norm < 85:
        maturity_norm = 85

    components = {
        "cvss": round(cvss_norm * 0.25, 2),
        "epss": round(epss_norm * 0.25, 2),
        "kev": round(kev_norm * 0.20, 2),
        "exposure": round(exposure_norm * 0.15, 2),
        "asset_criticality": round(criticality_norm * 0.10, 2),
        "exploit_maturity": round(maturity_norm * 0.05, 2),
        "modifiers": 0.0,
    }

    raw_score = sum(components.values())
    modifiers = 0.0

    if known_ransomware and known_ransomware.lower() == "known":
        modifiers += 7
    if is_kev and exposure.lower() in {"internet", "external", "dmz"}:
        modifiers += 8
    if epss_norm >= 90 and cvss_score >= 8.0:
        modifiers += 5

    components["modifiers"] = round(modifiers, 2)
    final_score = round(clamp(raw_score + modifiers), 2)
    final_rating = rating(final_score)
    final_sla = remediation_sla(final_rating, is_kev, exposure)

    reason_parts: list[str] = []
    reason_parts.append(f"CVSS {cvss_score:.1f} contributes technical severity")
    if epss_score is not None:
        reason_parts.append(f"EPSS {epss_score:.3f} indicates exploitation likelihood")
    else:
        reason_parts.append("EPSS unavailable, score uses remaining context")
    if is_kev:
        reason_parts.append("CISA KEV confirms real-world exploitation")
    if exploit_available or maturity_norm >= 70:
        reason_parts.append(f"exploit maturity is {exploit_maturity}")
    reason_parts.append(f"asset exposure is {exposure}")
    reason_parts.append(f"business criticality is {business_criticality}/5")
    if known_ransomware and known_ransomware.lower() == "known":
        reason_parts.append("ransomware use is known")

    return ScoreResult(
        risk_score=final_score,
        risk_rating=final_rating,
        sla=final_sla,
        priority_reason="; ".join(reason_parts) + ".",
        components=components,
    )
