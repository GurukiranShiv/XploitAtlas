from backend.app.scoring import score_vulnerability


def test_internet_kev_weaponized_becomes_critical():
    score = score_vulnerability(
        cvss_score=9.8,
        epss_score=0.95,
        is_kev=True,
        exploit_maturity="weaponized",
        exploit_available=True,
        exposure="internet",
        business_criticality=5,
        known_ransomware="Known",
    )
    assert score.risk_rating == "Critical"
    assert score.risk_score >= 85
    assert score.sla == "24 hours"


def test_high_cvss_dev_low_epss_is_not_automatically_critical():
    score = score_vulnerability(
        cvss_score=9.1,
        epss_score=0.05,
        is_kev=False,
        exploit_maturity="none",
        exploit_available=False,
        exposure="dev",
        business_criticality=2,
    )
    assert score.risk_rating in {"Low", "Medium"}
    assert score.risk_score < 70
