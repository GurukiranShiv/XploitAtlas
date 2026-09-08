"""Versioned, explainable weights. Scores are prioritization points, never probabilities."""
from __future__ import annotations
import hashlib
import json
import math

DEFAULT_WEIGHTS = {"kev": 60, "ransomware": 10, "cvss": 20, "epss": 15,
                   "exploit_reference": 5, "internet_exposed": 20, "asset_criticality": 10}
WEIGHT_LABELS = {"kev": "Known exploitation", "ransomware": "Ransomware evidence", "cvss": "Technical severity",
                 "epss": "Exploitation probability", "exploit_reference": "Published exploit reference",
                 "internet_exposed": "Internet exposure", "asset_criticality": "Asset importance"}


def validate_weights(values=None):
    if values is None:
        return dict(DEFAULT_WEIGHTS)
    if not isinstance(values, dict) or set(values) - set(DEFAULT_WEIGHTS):
        raise ValueError("Unknown priority weight.")
    weights = {**DEFAULT_WEIGHTS, **values}
    if any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 100 for v in weights.values()):
        raise ValueError("Each priority weight must be between 0 and 100.")
    if not any(weights.values()):
        raise ValueError("At least one weight must be greater than zero.")
    return weights


def priority_band(score):
    if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 100:
        raise ValueError("Priority score must be between 0 and 100.")
    return "Act now" if score >= 70 else "Investigate" if score >= 40 else "Review" if score >= 15 else "Monitor"


def score_evidence(evidence, weights=None):
    """Calculate points from normalized 0–1 evidence factors without record I/O."""
    weights = validate_weights(weights)
    if not isinstance(evidence, dict) or set(evidence) - set(DEFAULT_WEIGHTS):
        raise ValueError("Unknown priority evidence factor.")
    normalized = {}
    for key, factor in evidence.items():
        if isinstance(factor, bool):
            factor = int(factor)
        if type(factor) not in (int, float) or not math.isfinite(factor) or not 0 <= factor <= 1:
            raise ValueError("Priority evidence factors must be between 0 and 1.")
        normalized[key] = float(factor)
    reasons = [{"key": key, "label": WEIGHT_LABELS[key], "weight": weights[key], "factor": round(factor, 4),
                "points": round(weights[key] * factor, 2)} for key, factor in normalized.items()
               if weights[key] and factor]
    raw = sum(reason["points"] for reason in reasons)
    score = min(100, int(math.floor(raw + .5)))
    return {"score": score, "rawScore": round(raw, 2), "band": priority_band(score), "reasons": reasons}


def priority(record, weights=None, context=None):
    weights, context = validate_weights(weights), context or {}
    version = hashlib.sha256(json.dumps(weights, sort_keys=True).encode()).hexdigest()[:12]
    if record.get("withdrawn"):
        return {"score": 0, "band": "Withdrawn", "reasons": [], "missing": [], "model": "mastermonk-2",
                "profile": version, "rawScore": 0}
    evidence = {"kev": bool(record.get("kev")), "ransomware": record.get("ransomware") == "Known",
                "exploit_reference": any(r.get("kind") == "exploit" for r in record.get("references", [])),
                "internet_exposed": context.get("internet_exposed", False),
                "asset_criticality": max(0, min(1, context.get("criticality", 0) / 5))}
    missing = []
    for key, scale in (("cvss", 10), ("epss", 1)):
        value = record.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= scale:
            missing.append(key.upper())
        else:
            evidence[key] = value / scale
    result = score_evidence(evidence, weights)
    return {**result, "missing": missing, "model": "mastermonk-2", "profile": version}
