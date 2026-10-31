"""
Overall risk score (0-100, higher = riskier).

    raw   = sum(weight[severity] * confidence_score)       weights: Critical 10, High 6, Medium 3, Low 1
    score = 100 * (1 - exp(-raw / 25))                       saturating curve, never above 100

Levels: <10 Minimal | <30 Low | <55 Moderate | <75 High | else Critical
"""
import math

WEIGHTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}


def calculate(findings) -> dict:
    """findings: iterable of dicts with 'severity' and 'confidence_score'."""
    raw = sum(WEIGHTS.get(f["severity"], 0) * float(f.get("confidence_score", 0.8)) for f in findings)
    score = round(100 * (1 - math.exp(-raw / 25)), 1) if raw > 0 else 0.0
    return {"score": score, "level": level(score), "raw": round(raw, 2)}


def level(score: float) -> str:
    if score <= 0:
        return "None"
    if score < 10:
        return "Minimal"
    if score < 30:
        return "Low"
    if score < 55:
        return "Moderate"
    if score < 75:
        return "High"
    return "Critical"
