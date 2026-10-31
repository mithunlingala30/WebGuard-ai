"""
Severity / confidence classification.

IMPORTANT (honesty note): the default classifier is a TRANSPARENT RULE-BASED system, not machine
learning. Every decision is returned with a human-readable rationale. An OPTIONAL supervised
scikit-learn model (see ai_engine/train_model.py) can be trained on a labeled dataset; if
``ai_engine/models/severity_model.joblib`` exists it is used as an advisory second opinion
and any disagreement is reported in the rationale. Rules stay authoritative.
"""
from dataclasses import dataclass, field
from pathlib import Path

from ai_engine.recommendations import get_entry

SEVERITIES = ["Low", "Medium", "High", "Critical"]
DEFAULT_CONFIDENCE = {"confirmed": 0.9, "suspected": 0.5, "observed": 0.85}
MODEL_PATH = Path(__file__).parent / "models" / "severity_model.joblib"


@dataclass
class Classification:
    severity: str
    confidence_score: float
    confidence: str
    rationale: list = field(default_factory=list)
    method: str = "rule-based"


def confidence_label(score: float) -> str:
    return "High" if score >= 0.8 else "Medium" if score >= 0.5 else "Low"


def _bump(sev: str, delta: int) -> str:
    i = max(0, min(len(SEVERITIES) - 1, SEVERITIES.index(sev) + delta))
    return SEVERITIES[i]


class SeverityMLModel:
    """Optional supervised model (scikit-learn pipeline). Inactive unless a trained file exists."""

    def __init__(self):
        self.pipeline = None
        if MODEL_PATH.exists():
            try:
                import joblib
                self.pipeline = joblib.load(MODEL_PATH)
            except Exception:       # corrupt / incompatible model: fall back silently to rules
                self.pipeline = None

    @property
    def available(self):
        return self.pipeline is not None

    def predict(self, ftype, status, hint, exploitability):
        import pandas as pd
        row = pd.DataFrame([{"type": ftype, "status": status, "confidence_hint": hint,
                             "exploitability": exploitability}])
        return str(self.pipeline.predict(row)[0])


_ml = None


def get_ml():
    global _ml
    if _ml is None:
        _ml = SeverityMLModel()
    return _ml


def classify(raw) -> Classification:
    kb = get_entry(raw.type)
    status = raw.status if raw.status in ("confirmed", "suspected", "observed") else "observed"
    sev_map = kb["severity"]
    base = sev_map.get(status) or next(iter(sev_map.values()))
    rationale = [f"Base severity {base} from the knowledge base for '{raw.type}' with evidence status '{status}'."]
    severity = base

    if raw.type.startswith("cookie_") and raw.detail.get("is_session"):
        severity = _bump(severity, +1)
        rationale.append("Cookie name looks like a session/authentication token, so severity was raised one level.")
    if raw.type == "sqli_error" and status == "suspected":
        rationale.append("No differential confirmation (escaped quotes also errored), so it is reported as suspected.")

    score = float(raw.detail.get("confidence_hint", DEFAULT_CONFIDENCE[status]))
    rationale.append(f"Evidence confidence {score:.2f} ({confidence_label(score)}).")

    method = "rule-based"
    ml = get_ml()
    if ml.available:
        try:
            pred = ml.predict(raw.type, status, score, kb["exploitability"])
            method = "rule-based + ML advisory"
            if pred != severity:
                rationale.append(f"ML advisory model predicts '{pred}' (differs from the rule-based '{severity}').")
            else:
                rationale.append("ML advisory model agrees with the rule-based severity.")
        except Exception:
            pass
    return Classification(severity, score, confidence_label(score), rationale, method)
