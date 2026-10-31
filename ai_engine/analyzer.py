"""
AI analysis pipeline - consumes REAL scanner findings only.

1. exact de-duplication by fingerprint
2. explainable classification (OWASP category, severity, confidence) + remediation text
3. false-positive reduction: findings whose evidence confidence is below 0.30 are suppressed
4. near-duplicate detection with scikit-learn (TF-IDF + cosine similarity) per finding type/parameter
5. prioritisation (severity x confidence x exploitability)
6. overall risk score
"""
import hashlib
from urllib.parse import urlparse

from ai_engine import risk_score
from ai_engine.classifier import SEVERITIES, classify
from ai_engine.recommendations import get_entry

FP_THRESHOLD = 0.30
SIM_THRESHOLD = 0.90


def fingerprint(ftype: str, url: str, param: str = "") -> str:
    p = urlparse(url)
    raw = f"{ftype}|{p.netloc.lower()}|{p.path or '/'}|{param}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _near_duplicate_groups(items):
    """Group indices of findings of same type+param whose evidence text is >= SIM_THRESHOLD similar."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    buckets = {}
    for i, f in enumerate(items):
        buckets.setdefault((f["key"], f["param"]), []).append(i)
    merged = {}
    for (_k, _p), idxs in buckets.items():
        if len(idxs) < 2:
            continue
        texts = [items[i]["evidence"] for i in idxs]
        try:
            sim = cosine_similarity(TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit_transform(texts))
        except ValueError:
            continue
        keep = []
        for a, i in enumerate(idxs):
            dup_of = next((idxs[b] for b in range(a) if idxs[b] in keep and sim[a][b] >= SIM_THRESHOLD), None)
            if dup_of is None:
                keep.append(i)
            else:
                merged[i] = dup_of
    return merged


def analyze(raw_findings) -> dict:
    notes = []
    # 1. exact de-dup
    exact = {}
    duplicates = 0
    for rf in raw_findings:
        fp = fingerprint(rf.type, rf.url, rf.param)
        if fp in exact:
            duplicates += 1
            exact[fp]["raw"].detail["occurrences"] = exact[fp]["raw"].detail.get("occurrences", 1) + 1
            continue
        exact[fp] = {"raw": rf, "fp": fp}

    # 2-3. classify + FP reduction
    items, suppressed = [], 0
    for entry in exact.values():
        rf, kb = entry["raw"], get_entry(entry["raw"].type)
        c = classify(rf)
        if c.confidence_score < FP_THRESHOLD:
            suppressed += 1
            continue
        items.append({
            "key": rf.type, "name": kb["name"], "type": kb["category"], "owasp": kb["owasp"],
            "severity": c.severity, "url": rf.url, "param": rf.param, "description": kb["description"],
            "evidence": rf.evidence, "confidence": c.confidence, "confidence_score": c.confidence_score,
            "status": rf.status, "impact": kb["impact"], "recommendation": kb["recommendation"],
            "rationale": c.rationale, "fingerprint": entry["fp"], "occurrences": rf.detail.get("occurrences", 1),
            "exploitability": kb["exploitability"],
        })
    if suppressed:
        notes.append(f"{suppressed} low-confidence finding(s) suppressed as probable false positives.")

    # 4. near duplicates (scikit-learn)
    merged = _near_duplicate_groups(items)
    for dup, keeper in merged.items():
        items[keeper]["occurrences"] += items[dup]["occurrences"]
        items[keeper]["rationale"].append(f"Merged a near-identical finding at {items[dup]['url']} (TF-IDF similarity).")
    items = [f for i, f in enumerate(items) if i not in merged]
    duplicates += len(merged)
    if duplicates:
        notes.append(f"{duplicates} duplicate finding(s) merged.")

    # 5. prioritise
    for f in items:
        f["_rank"] = (SEVERITIES.index(f["severity"]) + 1) * f["confidence_score"] * (0.5 + f["exploitability"] / 2)
    items.sort(key=lambda f: f["_rank"], reverse=True)
    for n, f in enumerate(items, 1):
        f["priority"] = n
        r = f.pop("_rank")
        f["priority_label"] = "P1 - Fix immediately" if r >= 3 else "P2 - Fix soon" if r >= 1.6 else "P3 - Plan fix" if r >= 0.8 else "P4 - Hardening"
        f.pop("exploitability", None)

    # 6. risk
    risk = risk_score.calculate(items)
    return {"findings": items, "risk": risk, "suppressed": suppressed, "duplicates": duplicates, "notes": notes}
