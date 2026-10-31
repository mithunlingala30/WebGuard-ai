"""Scan-to-scan comparison based on finding fingerprints."""
from models import Scan


def previous_scan(scan):
    """Most recent completed scan of the same target (same owner) that started before ``scan``."""
    return (Scan.query.filter(Scan.user_id == scan.user_id, Scan.target_url == scan.target_url,
                              Scan.scan_status == "Completed", Scan.id < scan.id)
            .order_by(Scan.id.desc()).first())


def compare(old, new):
    old_map = {v.fingerprint: v for v in old.vulnerabilities}
    new_map = {v.fingerprint: v for v in new.vulnerabilities}

    def brief(v):
        return {"name": v.vulnerability_name, "severity": v.severity, "url": v.affected_url, "param": v.param}

    return {
        "old": {"id": old.id, "target": old.target_url, "risk": old.risk_score, "findings": old.total_findings,
                "start": old.scan_start_time.isoformat() + "Z" if old.scan_start_time else None},
        "new": {"id": new.id, "target": new.target_url, "risk": new.risk_score, "findings": new.total_findings,
                "start": new.scan_start_time.isoformat() + "Z" if new.scan_start_time else None},
        "risk_delta": round(new.risk_score - old.risk_score, 1),
        "new_findings": [brief(v) for k, v in new_map.items() if k not in old_map],
        "resolved": [brief(v) for k, v in old_map.items() if k not in new_map],
        "persistent": [brief(v) for k, v in new_map.items() if k in old_map],
    }
