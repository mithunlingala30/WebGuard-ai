from collections import OrderedDict
from datetime import timedelta

from flask import Blueprint, jsonify, render_template
from flask_login import current_user, login_required
from sqlalchemy import func

from ai_engine.risk_score import level as risk_level
from database import db, iso, utcnow
from models import ACTIVE_STATUSES, Scan, Vulnerability

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@bp.route("/api/dashboard/stats")
@login_required
def stats():
    uid = current_user.id
    scans = Scan.query.filter_by(user_id=uid)
    total = scans.count()
    completed = scans.filter_by(scan_status="Completed").count()
    running = scans.filter(Scan.scan_status.in_(ACTIVE_STATUSES)).count()

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    rows = (db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
            .join(Scan, Scan.id == Vulnerability.scan_id).filter(Scan.user_id == uid)
            .group_by(Vulnerability.severity).all())
    for s, c in rows:
        sev[s] = c

    # scan activity: scans started per day, last 14 days
    today = utcnow().date()
    days = OrderedDict((today - timedelta(days=i), 0) for i in range(13, -1, -1))
    for (created,) in db.session.query(Scan.created_at).filter(Scan.user_id == uid,
                                                                Scan.created_at >= utcnow() - timedelta(days=14)):
        if created.date() in days:
            days[created.date()] += 1

    # overall risk = mean of the latest completed scan score per target
    latest = {}
    for s in scans.filter_by(scan_status="Completed").order_by(Scan.id):
        latest[s.target_url] = s.risk_score
    risk = round(sum(latest.values()) / len(latest), 1) if latest else 0.0

    recent_scans = scans.order_by(Scan.id.desc()).limit(6).all()
    recent_findings = (Vulnerability.query.join(Scan).filter(Scan.user_id == uid)
                       .order_by(Vulnerability.id.desc()).limit(8).all())
    return jsonify({
        "totals": {"total_scans": total, "completed": completed, "running": running,
                   "vulnerabilities": sum(sev.values()), **{k.lower(): v for k, v in sev.items()}},
        "severity": sev,
        "activity": [{"date": d.strftime("%d %b"), "count": c} for d, c in days.items()],
        "risk": {"score": risk, "level": risk_level(risk), "targets": len(latest)},
        "recent_scans": [s.to_dict() for s in recent_scans],
        "recent_findings": [{**v.to_dict(), "target": v.scan.target_url, "created": iso(v.scan.scan_start_time)}
                            for v in recent_findings],
    })
