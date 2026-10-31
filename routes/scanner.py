import json

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from database import db, utcnow
from models import ACTIVE_STATUSES, Scan, Vulnerability
from services.comparison import compare, previous_scan
from services.scan_manager import PROFILES
from services.target_validator import TargetError, validate_target

bp = Blueprint("scanner", __name__)


def own_scan_or_404(scan_id) -> Scan:
    """Users can only ever load their own scans (404 instead of 403 prevents enumeration)."""
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if scan is None:
        abort(404)
    return scan


@bp.route("/scan/new")
@login_required
def new_scan():
    cfg = current_app.config
    return render_template("new_scan.html", active="scan", profiles=PROFILES,
                           authorized=cfg["AUTHORIZED_DOMAINS"], lab=cfg["LAB_MODE"], lab_hosts=cfg["LAB_HOSTS"],
                           allow_any=cfg.get("ALLOW_ANY_DOMAIN", True))


@bp.route("/api/scans", methods=["POST"])
@login_required
def create_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    scan_type = data.get("scan_type", "standard")
    if scan_type not in PROFILES:
        return jsonify(error="Unknown scan type."), 400
    if data.get("authorized") is not True:
        return jsonify(error="You must confirm that you are authorized to test this website."), 400

    # server-side validation: syntax, authorization list, DNS/IP safety, ports
    try:
        target = validate_target(url)
    except TargetError as exc:
        return jsonify(error=str(exc)), 400

    active = Scan.query.filter(Scan.user_id == current_user.id, Scan.scan_status.in_(ACTIVE_STATUSES)).count()
    if active >= current_app.config["MAX_ACTIVE_SCANS_PER_USER"]:
        return jsonify(error=f"You already have {active} scans running. Wait for one to finish or cancel it."), 429

    extra = []
    for line in str(data.get("extra_paths", ""))[:2000].splitlines():
        line = line.strip()
        if line.startswith("/") and not line.startswith("//") and len(line) < 200 and len(extra) < 15:
            extra.append(line)

    scan = Scan(user_id=current_user.id, target_url=target.url, scan_type=scan_type,
                options=json.dumps({"extra_paths": extra}), scan_status="Waiting", current_activity="Waiting in queue")
    db.session.add(scan)
    db.session.commit()
    current_app.extensions["scan_manager"].submit(scan.id)
    return jsonify(scan_id=scan.id, scan=scan.to_dict()), 201


@bp.route("/api/scans/<int:scan_id>")
@login_required
def scan_status(scan_id):
    return jsonify(own_scan_or_404(scan_id).to_dict())


@bp.route("/api/scans/<int:scan_id>/cancel", methods=["POST"])
@login_required
def cancel_scan(scan_id):
    scan = own_scan_or_404(scan_id)
    if not scan.is_active:
        return jsonify(error="This scan is not running."), 400
    if not current_app.extensions["scan_manager"].cancel(scan_id):
        # worker is gone (e.g. after a restart): close the record directly
        scan.scan_status, scan.scan_end_time, scan.current_activity = "Cancelled", utcnow(), "Scan cancelled by user."
        db.session.commit()
    return jsonify(ok=True, message="Cancellation requested.")


@bp.route("/scan/<int:scan_id>")
@login_required
def scan_results(scan_id):
    scan = own_scan_or_404(scan_id)
    return render_template("scan_results.html", scan=scan, active="history")


@bp.route("/api/scans/<int:scan_id>/findings")
@login_required
def findings(scan_id):
    scan = own_scan_or_404(scan_id)
    q = Vulnerability.query.filter_by(scan_id=scan.id)
    sev, ftype, text = request.args.get("severity"), request.args.get("type"), (request.args.get("q") or "").strip().lower()
    if sev in ("Critical", "High", "Medium", "Low"):
        q = q.filter(Vulnerability.severity == sev)
    if ftype:
        q = q.filter(Vulnerability.vulnerability_type == ftype)
    items = [v.to_dict() for v in q.order_by(Vulnerability.priority).all()]
    if text:
        items = [f for f in items if text in " ".join([f["name"], f["url"], f["owasp"], f["description"], f["evidence"]]).lower()]
    types = sorted({v.vulnerability_type for v in scan.vulnerabilities})
    return jsonify(findings=items, types=types, severity=scan.severity_counts())


@bp.route("/api/scans/<int:scan_id>/logs")
@login_required
def logs(scan_id):
    scan = own_scan_or_404(scan_id)
    return jsonify(logs=[l.to_dict() for l in scan.logs.all()])


@bp.route("/api/scans/<int:scan_id>/compare")
@login_required
def compare_previous(scan_id):
    scan = own_scan_or_404(scan_id)
    prev = previous_scan(scan)
    if prev is None:
        return jsonify(available=False, message="No earlier completed scan of this target to compare with.")
    return jsonify(available=True, **compare(prev, scan))
