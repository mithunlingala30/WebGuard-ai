import os

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from database import db
from models import Scan
from routes.scanner import own_scan_or_404
from services.comparison import compare

bp = Blueprint("history", __name__)


@bp.route("/history")
@login_required
def history():
    return render_template("history.html", active="history")


@bp.route("/api/history")
@login_required
def history_api():
    q = Scan.query.filter_by(user_id=current_user.id)
    status, text = request.args.get("status"), (request.args.get("q") or "").strip().lower()
    if status:
        q = q.filter(Scan.scan_status == status)
    scans = [s.to_dict() for s in q.order_by(Scan.id.desc()).all()]
    if text:
        scans = [s for s in scans if text in s["target_url"].lower()]
    return jsonify(scans=scans)


@bp.route("/api/compare")
@login_required
def compare_api():
    try:
        a, b = int(request.args["a"]), int(request.args["b"])
    except (KeyError, ValueError):
        return jsonify(error="Select two scans to compare."), 400
    if a == b:
        return jsonify(error="Choose two different scans."), 400
    sa, sb = own_scan_or_404(a), own_scan_or_404(b)
    old, new = (sa, sb) if sa.id < sb.id else (sb, sa)
    if old.scan_status != "Completed" or new.scan_status != "Completed":
        return jsonify(error="Both scans must be completed."), 400
    return jsonify(compare(old, new))


@bp.route("/api/scans/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = own_scan_or_404(scan_id)
    if scan.is_active:
        return jsonify(error="Cancel the scan before deleting it."), 400
    for r in scan.reports:
        try:
            os.remove(r.file_path)
        except OSError:
            pass
    db.session.delete(scan)
    db.session.commit()
    return jsonify(ok=True)
