from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, send_file, url_for
from flask_login import current_user, login_required

from database import iso
from models import Report, Scan
from routes.scanner import own_scan_or_404
from services.report_generator import save_report

bp = Blueprint("reports", __name__)


@bp.route("/reports")
@login_required
def reports():
    return render_template("reports.html", active="reports")


@bp.route("/api/reports")
@login_required
def reports_api():
    scans = Scan.query.filter_by(user_id=current_user.id, scan_status="Completed").order_by(Scan.id.desc()).all()
    out = []
    for s in scans:
        d = s.to_dict()
        d["reports"] = {r.report_type: iso(r.generated_at) for r in s.reports}
        out.append(d)
    return jsonify(scans=out)


@bp.route("/reports/<int:scan_id>/<fmt>")
@login_required
def download(scan_id, fmt):
    if fmt not in ("pdf", "html"):
        abort(404)
    scan = own_scan_or_404(scan_id)
    if scan.scan_status != "Completed":
        flash("Reports are only available for completed scans.", "error")
        return redirect(url_for("reports.reports"))
    try:
        _rep, path = save_report(scan, fmt)     # always rebuilt from current database findings
    except Exception:
        current_app.logger.exception("Report generation failed for scan %s", scan_id)
        flash("The report could not be generated. The error was logged on the server.", "error")
        return redirect(url_for("scanner.scan_results", scan_id=scan_id))
    return send_file(path, as_attachment=True, download_name=f"WebGuard_Scan{scan_id}_report.{fmt}")
