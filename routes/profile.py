"""Profile route — view and update account details, change password."""
import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from database import db
from models import Scan

bp = Blueprint("profile", __name__)

EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _password_problems(pw: str):
    problems = []
    if len(pw) < 8:
        problems.append("at least 8 characters")
    if not re.search(r"[a-z]", pw):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw):
        problems.append("an uppercase letter")
    if not re.search(r"\d", pw):
        problems.append("a number")
    return problems


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    # Aggregate stats for the profile page
    from models import ACTIVE_STATUSES, FINAL_STATUSES
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    completed_scans = Scan.query.filter(
        Scan.user_id == current_user.id, Scan.scan_status == "Completed"
    ).count()
    active_scans = Scan.query.filter(
        Scan.user_id == current_user.id, Scan.scan_status.in_(ACTIVE_STATUSES)
    ).count()
    # Most recent completed scan
    last_scan = (
        Scan.query.filter(Scan.user_id == current_user.id, Scan.scan_status.in_(FINAL_STATUSES))
        .order_by(Scan.scan_end_time.desc())
        .first()
    )

    return render_template(
        "profile.html",
        active="profile",
        total_scans=total_scans,
        completed_scans=completed_scans,
        active_scans=active_scans,
        last_scan=last_scan,
    )


@bp.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()

    errors = []
    if not 2 <= len(name) <= 80:
        errors.append("Full name must be between 2 and 80 characters.")
    if not EMAIL_RX.match(email) or len(email) > 255:
        errors.append("Please enter a valid email address.")

    if not errors:
        from models import User
        conflict = User.query.filter_by(email=email).first()
        if conflict and conflict.id != current_user.id:
            errors.append("That email address is already in use by another account.")

    if errors:
        for e in errors:
            flash(e, "error")
    else:
        current_user.full_name = name
        current_user.email = email
        db.session.commit()
        flash("Profile updated successfully.", "success")

    return redirect(url_for("profile.profile"))


@bp.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if not current_user.check_password(current_pw):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("profile.profile"))

    problems = _password_problems(new_pw)
    if problems:
        flash("New password needs: " + ", ".join(problems) + ".", "error")
        return redirect(url_for("profile.profile"))

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
        return redirect(url_for("profile.profile"))

    if current_pw == new_pw:
        flash("New password must be different from your current password.", "error")
        return redirect(url_for("profile.profile"))

    current_user.set_password(new_pw)
    db.session.commit()
    flash("Password changed successfully.", "success")
    return redirect(url_for("profile.profile"))
