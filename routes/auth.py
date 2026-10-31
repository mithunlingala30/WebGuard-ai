import re
import time
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from database import db
from models import User

bp = Blueprint("auth", __name__)

EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_failed = {}     # key -> (count, first_failure_ts)   (in-memory brute-force throttle)


def password_problems(pw: str):
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


def _safe_next(target):
    if not target:
        return None
    p = urlparse(target)
    return target if not p.netloc and not p.scheme and target.startswith("/") and not target.startswith("//") else None


def _locked(key):
    cfg = current_app.config
    rec = _failed.get(key)
    if not rec:
        return 0
    count, ts = rec
    if time.time() - ts > cfg["LOGIN_LOCKOUT_SECONDS"]:
        _failed.pop(key, None)
        return 0
    return int(cfg["LOGIN_LOCKOUT_SECONDS"] - (time.time() - ts)) if count >= cfg["LOGIN_MAX_ATTEMPTS"] else 0


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    form = {"full_name": "", "email": ""}
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm_password", "")
        form.update(full_name=name, email=email)
        errors = []
        if not 2 <= len(name) <= 80:
            errors.append("Full name must be between 2 and 80 characters.")
        if not EMAIL_RX.match(email) or len(email) > 255:
            errors.append("Please enter a valid email address.")
        probs = password_problems(pw)
        if probs:
            errors.append("Password needs " + ", ".join(probs) + ".")
        if pw != pw2:
            errors.append("Passwords do not match.")
        if not errors and User.query.filter_by(email=email).first():
            errors.append("An account with this email already exists.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            user = User(full_name=name, email=email)
            user.set_password(pw)
            db.session.add(user)
            db.session.commit()
            flash("Account created. You can sign in now.", "success")
            return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    email = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        key = f"{email}|{request.remote_addr}"
        wait = _locked(key)
        if wait:
            flash(f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).", "error")
        elif not email or not pw:
            flash("Enter your email and password.", "error")
        else:
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(pw):
                _failed.pop(key, None)
                session.clear()
                login_user(user)
                session.permanent = True
                return redirect(_safe_next(request.args.get("next")) or url_for("dashboard.dashboard"))
            count, ts = _failed.get(key, (0, time.time()))
            _failed[key] = (count + 1, ts if count else time.time())
            flash("Invalid email or password.", "error")
    return render_template("login.html", email=email)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
