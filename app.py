"""WebGuard AI - application factory and entry point.   Run:  python app.py"""
import hmac
import logging
import secrets
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session

from config import Config, INSTANCE_DIR
from database import db, iso, login_manager, socketio


def create_app(test_config=None):
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # ---- logging (technical details stay in the server log) ----
    handler = RotatingFileHandler(Path(INSTANCE_DIR) / "webguard.log", maxBytes=1_000_000, backupCount=3,
                                  encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    logging.getLogger("webguard").addHandler(handler)
    logging.getLogger("webguard").setLevel(logging.INFO)

    # ---- extensions ----
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"
    socketio.init_app(app, async_mode="threading", logger=False, engineio_logger=False)

    import models  # noqa: F401  (register tables)
    with app.app_context():
        db.create_all()

    from services.scan_manager import ScanManager
    ScanManager.recover_interrupted(app)
    app.extensions["scan_manager"] = ScanManager(app)

    # ---- blueprints ----
    from routes.auth import bp as auth_bp
    from routes.dashboard import bp as dash_bp
    from routes.history import bp as history_bp
    from routes.profile import bp as profile_bp
    from routes.reports import bp as reports_bp
    from routes.scanner import bp as scanner_bp
    import routes.sockets  # noqa: F401
    for bp in (auth_bp, dash_bp, scanner_bp, history_bp, reports_bp, profile_bp):
        app.register_blueprint(bp)

    # ---- unauthorized handling: JSON for API, redirect for pages ----
    @login_manager.unauthorized_handler
    def _unauth():
        if request.path.startswith("/api/"):
            return jsonify(error="Your session has expired. Please sign in again."), 401
        from flask import flash, redirect, url_for
        flash("Please sign in to continue.", "warning")
        return redirect(url_for("auth.login", next=request.path))

    # ---- CSRF protection ----
    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["app_name"] = app.config["APP_NAME"]

    @app.before_request
    def _csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not app.config.get("WTF_CSRF_DISABLED"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            expected = session.get("_csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                if request.path.startswith("/api/"):
                    return jsonify(error="Security token missing or expired. Refresh the page and try again."), 400
                return render_template("error.html", code=400, message="Security token missing or expired. "
                                       "Go back, refresh the page and try again."), 400

    @app.before_request
    def _keep_session():
        session.permanent = True      # inactivity timeout = PERMANENT_SESSION_LIFETIME, refreshed per request

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if request.path.startswith("/api/") or request.path.startswith("/scan/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---- error pages ----
    def _err(code, message):
        if request.path.startswith("/api/"):
            return jsonify(error=message), code
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(404)
    def _404(_e):
        return _err(404, "The page you are looking for does not exist.")

    @app.errorhandler(405)
    def _405(_e):
        return _err(405, "That action is not allowed here.")

    @app.errorhandler(500)
    def _500(e):
        app.logger.exception("Server error: %s", e)
        return _err(500, "Something went wrong on our side. The error was logged.")

    app.jinja_env.filters["iso"] = iso
    return app


if __name__ == "__main__":
    application = create_app()
    cfg = application.config
    print(f"\n  WebGuard AI running at http://{cfg['HOST']}:{cfg['PORT']}")
    print(f"  Lab mode: {'ON (' + ', '.join(cfg['LAB_HOSTS']) + ')' if cfg['LAB_MODE'] else 'off'}")
    print(f"  Authorized domains: {', '.join(cfg['AUTHORIZED_DOMAINS']) or '(none)'}\n")
    socketio.run(application, host=cfg["HOST"], port=cfg["PORT"], debug=False, use_reloader=False,
                 allow_unsafe_werkzeug=True)
