"""
Background scan execution.

A small pool of DAEMON worker threads pulls scan ids from a queue. Each scan runs a real pipeline;
the progress percentage is derived from work actually completed (pages crawled, checks and
injection points tested) inside fixed stage ranges:

   0-10  initializing / validating target
  10-35  crawling            35-45 security headers      45-60 cookies + TLS
  60-70  information disclosure
  70-85  authorized vulnerability checks (SQLi / XSS)    85-95 AI analysis     95-100 saving results
"""
import json
import logging
import queue
import threading

from database import db, iso, socketio, utcnow
from models import ACTIVE_STATUSES, Scan, ScanLog, Vulnerability
from services.http_client import SafeHTTP, ScanCancelled
from services.target_validator import TargetError, validate_target

log = logging.getLogger("webguard.scan")

PROFILES = {
    "quick": dict(label="Quick Scan", max_depth=0, max_pages=1, active=False, post=False, points=0),
    "standard": dict(label="Standard Scan", max_depth=2, max_pages=30, active=True, post=False, points=20),
    "full": dict(label="Full Assessment", max_depth=3, max_pages=60, active=True, post=True, points=40),
}


class ScanManager:
    def __init__(self, app):
        self.app = app
        self.queue = queue.Queue()
        self.cancel_events = {}
        self.lock = threading.Lock()
        self.workers = []
        for i in range(app.config["MAX_CONCURRENT_SCANS"]):
            t = threading.Thread(target=self._worker, name=f"scan-worker-{i}", daemon=True)
            t.start()
            self.workers.append(t)

    # ------------------------------------------------------------------ public
    def submit(self, scan_id: int):
        with self.lock:
            self.cancel_events[scan_id] = threading.Event()
        self.queue.put(scan_id)

    def cancel(self, scan_id: int) -> bool:
        with self.lock:
            ev = self.cancel_events.get(scan_id)
        if ev:
            ev.set()
            return True
        return False

    def run_sync(self, scan_id: int):
        """Run a scan in the calling thread (used by tests)."""
        with self.lock:
            self.cancel_events.setdefault(scan_id, threading.Event())
        self._run(scan_id)

    @staticmethod
    def recover_interrupted(app):
        """Scans left active by a previous server run can never finish: mark them Failed."""
        with app.app_context():
            stale = Scan.query.filter(Scan.scan_status.in_(ACTIVE_STATUSES)).all()
            for s in stale:
                s.scan_status = "Failed"
                s.error_message = "The scan was interrupted because the server restarted."
                s.scan_end_time = utcnow()
                s.current_activity = "Interrupted"
            if stale:
                db.session.commit()

    # ---------------------------------------------------------------- internals
    def _worker(self):
        while True:
            scan_id = self.queue.get()
            try:
                self._run(scan_id)
            except Exception:
                log.exception("Unhandled error in scan worker for scan %s", scan_id)
            finally:
                self.queue.task_done()

    def _emit(self, scan: Scan, finished=False):
        payload = scan.progress_payload()
        socketio.emit("scan_progress", payload, to=f"scan_{scan.id}")
        if finished:
            socketio.emit("scan_finished", {**payload, "target_url": scan.target_url}, to=f"user_{scan.user_id}")

    def _run(self, scan_id: int):
        with self.app.app_context():
            scan = db.session.get(Scan, scan_id)
            cancel = self.cancel_events.get(scan_id) or threading.Event()
            if scan is None:
                return
            if cancel.is_set():
                self._finish(scan, "Cancelled", "Scan was cancelled before it started.")
                return
            user_id = scan.user_id

            def on_log(msg, level="info"):
                db.session.add(ScanLog(scan_id=scan_id, log_message=str(msg)[:1000], status=level))
                db.session.commit()
                socketio.emit("scan_log", {"scan_id": scan_id, "message": str(msg)[:1000], "status": level,
                                           "timestamp": iso(utcnow())}, to=f"scan_{scan_id}")

            state = {"status": "Initializing", "stats": {"pages": 0, "tests": 0}}

            def on_progress(pct, activity, status=None):
                if status:
                    state["status"] = status
                s = db.session.get(Scan, scan_id)
                s.scan_status = state["status"]
                s.progress = max(s.progress or 0, min(100, int(pct)))
                s.current_activity = activity[:500]
                s.pages_discovered = state["stats"]["pages"]
                s.tests_completed = state["stats"]["tests"]
                db.session.commit()
                self._emit(s)

            try:
                self._execute(scan, cancel, on_progress, on_log, state)
            except ScanCancelled:
                db.session.rollback()
                self._finish(db.session.get(Scan, scan_id), "Cancelled", "Scan cancelled by user.")
            except TargetError as exc:
                db.session.rollback()
                self._finish(db.session.get(Scan, scan_id), "Failed", str(exc))
            except Exception:
                log.exception("Scan %s failed", scan_id)
                db.session.rollback()
                self._finish(db.session.get(Scan, scan_id), "Failed",
                             "An internal error occurred while scanning. Details were written to the server log.")
            finally:
                with self.lock:
                    self.cancel_events.pop(scan_id, None)
                db.session.remove()

    # The pipeline -----------------------------------------------------------
    def _execute(self, scan, cancel, on_progress, on_log, state):
        from ai_engine import analyzer
        from scanner import (cookie_checker, crawler, header_checker, information_disclosure,
                             sqli_scanner, ssl_checker, xss_scanner)
        from scanner.base import ScanContext

        cfg = self.app.config
        scan_id = scan.id
        profile = PROFILES.get(scan.scan_type, PROFILES["standard"])
        options = json.loads(scan.options or "{}")
        scan.scan_start_time = utcnow()
        db.session.commit()

        http = SafeHTTP(cfg, cancel)

        # --- 0-10: init + validation
        on_progress(0, "Initializing scanner", "Initializing")
        on_log(f"Scan started: {profile['label']} of {scan.target_url}")
        on_progress(5, "Loading scan profile and safety limits")
        on_progress(10, "Validating target (authorization, DNS and network safety)")
        target = validate_target(scan.target_url)
        on_log(f"Target validated: {target.host} resolves to {', '.join(target.ips)}", "success")

        ctx = ScanContext(http, target, profile, options, cancel, on_progress, on_log)
        ctx.stats = state["stats"]      # share the live counters with the progress callback

        # --- 10-35: crawl
        on_progress(10, "Crawling website", "Crawling")
        ctx.set_range(10, 35)
        crawl = crawler.crawl(ctx, target.url, profile["max_depth"], profile["max_pages"], options.get("extra_paths", []))
        home = crawl.home
        if home is None or not home.ok:
            err = home.error if home is not None else "no response"
            raise TargetError(f"The website could not be reached: {err}")
        on_log(f"Crawl finished: {len(crawl.pages)} page(s), {len(crawl.forms)} form(s) discovered", "success")
        on_progress(35, f"Crawl complete - {len(crawl.pages)} pages discovered", "Testing")

        # --- 35-45 headers
        ctx.set_range(35, 45)
        ctx.stage(0.0, "Checking security headers")
        header_checker.run(ctx, home)
        ctx.stage(1.0, "Security headers checked")

        # --- 45-60 cookies + TLS
        ctx.set_range(45, 60)
        ctx.stage(0.0, "Checking cookie attributes")
        cookie_checker.run(ctx, crawl)
        ctx.stage(0.5, "Checking TLS configuration")
        ssl_checker.run(ctx, home)
        if http.tls_verification_failed and not any(f.type.startswith("ssl_") for f in ctx.findings):
            ctx.log("Certificate could not be verified during crawling.", "warning")
        ctx.stage(1.0, "Cookies and TLS checked")

        # --- 60-70 information disclosure
        ctx.set_range(60, 70)
        ctx.stage(0.0, "Checking for information disclosure")
        information_disclosure.run(ctx, crawl)
        ctx.stage(1.0, "Information disclosure checks complete")

        # --- 70-85 active checks
        if profile["active"]:
            points = crawler.build_injection_points(crawl, profile["post"], profile["points"])
            on_log(f"Running authorized vulnerability checks on {len(points)} input point(s)")
            total = max(1, len(points) * 2)
            if points:
                sqli_scanner.run(ctx, points, 70, 85, 0, total)
                xss_scanner.run(ctx, points, 70, 85, len(points), total)
            else:
                on_log("No testable input fields or URL parameters were found.")
        else:
            on_log("Quick scan: active injection checks skipped.")
        ctx.set_range(70, 85)
        ctx.stage(1.0, "Vulnerability checks complete")

        # --- 85-95 AI analysis
        on_progress(85, "AI analysis of scanner findings", "AI Analysis")
        result = analyzer.analyze(ctx.findings)
        for note in result["notes"]:
            on_log(note)
        on_progress(95, "Generating results")

        # --- 95-100 persist
        for f in result["findings"]:
            db.session.add(Vulnerability(
                scan_id=scan_id, vulnerability_name=f["name"], vulnerability_type=f["type"],
                owasp_category=f["owasp"], severity=f["severity"], affected_url=f["url"][:2048],
                description=f["description"], evidence=f["evidence"][:4000], confidence=f["confidence"],
                recommendation=f["recommendation"], finding_key=f["key"], param=f["param"][:200],
                finding_status=f["status"], impact=f["impact"], confidence_score=f["confidence_score"],
                priority=f["priority"], priority_label=f["priority_label"],
                rationale=json.dumps(f["rationale"]), fingerprint=f["fingerprint"], occurrences=f["occurrences"]))
        scan = db.session.get(Scan, scan_id)
        scan.total_findings = len(result["findings"])
        scan.risk_score = result["risk"]["score"]
        scan.risk_level = result["risk"]["level"]
        scan.pages_discovered = ctx.stats["pages"]
        scan.tests_completed = ctx.stats["tests"]
        db.session.commit()
        on_log(f"Analysis complete: {len(result['findings'])} finding(s), risk score {result['risk']['score']} "
               f"({result['risk']['level']})", "success")
        self._finish(scan, "Completed", "Scan completed")

    def _finish(self, scan, status, message):
        if scan is None:
            return
        scan.scan_status = status
        scan.scan_end_time = utcnow()
        scan.current_activity = message[:500]
        if status == "Completed":
            scan.progress = 100
        else:
            scan.error_message = message[:1000]
        db.session.add(ScanLog(scan_id=scan.id, log_message=message[:1000],
                               status="success" if status == "Completed" else "warning" if status == "Cancelled" else "error"))
        db.session.commit()
        self._emit(scan, finished=True)
