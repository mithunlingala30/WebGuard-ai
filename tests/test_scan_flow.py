"""End-to-end: real scan of the local lab site -> AI analysis -> DB -> dashboard -> PDF/HTML reports."""
import threading

from database import db
from models import Scan, Vulnerability
from tests.conftest import register_and_login


def run_scan(client, app, url, scan_type="standard"):
    register_and_login(client)
    r = client.post("/api/scans", json={"url": url, "authorized": True, "scan_type": scan_type})
    assert r.status_code == 201, r.get_json()
    sid = r.get_json()["scan_id"]
    # the background worker picked it up; wait for completion
    import time
    for _ in range(120):
        d = client.get(f"/api/scans/{sid}").get_json()
        if d["status"] in ("Completed", "Failed", "Cancelled"):
            return sid, d
        time.sleep(0.5)
    raise AssertionError("scan did not finish")


def test_full_scan_pipeline(client, app, lab_site):
    sid, d = run_scan(client, app, lab_site + "/")
    assert d["status"] == "Completed", d
    assert d["progress"] == 100 and d["pages"] >= 3 and d["tests"] > 10

    with app.app_context():
        keys = {v.finding_key: v for v in Vulnerability.query.filter_by(scan_id=sid)}
    for expected in ("missing_csp", "missing_xcto", "missing_xfo", "missing_referrer_policy", "cookie_missing_httponly",
                     "directory_listing", "env_file_exposed", "server_version_disclosure",
                     "xss_reflected", "sqli_error"):
        assert expected in keys, f"missing {expected}; got {sorted(keys)}"
    assert ("no_https" in keys or "https_not_enforced" in keys), f"expected HTTPS finding; got {sorted(keys)}"
    assert keys["sqli_error"].severity == "Critical" and keys["sqli_error"].finding_status == "confirmed"
    assert keys["xss_reflected"].severity == "High"
    assert d["risk_score"] > 40

    stats = client.get("/api/dashboard/stats").get_json()
    assert stats["totals"]["completed"] == 1 and stats["totals"]["critical"] >= 1

    r = client.get(f"/api/scans/{sid}/findings?severity=Critical").get_json()
    assert all(f["severity"] == "Critical" for f in r["findings"]) and r["findings"]
    assert client.get(f"/api/scans/{sid}/findings?q=wgx").get_json()["findings"] is not None

    pdf = client.get(f"/reports/{sid}/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    html = client.get(f"/reports/{sid}/html")
    assert html.status_code == 200 and b"Missing Content-Security-Policy" in html.data

    # second scan -> comparison
    r = client.post("/api/scans", json={"url": lab_site + "/", "authorized": True, "scan_type": "quick"})
    sid2 = r.get_json()["scan_id"]
    import time
    for _ in range(120):
        if client.get(f"/api/scans/{sid2}").get_json()["status"] == "Completed":
            break
        time.sleep(0.5)
    cmp = client.get(f"/api/scans/{sid2}/compare").get_json()
    assert cmp["available"] and len(cmp["resolved"]) >= 1      # quick scan has no active findings
    assert client.get(f"/api/compare?a={sid}&b={sid2}").status_code == 200


def test_cancel_scan(client, app, lab_site):
    register_and_login(client)
    app.config["REQUEST_DELAY"] = 0.5            # slow it down so cancellation lands mid-scan
    r = client.post("/api/scans", json={"url": lab_site + "/", "authorized": True, "scan_type": "full"})
    sid = r.get_json()["scan_id"]
    import time
    time.sleep(1.5)
    assert client.post(f"/api/scans/{sid}/cancel").status_code == 200
    for _ in range(60):
        d = client.get(f"/api/scans/{sid}").get_json()
        if d["status"] in ("Completed", "Failed", "Cancelled"):
            break
        time.sleep(0.5)
    assert d["status"] == "Cancelled"
    with app.app_context():
        assert Vulnerability.query.filter_by(scan_id=sid).count() == 0


def test_unreachable_target_fails_gracefully(client, app):
    sid, d = run_scan(client, app, "http://localhost:8081/")      # nothing listens here
    assert d["status"] == "Failed" and "could not be reached" in d["error"].lower()
