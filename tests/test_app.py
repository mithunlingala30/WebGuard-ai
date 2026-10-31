from tests.conftest import register_and_login


def test_pages_render(client):
    for path in ("/", "/login", "/register"):
        assert client.get(path).status_code == 200


def test_protected_routes_redirect_or_401(client):
    assert client.get("/dashboard").status_code == 302
    assert client.get("/api/dashboard/stats").status_code == 401
    assert client.post("/api/scans", json={}).status_code == 401


def test_register_validation_and_duplicate(client):
    r = client.post("/register", data={"full_name": "A", "email": "bad", "password": "x", "confirm_password": "y"})
    assert b"valid email" in r.data and b"Passwords do not match" in r.data
    register_and_login(client)
    client.post("/logout")
    r = client.post("/register", data={"full_name": "Alice Tester", "email": "a@example.com",
                                       "password": "Passw0rdX", "confirm_password": "Passw0rdX"})
    assert b"already exists" in r.data


def test_login_wrong_password_and_success(client):
    register_and_login(client)
    client.post("/logout")
    assert b"Invalid email or password" in client.post("/login", data={"email": "a@example.com", "password": "nope"}).data
    assert client.post("/login", data={"email": "a@example.com", "password": "Passw0rdX"}).status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_open_redirect_blocked(client):
    register_and_login(client)
    client.post("/logout")
    r = client.post("/login?next=//evil.com", data={"email": "a@example.com", "password": "Passw0rdX"})
    assert "evil.com" not in r.headers["Location"]


def test_scan_requires_authorization_and_valid_target(client):
    register_and_login(client)
    assert client.post("/api/scans", json={"url": "http://localhost:3000", "authorized": False}).status_code == 400
    assert client.post("/api/scans", json={"url": "", "authorized": True}).status_code == 400
    r = client.post("/api/scans", json={"url": "https://not-listed.org", "authorized": True})
    assert r.status_code == 400 and "authorized" in r.get_json()["error"]
    assert client.post("/api/scans", json={"url": "http://169.254.169.254", "authorized": True}).status_code == 400


def test_user_cannot_read_other_users_scans(client, app):
    from database import db
    from models import Scan
    register_and_login(client, "a@example.com")
    with app.app_context():
        s = Scan(user_id=1, target_url="http://localhost:5001/", scan_status="Completed")
        db.session.add(s); db.session.commit(); sid = s.id
    assert client.get(f"/api/scans/{sid}").status_code == 200
    client.post("/logout")
    register_and_login(client, "b@example.com", "Bob Tester")
    for url in (f"/api/scans/{sid}", f"/scan/{sid}", f"/api/scans/{sid}/findings", f"/reports/{sid}/pdf"):
        assert client.get(url).status_code == 404
    assert client.post(f"/api/scans/{sid}/cancel").status_code == 404


def test_csrf_enforced(app):
    app.config["WTF_CSRF_DISABLED"] = False
    c = app.test_client()
    assert c.post("/login", data={"email": "a", "password": "b"}).status_code == 400
