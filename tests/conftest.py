import sys
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app          # noqa: E402
from database import db            # noqa: E402


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 't.db').as_posix()}",
        "REPORTS_DIR": str(tmp_path / "reports"), "LAB_MODE": True, "REQUEST_DELAY": 0, "WTF_CSRF_DISABLED": True,
        "AUTHORIZED_DOMAINS": ["example.com"], "ALLOW_ANY_DOMAIN": False,
    })
    yield app
    with app.app_context():
        db.session.remove()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(scope="session")
def lab_site():
    """Starts the intentionally weak local test website on port 5001 for integration tests."""
    from tests.vuln_test_site import app as site
    server = make_server("127.0.0.1", 5001, site, threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:5001"
    server.shutdown()


def register_and_login(client, email="a@example.com", name="Alice Tester", pw="Passw0rdX"):
    client.post("/register", data={"full_name": name, "email": email, "password": pw, "confirm_password": pw})
    return client.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
