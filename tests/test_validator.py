import pytest

from services.target_validator import TargetError, normalize_url, validate_target


def test_normalize_rejects_bad_input():
    for bad in ["", "   ", "ftp://example.com", "javascript:alert(1)", "http://user:pw@example.com", "http://exa mple.com"]:
        with pytest.raises(TargetError):
            normalize_url(bad)


def test_normalize_adds_scheme_and_strips_fragment():
    assert normalize_url("Example.com/path#frag") == "https://example.com/path"


def test_unauthorized_domain_blocked(app):
    with app.app_context(), pytest.raises(TargetError, match="authorized"):
        validate_target("https://google.com")


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data", "http://10.0.0.5/", "http://192.168.1.1/",
                                 "http://[::1]/", "http://metadata.google.internal/"])
def test_internal_targets_blocked(app, url):
    with app.app_context(), pytest.raises(TargetError):
        validate_target(url)


def test_bad_port_blocked(app):
    with app.app_context(), pytest.raises(TargetError, match="Port"):
        validate_target("http://localhost:22/")


def test_lab_host_allowed_only_in_lab_mode(app):
    with app.app_context():
        assert validate_target("http://localhost:3000/").lab
        app.config["LAB_MODE"] = False
        with pytest.raises(TargetError):
            validate_target("http://localhost:3000/")
