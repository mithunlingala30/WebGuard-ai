from ai_engine import analyzer, risk_score
from scanner.base import RawFinding


def rf(t, url="http://x.test/", status="observed", param="", hint=0.9, **detail):
    return RawFinding(t, url, f"evidence for {t} {param}", status, param, {"confidence_hint": hint, **detail})


def test_classification_and_owasp():
    out = analyzer.analyze([rf("missing_csp"), rf("sqli_error", status="confirmed", param="id", hint=0.92)])
    by = {f["key"]: f for f in out["findings"]}
    assert by["missing_csp"]["severity"] == "Medium" and "Misconfiguration" in by["missing_csp"]["owasp"]
    assert by["sqli_error"]["severity"] == "Critical" and "Injection" in by["sqli_error"]["owasp"]
    assert out["findings"][0]["key"] == "sqli_error" and out["findings"][0]["priority"] == 1


def test_suspected_sqli_is_downgraded():
    out = analyzer.analyze([rf("sqli_error", status="suspected", param="id", hint=0.6)])
    assert out["findings"][0]["severity"] == "High"


def test_exact_duplicates_merged_and_low_confidence_suppressed():
    out = analyzer.analyze([rf("missing_xcto"), rf("missing_xcto"), rf("xss_reflected", status="suspected", hint=0.1)])
    assert len(out["findings"]) == 1 and out["suppressed"] == 1 and out["duplicates"] == 1


def test_near_duplicates_merged_with_sklearn():
    a = RawFinding("xss_reflected", "http://x.test/a", "Parameter 'q' marker wgab12 reflected raw context", "confirmed", "q", {"confidence_hint": .9})
    b = RawFinding("xss_reflected", "http://x.test/b", "Parameter 'q' marker wgab12 reflected raw context", "confirmed", "q", {"confidence_hint": .9})
    out = analyzer.analyze([a, b])
    assert len(out["findings"]) == 1 and out["findings"][0]["occurrences"] == 2


def test_session_cookie_severity_bump():
    out = analyzer.analyze([rf("cookie_missing_httponly", param="sessionid", is_session=True),
                            rf("cookie_missing_httponly", param="theme", is_session=False)])
    sev = {f["param"]: f["severity"] for f in out["findings"]}
    assert sev["sessionid"] == "Medium" and sev["theme"] == "Low"


def test_risk_score_monotonic_and_bounded():
    none = risk_score.calculate([])
    some = risk_score.calculate([{"severity": "High", "confidence_score": .9}])
    more = risk_score.calculate([{"severity": "Critical", "confidence_score": .9}] * 20)
    assert none["score"] == 0 and none["level"] == "None"
    assert 0 < some["score"] < more["score"] <= 100
