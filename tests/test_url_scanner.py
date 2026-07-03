from detection import url_scanner


def test_raw_ip_url_detected():
    findings = url_scanner.scan("Download it from http://185.220.101.7/payload.exe")
    assert any(f.label == "RAW_IP_URL" for f in findings)


def test_url_shortener_detected():
    findings = url_scanner.scan("Click here: http://bit.ly/abc123")
    assert any(f.label == "URL_SHORTENER" for f in findings)


def test_credential_in_url_detected():
    findings = url_scanner.scan("Connect to http://admin:hunter2@internal.example.com/api")
    assert any(f.label == "CREDENTIAL_IN_URL" for f in findings)


def test_normal_url_has_no_findings():
    findings = url_scanner.scan("Check out https://docs.python.org/3/library/re.html for details.")
    assert findings == []


def test_no_url_present_has_no_findings():
    assert url_scanner.scan("There is no URL in this sentence at all.") == []
