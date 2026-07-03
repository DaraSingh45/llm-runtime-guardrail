from detection.dlp_scanner import DlpScanner, _luhn_valid


def test_luhn_validates_known_test_card_number():
    assert _luhn_valid("4111111111111111") is True


def test_luhn_rejects_invalid_number():
    assert _luhn_valid("1234567812345678") is False


def test_email_detected():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("Contact me at jane.doe@example.com please.")
    assert any(f.label == "EMAIL_ADDRESS" for f in findings)


def test_aws_access_key_detected():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("Here is the key: AKIAIOSFODNN7EXAMPLE")
    assert any(f.label == "AWS_ACCESS_KEY_ID" and f.severity == "CRITICAL" for f in findings)


def test_credit_card_detected_when_luhn_valid():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("My card number is 4111 1111 1111 1111 for the order.")
    assert any(f.label == "CREDIT_CARD_NUMBER" for f in findings)


def test_random_digit_string_not_flagged_as_credit_card():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("The invoice number is 1234567890123 for reference.")
    assert not any(f.label == "CREDIT_CARD_NUMBER" for f in findings)


def test_private_key_block_detected():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB...\n-----END RSA PRIVATE KEY-----")
    assert any(f.label == "PRIVATE_KEY_BLOCK" for f in findings)


def test_redacted_span_never_contains_full_secret():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("Key: AKIAIOSFODNN7EXAMPLE")
    aws_finding = next(f for f in findings if f.label == "AWS_ACCESS_KEY_ID")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_finding.redacted_span
    assert "*" in aws_finding.redacted_span


def test_benign_text_has_no_dlp_findings():
    scanner = DlpScanner(enable_ner=False)
    assert scanner.scan("What's a good recipe for vegetable biryani?") == []


def test_ner_disabled_does_not_crash_and_still_runs_regex_layer():
    scanner = DlpScanner(enable_ner=False)
    findings = scanner.scan("test AKIAIOSFODNN7EXAMPLE")
    assert any(f.label == "AWS_ACCESS_KEY_ID" for f in findings)


def test_ner_missing_model_fails_soft_not_hard():
    # enable_ner=True but the model likely isn't installed in this test
    # environment -- DlpScanner must not raise, just skip the NER layer.
    scanner = DlpScanner(enable_ner=True)
    findings = scanner.scan("AKIAIOSFODNN7EXAMPLE")
    assert any(f.label == "AWS_ACCESS_KEY_ID" for f in findings)
