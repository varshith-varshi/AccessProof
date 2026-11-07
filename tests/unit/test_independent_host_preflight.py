from scripts.certifier import independent_host_preflight as p

INSTANCE = "i-0123456789abcdef0"
ROLE = "arn:aws:iam::102076848988:role/AccessProofCertifierExec"
KEY = "arn:aws:kms:eu-north-1:102076848988:key/12345678-1234-1234-1234-1234567890ab"


def test_good_host_identity_and_public_key_never_claims_signing(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-certifier")
    for name in ("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN","AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(p, "imds_instance_id", lambda: INSTANCE)
    def mock_aws(*args):
        if args[:2] == ("sts", "get-caller-identity"):
            return {"Arn": "arn:aws:sts::102076848988:assumed-role/AccessProofCertifierExec/i-123"}
        if args[:2] == ("kms", "get-public-key"):
            return {"KeyId":KEY, "KeySpec":"ECC_NIST_EDWARDS25519",
                    "KeyUsage":"SIGN_VERIFY", "SigningAlgorithms":["ED25519_SHA_512"]}
        raise AssertionError("Not a read-only request")
    monkeypatch.setattr(p, "aws_read_only", mock_aws)
    result = p.report(expected_instance=INSTANCE, role_arn=ROLE, key_arn=KEY)
    assert result["host_prerequisites"] == "PASS"
    for field in ("signing_enabled","production_import_enabled","trust_pin_verified",
                  "employee_authorization_verified","customer_route_independent","migration_complete"):
        assert result[field] is False


def test_static_aws_credentials_fail_closed_without_signing_or_cloud_calls(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-certifier")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "unexpected")
    monkeypatch.setattr(p, "imds_instance_id", lambda: INSTANCE)
    monkeypatch.setattr(p, "aws_read_only", lambda *args: (_ for _ in ()).throw(AssertionError("Called AWS")))
    result = p.report(expected_instance=INSTANCE, role_arn=ROLE, key_arn=KEY)
    assert result["host_prerequisites"] == "BLOCKED"


def test_laptop_and_known_staging_host_rejected(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-certifier")
    monkeypatch.setattr(p, "imds_instance_id", lambda: "i-0e6d2256a1e5a6f67")
    monkeypatch.setattr(p, "aws_read_only", lambda *args: (_ for _ in ()).throw(AssertionError("Called AWS")))
    result = p.report(expected_instance="i-0e6d2256a1e5a6f67", role_arn=ROLE, key_arn=KEY)
    assert result["host_prerequisites"] == "BLOCKED"


def test_wrong_aws_account_and_key_format_short_circuit(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-certifier")
    monkeypatch.setattr(p, "imds_instance_id", lambda: (_ for _ in ()).throw(AssertionError("IMDS called")))
    result = p.report(expected_instance=INSTANCE, role_arn=ROLE,
                      key_arn=KEY.replace("102076848988", "111122223333"))
    assert result["host_prerequisites"] == "BLOCKED"
