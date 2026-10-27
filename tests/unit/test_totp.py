from packages.crypto.totp import generate_totp_secret, totp_code, verify_totp


def test_totp_roundtrip():
    s = generate_totp_secret()
    c = totp_code(s, at=1_000_000)
    assert verify_totp(s, c, at=1_000_000)
    assert not verify_totp(s, "000000", at=1_000_000) or c == "000000"
