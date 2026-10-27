from packages.crypto.passwords import hash_password, verify_password
from packages.crypto.secrets import SecretBox


def test_password_hashing():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong password", h)


def test_secret_box_authenticated_encryption():
    box = SecretBox.from_text("unit-test-secret")
    c = box.encrypt("very-secret")
    assert "very-secret" not in c
    assert box.decrypt(c) == "very-secret"
