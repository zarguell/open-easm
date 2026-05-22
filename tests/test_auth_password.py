from easm.auth.password import hash_password, verify_password


def test_hash_password_returns_bcrypt():
    hashed = hash_password("test_password")
    assert hashed.startswith("$2b$")


def test_verify_password_correct():
    hashed = hash_password("my_secret")
    assert verify_password("my_secret", hashed) is True


def test_verify_password_wrong():
    hashed = hash_password("my_secret")
    assert verify_password("wrong", hashed) is False


def test_different_hashes_for_same_password():
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2  # bcrypt uses random salt
