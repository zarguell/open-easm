from easm.auth.api_keys import generate_api_key, hash_api_key, verify_api_key, _get_pepper


def test_generate_api_key_format():
    raw, prefix, key_hash = generate_api_key()
    assert raw.startswith("easm_")
    assert len(raw) > 40
    assert prefix == raw[:12]
    assert len(key_hash) == 64  # HMAC-SHA256 hex


def test_generate_api_key_unique():
    r1, _, h1 = generate_api_key()
    r2, _, h2 = generate_api_key()
    assert r1 != r2
    assert h1 != h2


def test_hash_api_key_deterministic():
    raw = "easm_testkey1234567890abcdef"
    h1 = hash_api_key(raw)
    h2 = hash_api_key(raw)
    assert h1 == h2
    assert len(h1) == 64


def test_verify_api_key_against_hash():
    raw, _, key_hash = generate_api_key()
    assert verify_api_key(raw, key_hash) is True
    assert verify_api_key("easm_wrongkey", key_hash) is False


def test_pepper_makes_hash_opaque():
    """Without the pepper, raw SHA-256 would not match our hash."""
    import hashlib

    raw, _, key_hash = generate_api_key()
    plain_sha = hashlib.sha256(raw.encode()).hexdigest()
    assert plain_sha != key_hash
