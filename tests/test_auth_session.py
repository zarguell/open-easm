from easm.auth.session import create_session_token, decode_session_token


def test_create_and_decode_token():
    token = create_session_token(
        user_id="abc-123",
        username="admin",
        org_id="default",
        role="admin",
        secret="test-secret-key-at-least-32-chars-long!!",
        max_age_seconds=3600,
    )
    payload = decode_session_token(token, "test-secret-key-at-least-32-chars-long!!")
    assert payload["sub"] == "abc-123"
    assert payload["username"] == "admin"
    assert payload["org_id"] == "default"
    assert payload["role"] == "admin"
    assert payload["iss"] == "open-easm"
    assert payload["aud"] == "open-easm"
    assert "exp" in payload
    assert "iat" in payload


def test_expired_token_raises():
    import jwt

    token = create_session_token(
        user_id="abc-123",
        username="admin",
        org_id="default",
        role="admin",
        secret="test-secret-key-at-least-32-chars-long!!",
        max_age_seconds=-1,
    )
    try:
        decode_session_token(token, "test-secret-key-at-least-32-chars-long!!")
        assert False, "Should have raised"
    except jwt.ExpiredSignatureError:
        pass


def test_wrong_secret_raises():
    import jwt

    token = create_session_token(
        user_id="abc-123",
        username="admin",
        org_id="default",
        role="admin",
        secret="correct-secret-key-at-least-32-chars!!",
        max_age_seconds=3600,
    )
    try:
        decode_session_token(token, "wrong-secret-key-at-least-32-chars!!")
        assert False, "Should have raised"
    except jwt.InvalidSignatureError:
        pass
