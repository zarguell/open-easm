from __future__ import annotations

import pytest

from easm.auth.config import (
    ApiKeyConfig,
    AuthConfig,
    LocalAuthConfig,
    ReverseProxyAuthConfig,
    SSOProviderConfig,
)


def test_default_auth_mode_is_none():
    cfg = AuthConfig()
    assert cfg.mode == "none"


def test_default_api_keys_enabled():
    cfg = AuthConfig()
    assert cfg.api_keys.enabled is True
    assert cfg.api_keys.header_name == "X-API-Key"


def test_reverse_proxy_config():
    cfg = AuthConfig(
        mode="reverse_proxy",
        reverse_proxy=ReverseProxyAuthConfig(
            header="X-Auth-Request-User",
            trusted_proxies=["10.0.0.0/8", "172.16.0.0/12"],
        ),
    )
    assert cfg.mode == "reverse_proxy"
    assert cfg.reverse_proxy.header == "X-Auth-Request-User"
    assert cfg.reverse_proxy.trusted_proxies == ["10.0.0.0/8", "172.16.0.0/12"]


def test_local_auth_config():
    cfg = AuthConfig(
        mode="local",
        local=LocalAuthConfig(
            session_secret="super-secret-key-at-least-32-chars",
            session_max_age_seconds=3600,
        ),
    )
    assert cfg.local.session_secret == "super-secret-key-at-least-32-chars"
    assert cfg.local.session_max_age_seconds == 3600


def test_sso_config():
    cfg = AuthConfig(
        sso=SSOProviderConfig(
            provider="google",
            client_id="abc123",
            client_secret="secret",
        ),
    )
    assert cfg.sso.provider == "google"
    assert cfg.sso.client_id == "abc123"


def test_invalid_mode_rejected():
    with pytest.raises(Exception):
        AuthConfig(mode="invalid")


def test_local_mode_without_local_config():
    """Local mode should work if config is provided."""
    cfg = AuthConfig(
        mode="local",
        local=LocalAuthConfig(session_secret="a" * 32),
    )
    assert cfg.mode == "local"


def test_api_key_custom_header():
    cfg = AuthConfig(
        api_keys=ApiKeyConfig(header_name="Authorization"),
    )
    assert cfg.api_keys.header_name == "Authorization"


def test_local_mode_without_session_secret_rejected():
    """Local mode requires session_secret."""
    with pytest.raises(Exception):
        AuthConfig(mode="local")


def test_sso_mode_without_any_session_secret_rejected():
    """SSO mode requires session_secret via sso or local config."""
    with pytest.raises(Exception):
        AuthConfig(
            mode="sso",
            sso=SSOProviderConfig(
                provider="google",
                client_id="abc",
                client_secret="secret",
            ),
        )


def test_sso_mode_with_sso_session_secret():
    cfg = AuthConfig(
        mode="sso",
        sso=SSOProviderConfig(
            provider="google",
            client_id="abc",
            client_secret="secret",
            session_secret="sso-secret-at-least-32-characters!!",
        ),
    )
    assert cfg.mode == "sso"


def test_reverse_proxy_auto_provision_defaults():
    cfg = ReverseProxyAuthConfig()
    assert cfg.auto_provision is False
    assert cfg.auto_provision_role == "viewer"
