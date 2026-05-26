from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easm.auth.config import SSOProviderConfig


def get_sso_provider(config: SSOProviderConfig):
    """Return an initialized fastapi-sso SSO instance for the configured provider."""
    redirect_uri = config.redirect_uri

    if config.provider == "google":
        from fastapi_sso.sso.google import GoogleSSO

        return GoogleSSO(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri or "http://localhost:8000/api/auth/sso/google/callback",
        )
    elif config.provider == "github":
        from fastapi_sso.sso.github import GithubSSO

        return GithubSSO(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri or "http://localhost:8000/api/auth/sso/github/callback",
        )
    elif config.provider == "microsoft":
        from fastapi_sso.sso.microsoft import MicrosoftSSO

        return MicrosoftSSO(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri or "http://localhost:8000/api/auth/sso/microsoft/callback",
        )
    else:
        raise ValueError(f"Unsupported SSO provider: {config.provider}")
