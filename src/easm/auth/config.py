from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ReverseProxyAuthConfig(BaseModel):
    header: str = "X-Forwarded-User"
    trusted_proxies: list[str] = Field(default_factory=list)
    auto_provision: bool = False
    auto_provision_role: str = "viewer"


class LocalAuthConfig(BaseModel):
    session_secret: str
    session_max_age_seconds: int = 86400
    cookie_name: str = "easm_session"
    cookie_secure: bool = True


class SSOProviderConfig(BaseModel):
    provider: Literal["google", "github", "microsoft", "okta"]
    client_id: str
    client_secret: str
    redirect_uri: str | None = None
    session_secret: str | None = None


class ApiKeyConfig(BaseModel):
    enabled: bool = True
    header_name: str = "X-API-Key"


class AuthConfig(BaseModel):
    mode: Literal["none", "reverse_proxy", "local", "sso"] = "none"
    reverse_proxy: ReverseProxyAuthConfig | None = None
    local: LocalAuthConfig | None = None
    sso: SSOProviderConfig | None = None
    api_keys: ApiKeyConfig = Field(default_factory=ApiKeyConfig)

    @model_validator(mode="after")
    def validate_session_secret_for_mode(self) -> AuthConfig:
        if self.mode == "local" and (
            self.local is None or not self.local.session_secret
        ):
            raise ValueError("local mode requires auth.local.session_secret")
        if self.mode == "sso":
            has_sso_secret = self.sso and self.sso.session_secret
            has_local_secret = self.local and self.local.session_secret
            if not has_sso_secret and not has_local_secret:
                raise ValueError(
                    "sso mode requires auth.sso.session_secret or auth.local.session_secret"
                )
        return self
