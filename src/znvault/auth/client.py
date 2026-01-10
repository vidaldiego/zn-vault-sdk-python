# Path: zn-vault-sdk-python/src/znvault/auth/client.py
"""Authentication client for ZnVault."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from znvault.models.auth import (
    AuthResult,
    User,
    ApiKey,
    ApiKeyConditions,
    ManagedApiKey,
    ManagedKeyBindResponse,
    ManagedKeyRotateResponse,
    RotationMode,
    RegistrationToken,
    CreateRegistrationTokenResponse,
    BootstrapResponse,
)
from znvault.models.common import Page

if TYPE_CHECKING:
    from znvault.http.client import HttpClient


class AuthClient:
    """Client for authentication operations."""

    def __init__(self, http: "HttpClient") -> None:
        """Initialize the auth client."""
        self._http = http

    def login(
        self,
        username: str,
        password: str,
        totp_code: str | None = None,
        tenant: str | None = None,
    ) -> AuthResult:
        """
        Authenticate with username and password.

        The username must include the tenant prefix in the format `tenant/username`
        (e.g., "acme/admin"). This allows multiple tenants to have users with the
        same username. Email addresses can also be used as username.

        Alternatively, you can provide the `tenant` parameter separately, and the
        SDK will format the username automatically.

        Args:
            username: The username in format "tenant/username" or email address.
            password: The password to authenticate with.
            totp_code: Optional TOTP code if 2FA is enabled.
            tenant: Optional tenant (if provided, will be prefixed to username).

        Returns:
            AuthResult containing access and refresh tokens.
        """
        # If tenant is provided separately, format as "tenant/username"
        full_username = f"{tenant}/{username}" if tenant else username

        data = {"username": full_username, "password": password}
        if totp_code:
            data["totpCode"] = totp_code

        response = self._http.post("/auth/login", data)
        result = AuthResult.from_dict(response)

        # Store tokens in HTTP client
        self._http.set_tokens(result.access_token, result.refresh_token)

        return result

    def login_with_tenant(
        self,
        tenant: str,
        username: str,
        password: str,
        totp_code: str | None = None,
    ) -> AuthResult:
        """
        Authenticate with tenant and username as separate parameters.

        Convenience method that formats the username as "tenant/username".

        Args:
            tenant: Tenant identifier (e.g., "acme").
            username: Username within the tenant (e.g., "admin").
            password: The password to authenticate with.
            totp_code: Optional TOTP code if 2FA is enabled.

        Returns:
            AuthResult containing access and refresh tokens.
        """
        return self.login(username, password, totp_code, tenant)

    def refresh(self, refresh_token: str | None = None) -> AuthResult:
        """
        Refresh the access token.

        Args:
            refresh_token: The refresh token. If not provided, uses stored token.

        Returns:
            AuthResult with new tokens.
        """
        token = refresh_token or self._http.refresh_token
        if not token:
            raise ValueError("No refresh token available")

        response = self._http.post("/auth/refresh", {"refreshToken": token})
        result = AuthResult.from_dict(response)

        # Update stored tokens
        self._http.set_tokens(result.access_token, result.refresh_token)

        return result

    def logout(self) -> None:
        """Log out and invalidate tokens."""
        try:
            self._http.post("/auth/logout", {})
        finally:
            self._http.clear_tokens()

    def me(self) -> User:
        """
        Get the current authenticated user.

        Returns:
            The current user information.
        """
        response = self._http.get("/auth/me")
        # API returns {user: {...}}
        user_data = response.get("user", response)
        return User.from_dict(user_data)

    def register(
        self,
        username: str,
        password: str,
        email: str | None = None,
    ) -> User:
        """
        Register a new user.

        Args:
            username: The username for the new user.
            password: The password for the new user.
            email: Optional email address.

        Returns:
            The created user.
        """
        data = {"username": username, "password": password}
        if email:
            data["email"] = email

        response = self._http.post("/auth/register", data)
        return User.from_dict(response.get("user", response))

    def create_api_key(
        self,
        name: str,
        permissions: list[str],
        *,
        expires_in_days: int | None = None,
        ip_allowlist: list[str] | None = None,
        conditions: ApiKeyConditions | None = None,
        tenant_id: str | None = None,
        description: str | None = None,
    ) -> ApiKey:
        """
        Create a new API key.

        Args:
            name: Name for the API key.
            permissions: List of permissions (required).
            expires_in_days: Optional expiration in days.
            ip_allowlist: Optional list of allowed IPs/CIDRs.
            conditions: Optional inline ABAC conditions.
            tenant_id: Required for superadmin creating tenant-scoped keys.
            description: Optional description.

        Returns:
            The created API key (includes the key value only on creation).
        """
        data: dict[str, Any] = {"name": name, "permissions": permissions}
        if expires_in_days is not None:
            data["expiresInDays"] = expires_in_days
        if ip_allowlist:
            data["ipAllowlist"] = ip_allowlist
        if description:
            data["description"] = description
        if conditions:
            # Convert snake_case to camelCase for API
            api_conditions: dict[str, Any] = {}
            if "ip" in conditions:
                api_conditions["ip"] = conditions["ip"]
            if "time_range" in conditions:
                api_conditions["timeRange"] = conditions["time_range"]
            if "methods" in conditions:
                api_conditions["methods"] = conditions["methods"]
            if "resources" in conditions:
                api_conditions["resources"] = conditions["resources"]
            if "aliases" in conditions:
                api_conditions["aliases"] = conditions["aliases"]
            if "resource_tags" in conditions:
                api_conditions["resourceTags"] = conditions["resource_tags"]
            data["conditions"] = api_conditions

        # Tenant ID is passed as query parameter
        path = "/auth/api-keys"
        if tenant_id:
            path = f"/auth/api-keys?tenantId={tenant_id}"

        response = self._http.post(path, data)
        return ApiKey.from_dict(response)

    def list_api_keys(self) -> list[ApiKey]:
        """
        List all API keys for the current user.

        Returns:
            List of API keys.
        """
        response = self._http.get("/auth/api-keys")
        keys = response if isinstance(response, list) else response.get("keys", [])
        return [ApiKey.from_dict(k) for k in keys]

    def revoke_api_key(self, key_id: str) -> None:
        """
        Revoke an API key.

        Args:
            key_id: The ID of the API key to revoke.
        """
        self._http.delete(f"/auth/api-keys/{key_id}")

    def enable_totp(self) -> dict:
        """
        Enable TOTP 2FA for the current user.

        Returns:
            TOTP setup information (secret, QR code URL).
        """
        response = self._http.post("/auth/2fa/enable", {})
        return response

    def verify_totp(self, code: str) -> bool:
        """
        Verify TOTP code to complete 2FA setup.

        Args:
            code: The TOTP code to verify.

        Returns:
            True if verification succeeded.
        """
        response = self._http.post("/auth/2fa/verify", {"code": code})
        return response.get("verified", False)

    def disable_totp(self, code: str) -> None:
        """
        Disable TOTP 2FA for the current user.

        Args:
            code: TOTP code for verification.
        """
        self._http.post("/auth/2fa/disable", {"code": code})

    def rotate_api_key(self, key_id: str) -> ApiKey:
        """
        Rotate an API key by ID.

        This creates a new API key with the same configuration and revokes the old one.

        Args:
            key_id: The ID of the API key to rotate.

        Returns:
            The new API key (includes the key value only on creation).
        """
        response = self._http.post(f"/auth/api-keys/{key_id}/rotate", {})
        return ApiKey.from_dict(response)

    def get_current_api_key(self) -> ApiKey:
        """
        Get information about the current API key (when authenticated via API key).

        Returns:
            The current API key information.
        """
        response = self._http.get("/auth/api-keys/self")
        return ApiKey.from_dict(response)

    def rotate_current_api_key(self) -> ApiKey:
        """
        Rotate the current API key (self-rotation when authenticated via API key).

        This creates a new API key with the same configuration and revokes the current one.

        Returns:
            The new API key (includes the key value only on creation).
        """
        response = self._http.post("/auth/api-keys/self/rotate", {})
        return ApiKey.from_dict(response)

    # =========================================================================
    # Managed API Keys
    # =========================================================================

    def create_managed_api_key(
        self,
        name: str,
        permissions: list[str],
        rotation_mode: RotationMode,
        *,
        rotation_interval: str | None = None,
        grace_period: str | None = None,
        description: str | None = None,
        expires_in_days: int | None = None,
        tenant_id: str | None = None,
    ) -> ManagedApiKey:
        """
        Create a managed API key with auto-rotation configuration.

        Managed keys automatically rotate based on the configured mode:
        - scheduled: Rotates at fixed intervals (requires rotation_interval)
        - on-use: Rotates after being used (TTL resets on each use)
        - on-bind: Rotates each time bind is called

        Args:
            name: Unique name for the managed key.
            permissions: List of permissions for the key.
            rotation_mode: Rotation mode (scheduled, on-use, on-bind).
            rotation_interval: Interval for scheduled rotation (e.g., "24h", "7d").
            grace_period: Grace period for smooth transitions (e.g., "5m").
            description: Optional description.
            expires_in_days: Optional expiration in days.
            tenant_id: Required for superadmin creating tenant-scoped keys.

        Returns:
            The created managed key metadata (use bind to get the key value).
        """
        data: dict[str, Any] = {
            "name": name,
            "permissions": permissions,
            "rotationMode": rotation_mode,
        }
        if rotation_interval:
            data["rotationInterval"] = rotation_interval
        if grace_period:
            data["gracePeriod"] = grace_period
        if description:
            data["description"] = description
        if expires_in_days is not None:
            data["expiresInDays"] = expires_in_days

        path = "/auth/api-keys/managed"
        if tenant_id:
            path = f"/auth/api-keys/managed?tenantId={tenant_id}"

        response = self._http.post(path, data)
        api_key_data = response.get("apiKey", response)
        return ManagedApiKey.from_dict(api_key_data)

    def list_managed_api_keys(
        self,
        tenant_id: str | None = None,
    ) -> list[ManagedApiKey]:
        """
        List managed API keys.

        Args:
            tenant_id: Optional tenant ID filter (for superadmin).

        Returns:
            List of managed keys.
        """
        path = "/auth/api-keys/managed"
        if tenant_id:
            path = f"/auth/api-keys/managed?tenantId={tenant_id}"

        response = self._http.get(path)
        keys = response.get("keys", [])
        return [ManagedApiKey.from_dict(k) for k in keys]

    def get_managed_api_key(
        self,
        name: str,
        tenant_id: str | None = None,
    ) -> ManagedApiKey:
        """
        Get a managed API key by name.

        Args:
            name: The managed key name.
            tenant_id: Optional tenant ID (for cross-tenant access).

        Returns:
            The managed key metadata.
        """
        from urllib.parse import quote

        path = f"/auth/api-keys/managed/{quote(name, safe='')}"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        response = self._http.get(path)
        return ManagedApiKey.from_dict(response)

    def bind_managed_api_key(
        self,
        name: str,
        tenant_id: str | None = None,
    ) -> ManagedKeyBindResponse:
        """
        Bind to a managed API key to get the current key value.

        This is the primary method for agents to obtain their API key.
        The response includes rotation metadata to help determine when
        to re-bind for a new key.

        Security: This endpoint requires the caller to already have a valid
        API key (the current one, even during grace period). This prevents
        unauthorized access to managed keys.

        Args:
            name: The managed key name.
            tenant_id: Optional tenant ID (for cross-tenant access).

        Returns:
            The current key value and rotation metadata.
        """
        from urllib.parse import quote

        path = f"/auth/api-keys/managed/{quote(name, safe='')}/bind"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        response = self._http.post(path, {})
        return ManagedKeyBindResponse.from_dict(response)

    def rotate_managed_api_key(
        self,
        name: str,
        tenant_id: str | None = None,
    ) -> ManagedKeyRotateResponse:
        """
        Force rotate a managed API key.

        Creates a new key immediately, regardless of the rotation schedule.
        The old key remains valid during the grace period.

        Args:
            name: The managed key name.
            tenant_id: Optional tenant ID (for cross-tenant access).

        Returns:
            The new key value and rotation info.
        """
        from urllib.parse import quote

        path = f"/auth/api-keys/managed/{quote(name, safe='')}/rotate"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        response = self._http.post(path, {})
        return ManagedKeyRotateResponse.from_dict(response)

    def update_managed_api_key_config(
        self,
        name: str,
        *,
        rotation_interval: str | None = None,
        grace_period: str | None = None,
        enabled: bool | None = None,
        tenant_id: str | None = None,
    ) -> ManagedApiKey:
        """
        Update managed API key configuration.

        Args:
            name: The managed key name.
            rotation_interval: New rotation interval.
            grace_period: New grace period.
            enabled: Enable/disable the key.
            tenant_id: Optional tenant ID (for cross-tenant access).

        Returns:
            Updated managed key metadata.
        """
        from urllib.parse import quote

        data: dict[str, Any] = {}
        if rotation_interval is not None:
            data["rotationInterval"] = rotation_interval
        if grace_period is not None:
            data["gracePeriod"] = grace_period
        if enabled is not None:
            data["enabled"] = enabled

        path = f"/auth/api-keys/managed/{quote(name, safe='')}/config"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        response = self._http.patch(path, data)
        return ManagedApiKey.from_dict(response)

    def delete_managed_api_key(
        self,
        name: str,
        tenant_id: str | None = None,
    ) -> None:
        """
        Delete a managed API key.

        Args:
            name: The managed key name.
            tenant_id: Optional tenant ID (for cross-tenant access).
        """
        from urllib.parse import quote

        path = f"/auth/api-keys/managed/{quote(name, safe='')}"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        self._http.delete(path)

    # =========================================================================
    # Registration Tokens (Agent Bootstrap)
    # =========================================================================

    def create_registration_token(
        self,
        managed_key_name: str,
        *,
        expires_in: str | None = None,
        description: str | None = None,
        tenant_id: str | None = None,
    ) -> CreateRegistrationTokenResponse:
        """
        Create a registration token for agent bootstrapping.

        Registration tokens are one-time use tokens that allow agents to
        obtain their managed API key without prior authentication.

        Args:
            managed_key_name: The managed key to create a token for.
            expires_in: Token expiration (e.g., "1h", "24h"). Min 1m, max 24h.
            description: Optional description for audit trail.
            tenant_id: Optional tenant ID (for cross-tenant access).

        Returns:
            The created token (shown only once - save it immediately!).
        """
        from urllib.parse import quote

        data: dict[str, Any] = {}
        if expires_in:
            data["expiresIn"] = expires_in
        if description:
            data["description"] = description

        path = f"/auth/api-keys/managed/{quote(managed_key_name, safe='')}/registration-tokens"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        response = self._http.post(path, data)
        return CreateRegistrationTokenResponse.from_dict(response)

    def list_registration_tokens(
        self,
        managed_key_name: str,
        *,
        include_used: bool = False,
        tenant_id: str | None = None,
    ) -> list[RegistrationToken]:
        """
        List registration tokens for a managed key.

        Args:
            managed_key_name: The managed key name.
            include_used: Include tokens that have been used.
            tenant_id: Optional tenant ID (for cross-tenant access).

        Returns:
            List of registration tokens.
        """
        from urllib.parse import quote, urlencode

        params: dict[str, str] = {}
        if include_used:
            params["includeUsed"] = "true"
        if tenant_id:
            params["tenantId"] = tenant_id

        path = f"/auth/api-keys/managed/{quote(managed_key_name, safe='')}/registration-tokens"
        if params:
            path = f"{path}?{urlencode(params)}"

        response = self._http.get(path)
        tokens = response.get("tokens", [])
        return [RegistrationToken.from_dict(t) for t in tokens]

    def revoke_registration_token(
        self,
        managed_key_name: str,
        token_id: str,
        tenant_id: str | None = None,
    ) -> None:
        """
        Revoke a registration token.

        Prevents the token from being used for bootstrapping.

        Args:
            managed_key_name: The managed key name.
            token_id: The token ID to revoke.
            tenant_id: Optional tenant ID (for cross-tenant access).
        """
        from urllib.parse import quote

        path = f"/auth/api-keys/managed/{quote(managed_key_name, safe='')}/registration-tokens/{token_id}"
        if tenant_id:
            path = f"{path}?tenantId={tenant_id}"

        self._http.delete(path)

    def bootstrap(self, token: str) -> BootstrapResponse:
        """
        Bootstrap an agent using a registration token.

        This is the unauthenticated endpoint used by agents to exchange a
        one-time registration token for a managed API key binding.

        Note: This method does not require prior authentication.

        Args:
            token: The registration token (format: zrt_...).

        Returns:
            The API key binding response.
        """
        response = self._http.post("/agent/bootstrap", {"token": token})
        return BootstrapResponse.from_dict(response)
