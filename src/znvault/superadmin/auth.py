# Path: zn-vault-sdk-python/src/znvault/superadmin/auth.py
"""Superadmin auth operations for cross-tenant API key management.

**Server requirement:** these methods call routes under
`/v1/superadmin/api-keys/` (including the `managed/` sub-tree). Those
routes are not yet implemented on the server (as of vault 1.38.8); calls
will return 404 until they ship.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from znvault.models.auth import (
    ApiKey,
    ManagedApiKey,
    ManagedKeyRotateResponse,
    RegistrationToken,
    CreateRegistrationTokenResponse,
    RotationMode,
)

if TYPE_CHECKING:
    from znvault.http.client import HttpClient


class SuperadminAuthClient:
    """Superadmin-only auth operations for cross-tenant API key and
    registration token management."""

    def __init__(self, http: "HttpClient") -> None:
        self._http = http

    # ==================== API Keys ====================

    def create_api_key(
        self,
        tenant_id: str,
        name: str,
        permissions: list[str],
        *,
        expires_in_days: int | None = None,
        description: str | None = None,
    ) -> ApiKey:
        """Create a regular API key in any tenant."""
        data: dict[str, Any] = {"name": name, "permissions": permissions}
        if expires_in_days is not None:
            data["expiresInDays"] = expires_in_days
        if description:
            data["description"] = description
        response = self._http.post(
            f"/v1/superadmin/api-keys?tenantId={quote(tenant_id, safe='')}",
            data,
        )
        return ApiKey.from_dict(response)

    def list_api_keys(self, tenant_id: str) -> list[ApiKey]:
        """List API keys for any tenant."""
        response = self._http.get(
            f"/v1/superadmin/api-keys?tenantId={quote(tenant_id, safe='')}"
        )
        items = response.get("items", []) if isinstance(response, dict) else response
        return [ApiKey.from_dict(k) for k in items]

    def delete_api_key(self, key_id: str) -> None:
        """Delete an API key (server resolves tenant from the key record)."""
        self._http.delete(f"/v1/superadmin/api-keys/{key_id}")

    # ==================== Managed API Keys ====================

    def create_managed_api_key(
        self,
        tenant_id: str,
        name: str,
        permissions: list[str],
        rotation_mode: RotationMode,
        *,
        rotation_interval: str | None = None,
        grace_period: str | None = None,
        description: str | None = None,
        expires_in_days: int | None = None,
    ) -> ManagedApiKey:
        """Create a managed API key in any tenant."""
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
        response = self._http.post(
            f"/v1/superadmin/api-keys/managed?tenantId={quote(tenant_id, safe='')}",
            data,
        )
        return ManagedApiKey.from_dict(response.get("apiKey", response))

    def list_managed_api_keys(self, tenant_id: str) -> list[ManagedApiKey]:
        """List managed API keys in any tenant."""
        response = self._http.get(
            f"/v1/superadmin/api-keys/managed?tenantId={quote(tenant_id, safe='')}"
        )
        return [ManagedApiKey.from_dict(k) for k in response.get("items", [])]

    def get_managed_api_key(self, tenant_id: str, name: str) -> ManagedApiKey:
        """Get a managed API key by name in any tenant."""
        response = self._http.get(
            f"/v1/superadmin/api-keys/managed/{quote(name, safe='')}?tenantId={quote(tenant_id, safe='')}"
        )
        return ManagedApiKey.from_dict(response)

    def rotate_managed_api_key(
        self, tenant_id: str, name: str
    ) -> ManagedKeyRotateResponse:
        """Force rotate a managed API key in any tenant."""
        response = self._http.post(
            f"/v1/superadmin/api-keys/managed/{quote(name, safe='')}/rotate?tenantId={quote(tenant_id, safe='')}",
            {},
        )
        return ManagedKeyRotateResponse.from_dict(response)

    def update_managed_api_key_config(
        self,
        tenant_id: str,
        name: str,
        *,
        rotation_interval: str | None = None,
        grace_period: str | None = None,
        enabled: bool | None = None,
    ) -> ManagedApiKey:
        """Update managed API key configuration in any tenant."""
        data: dict[str, Any] = {}
        if rotation_interval is not None:
            data["rotationInterval"] = rotation_interval
        if grace_period is not None:
            data["gracePeriod"] = grace_period
        if enabled is not None:
            data["enabled"] = enabled
        response = self._http.patch(
            f"/v1/superadmin/api-keys/managed/{quote(name, safe='')}/config?tenantId={quote(tenant_id, safe='')}",
            data,
        )
        return ManagedApiKey.from_dict(response)

    def delete_managed_api_key(self, tenant_id: str, name: str) -> None:
        """Delete a managed API key in any tenant."""
        self._http.delete(
            f"/v1/superadmin/api-keys/managed/{quote(name, safe='')}?tenantId={quote(tenant_id, safe='')}"
        )

    # ==================== Registration Tokens ====================

    def create_registration_token(
        self,
        tenant_id: str,
        managed_key_name: str,
        *,
        expires_in: str | None = None,
        description: str | None = None,
    ) -> CreateRegistrationTokenResponse:
        """Create a registration token for any tenant's managed key."""
        data: dict[str, Any] = {}
        if expires_in:
            data["expiresIn"] = expires_in
        if description:
            data["description"] = description
        response = self._http.post(
            f"/v1/superadmin/api-keys/managed/{quote(managed_key_name, safe='')}/registration-tokens?tenantId={quote(tenant_id, safe='')}",
            data,
        )
        return CreateRegistrationTokenResponse.from_dict(response)

    def list_registration_tokens(
        self,
        tenant_id: str,
        managed_key_name: str,
        *,
        include_used: bool = False,
    ) -> list[RegistrationToken]:
        """List registration tokens for any tenant's managed key."""
        include_used_q = "&includeUsed=true" if include_used else ""
        response = self._http.get(
            f"/v1/superadmin/api-keys/managed/{quote(managed_key_name, safe='')}/registration-tokens?tenantId={quote(tenant_id, safe='')}{include_used_q}"
        )
        tokens = response.get("tokens", [])
        return [RegistrationToken.from_dict(t) for t in tokens]

    def revoke_registration_token(
        self,
        tenant_id: str,
        managed_key_name: str,
        token_id: str,
    ) -> None:
        """Revoke a registration token in any tenant."""
        self._http.delete(
            f"/v1/superadmin/api-keys/managed/{quote(managed_key_name, safe='')}/registration-tokens/{token_id}?tenantId={quote(tenant_id, safe='')}"
        )
