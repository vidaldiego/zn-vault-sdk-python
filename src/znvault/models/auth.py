# Path: zn-vault-sdk-python/src/znvault/models/auth.py
"""Authentication models."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, TypedDict

# Rotation mode for managed API keys
RotationMode = Literal["scheduled", "on-use", "on-bind"]


class ApiKeyTimeRange(TypedDict, total=False):
    """Time range condition for API key access."""

    start: str  # e.g., "09:00"
    end: str  # e.g., "17:00"
    timezone: str  # e.g., "UTC"


class ApiKeyResourceConditions(TypedDict, total=False):
    """Resource-specific conditions."""

    certificates: list[str]
    secrets: list[str]


class ApiKeyConditions(TypedDict, total=False):
    """Inline ABAC conditions for API keys."""

    ip: list[str]  # IP/CIDR allowlist
    time_range: ApiKeyTimeRange
    methods: list[str]  # HTTP methods allowed
    resources: ApiKeyResourceConditions  # Specific resource IDs
    aliases: list[str]  # Glob patterns for aliases
    resource_tags: dict[str, str]  # Tag matching


@dataclass
class AuthResult:
    """Authentication result from login."""

    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"
    requires_totp: bool = False
    user: "User | None" = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthResult":
        """Create from API response dictionary."""
        user_data = data.get("user")
        return cls(
            access_token=data.get("accessToken", ""),
            refresh_token=data.get("refreshToken", ""),
            expires_in=data.get("expiresIn", 3600),
            token_type=data.get("tokenType", "Bearer"),
            requires_totp=data.get("requiresTotp", False),
            user=User.from_dict(user_data) if user_data else None,
        )


@dataclass
class User:
    """User account information."""

    id: str
    username: str
    email: str | None = None
    role: str | None = None
    tenant_id: str | None = None
    totp_enabled: bool = False
    status: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_login: datetime | None = None
    permissions: list[str] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "User":
        """Create from API response dictionary."""
        return cls(
            id=data.get("id", data.get("userId", "")),
            username=data.get("username", ""),
            email=data.get("email"),
            role=data.get("role"),
            tenant_id=data.get("tenantId", data.get("tenant_id")),
            totp_enabled=data.get("totp_enabled", data.get("totpEnabled", False)),
            status=data.get("status"),
            created_at=_parse_datetime(data.get("createdAt")),
            updated_at=_parse_datetime(data.get("updatedAt")),
            last_login=_parse_datetime(data.get("lastLogin")),
            permissions=data.get("permissions", []),
            roles=data.get("roles", []),
        )


@dataclass
class ApiKey:
    """API key information."""

    id: str
    name: str
    key_prefix: str
    key: str | None = None  # Only returned on creation
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used: datetime | None = None
    tenant_id: str | None = None
    permissions: list[str] = field(default_factory=list)
    ip_allowlist: list[str] = field(default_factory=list)
    conditions: ApiKeyConditions | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApiKey":
        """Create from API response dictionary."""
        # Parse conditions if present
        conditions_data = data.get("conditions")
        conditions: ApiKeyConditions | None = None
        if conditions_data:
            conditions = ApiKeyConditions(
                ip=conditions_data.get("ip"),
                time_range=conditions_data.get("timeRange"),
                methods=conditions_data.get("methods"),
                resources=conditions_data.get("resources"),
                aliases=conditions_data.get("aliases"),
                resource_tags=conditions_data.get("resourceTags"),
            )

        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            key_prefix=data.get("keyPrefix", data.get("prefix", "")),
            key=data.get("key", data.get("apiKey")),
            created_at=_parse_datetime(data.get("createdAt")),
            expires_at=_parse_datetime(data.get("expiresAt")),
            last_used=_parse_datetime(data.get("lastUsed")),
            tenant_id=data.get("tenantId"),
            permissions=data.get("permissions", []),
            ip_allowlist=data.get("ipAllowlist", []),
            conditions=conditions,
        )


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse ISO datetime string."""
    if not value:
        return None
    try:
        # Handle ISO format with or without microseconds
        if "." in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# ============================================================================
# Managed API Keys
# ============================================================================


@dataclass
class ManagedApiKey:
    """
    Managed API key with auto-rotation configuration.

    Managed keys automatically rotate based on the configured mode:
    - scheduled: Rotates at fixed intervals (e.g., every 24 hours)
    - on-use: Rotates after being used (TTL resets on each use)
    - on-bind: Rotates each time bind is called
    """

    id: str
    name: str
    tenant_id: str
    permissions: list[str]
    rotation_mode: RotationMode
    grace_period: str
    enabled: bool
    created_at: datetime | None = None
    description: str | None = None
    rotation_interval: str | None = None
    last_rotated_at: datetime | None = None
    next_rotation_at: datetime | None = None
    created_by: str | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManagedApiKey":
        """Create from API response dictionary."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            tenant_id=data.get("tenantId", ""),
            permissions=data.get("permissions", []),
            rotation_mode=data.get("rotationMode", "scheduled"),
            grace_period=data.get("gracePeriod", "5m"),
            enabled=data.get("enabled", True),
            created_at=_parse_datetime(data.get("createdAt")),
            description=data.get("description"),
            rotation_interval=data.get("rotationInterval"),
            last_rotated_at=_parse_datetime(data.get("lastRotatedAt")),
            next_rotation_at=_parse_datetime(data.get("nextRotationAt")),
            created_by=data.get("createdBy"),
            updated_at=_parse_datetime(data.get("updatedAt")),
        )


@dataclass
class ManagedKeyBindResponse:
    """
    Response from binding to a managed API key.

    This is what agents use to get the current key value and rotation metadata.
    """

    id: str
    key: str
    prefix: str
    name: str
    expires_at: datetime | None
    grace_period: str
    rotation_mode: RotationMode
    permissions: list[str]
    next_rotation_at: datetime | None = None
    grace_expires_at: datetime | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManagedKeyBindResponse":
        """Create from API response dictionary."""
        return cls(
            id=data.get("id", ""),
            key=data.get("key", ""),
            prefix=data.get("prefix", ""),
            name=data.get("name", ""),
            expires_at=_parse_datetime(data.get("expiresAt")),
            grace_period=data.get("gracePeriod", "5m"),
            rotation_mode=data.get("rotationMode", "scheduled"),
            permissions=data.get("permissions", []),
            next_rotation_at=_parse_datetime(data.get("nextRotationAt")),
            grace_expires_at=_parse_datetime(data.get("graceExpiresAt")),
        )


@dataclass
class ManagedKeyRotateResponse:
    """Response from rotating a managed API key."""

    key: str
    api_key: ManagedApiKey
    grace_expires_at: datetime | None
    message: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManagedKeyRotateResponse":
        """Create from API response dictionary."""
        return cls(
            key=data.get("key", ""),
            api_key=ManagedApiKey.from_dict(data.get("apiKey", {})),
            grace_expires_at=_parse_datetime(data.get("graceExpiresAt")),
            message=data.get("message"),
        )
