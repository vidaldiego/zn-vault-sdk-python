# Path: zn-vault-sdk-python/src/znvault/models/secrets.py
"""Secret management models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SecretType(str, Enum):
    """Secret type enumeration."""

    OPAQUE = "opaque"
    CREDENTIAL = "credential"
    SETTING = "setting"


@dataclass
class Secret:
    """Secret metadata (not decrypted value)."""

    id: str
    alias: str
    tenant: str
    type: SecretType
    version: int
    tags: list[str] = field(default_factory=list)
    env: str | None = None
    service: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    expires_at: datetime | None = None
    created_by: str | None = None
    checksum: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Secret":
        """Create from API response dictionary."""
        secret_type = data.get("type", "opaque")
        if isinstance(secret_type, str):
            try:
                secret_type = SecretType(secret_type.lower())
            except ValueError:
                secret_type = SecretType.OPAQUE

        return cls(
            id=data.get("id", ""),
            alias=data.get("alias", ""),
            tenant=data.get("tenant", ""),
            type=secret_type,
            version=data.get("version", 1),
            tags=data.get("tags", []),
            env=data.get("env"),
            service=data.get("service"),
            created_at=_parse_datetime(data.get("createdAt")),
            updated_at=_parse_datetime(data.get("updatedAt")),
            expires_at=_parse_datetime(data.get("expiresAt")),
            created_by=data.get("createdBy"),
            checksum=data.get("checksum"),
        )


@dataclass
class SecretData:
    """Decrypted secret data."""

    data: dict[str, Any]
    version: int
    decrypted_at: datetime | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretData":
        """Create from API response dictionary."""
        return cls(
            data=data.get("data", {}),
            version=data.get("version", 1),
            decrypted_at=_parse_datetime(data.get("decryptedAt")) or datetime.now(),
        )


@dataclass
class SecretVersion:
    """Secret version history entry."""

    version: int
    created_at: datetime | None
    created_by: str | None = None
    checksum: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretVersion":
        """Create from API response dictionary."""
        return cls(
            version=data.get("version", 1),
            created_at=_parse_datetime(data.get("createdAt")),
            created_by=data.get("createdBy"),
            checksum=data.get("checksum"),
        )


@dataclass
class CreateSecretRequest:
    """Request to create a secret."""

    alias: str
    tenant: str
    type: SecretType
    data: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    env: str | None = None
    service: str | None = None
    ttl_until: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to API request dictionary."""
        result: dict[str, Any] = {
            "alias": self.alias,
            "tenant": self.tenant,
            "type": self.type.value,
            "data": self.data,
        }
        if self.tags:
            result["tags"] = self.tags
        if self.env:
            result["env"] = self.env
        if self.service:
            result["service"] = self.service
        if self.ttl_until:
            result["ttlUntil"] = self.ttl_until.isoformat()
        return result


@dataclass
class UpdateSecretRequest:
    """Request to update a secret."""

    data: dict[str, Any]
    tags: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to API request dictionary."""
        result: dict[str, Any] = {"data": self.data}
        if self.tags is not None:
            result["tags"] = self.tags
        return result


@dataclass
class SecretFilter:
    """Filter options for listing secrets."""

    tenant: str | None = None
    env: str | None = None
    service: str | None = None
    type: SecretType | None = None
    tags: list[str] | None = None
    limit: int = 100
    offset: int = 0
    marker: str | None = None

    def to_params(self) -> dict[str, Any]:
        """Convert to query parameters."""
        params: dict[str, Any] = {
            "limit": self.limit,
            "offset": self.offset,
        }
        if self.tenant:
            params["tenant"] = self.tenant
        if self.env:
            params["env"] = self.env
        if self.service:
            params["service"] = self.service
        if self.type:
            params["type"] = self.type.value
        if self.tags:
            params["tags"] = ",".join(self.tags)
        if self.marker:
            params["marker"] = self.marker
        return params


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse ISO datetime string."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
