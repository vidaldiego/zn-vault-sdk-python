# Path: zn-vault-sdk-python/src/znvault/superadmin/client.py
"""Superadmin-scoped client for cross-tenant administrative operations."""

from znvault.config import ZnVaultConfig
from znvault.http.client import HttpClient
from znvault.admin.tenants import TenantsClient
from znvault.audit.client import AuditClient
from znvault.health.client import HealthClient
from znvault.superadmin.auth import SuperadminAuthClient
from znvault.exceptions import ConfigurationError


class ZnVaultSuperadminClient:
    """Superadmin-scoped client.

    Use this only with a superadmin principal. For tenant operations, use
    :class:`znvault.ZnVaultClient`.

    The split is intentional: a service that holds a tenant-scoped API key
    cannot import or instantiate cross-tenant operations.

    **Note:** the cross-tenant API key surface on ``auth`` targets routes
    under ``/v1/superadmin/api-keys/`` which are not yet implemented on the
    vault server (as of 1.38.8). Those calls will 404 until shipped.

    Example:
        >>> admin = ZnVaultSuperadminClient.builder() \\
        ...     .base_url("https://vault.example.com:8443") \\
        ...     .api_key("znv_superadmin_xxx") \\
        ...     .build()
        >>> tenant = admin.tenants.create(name="acme", description="Acme")
    """

    def __init__(self, config: ZnVaultConfig) -> None:
        self._config = config
        self._http = HttpClient(config)

        self._tenants = TenantsClient(self._http)
        self._auth = SuperadminAuthClient(self._http)
        self._audit = AuditClient(self._http)
        self._health = HealthClient(self._http)

    @classmethod
    def builder(cls) -> "ZnVaultSuperadminClientBuilder":
        return ZnVaultSuperadminClientBuilder()

    @property
    def tenants(self) -> TenantsClient:
        """Tenant CRUD (superadmin only)."""
        return self._tenants

    @property
    def auth(self) -> SuperadminAuthClient:
        """Cross-tenant API key / managed-key / registration-token management.

        Targets ``/v1/superadmin/api-keys/`` routes — will 404 until the
        server ships them.
        """
        return self._auth

    @property
    def audit(self) -> AuditClient:
        """Audit log across all tenants."""
        return self._audit

    @property
    def health(self) -> HealthClient:
        """Health check operations."""
        return self._health

    @property
    def config(self) -> ZnVaultConfig:
        return self._config


class ZnVaultSuperadminClientBuilder:
    """Builder for ZnVaultSuperadminClient."""

    def __init__(self) -> None:
        self._base_url: str | None = None
        self._api_key: str | None = None
        self._timeout: int = 30
        self._verify_ssl: bool = True
        self._trust_self_signed: bool = False
        self._retry_attempts: int = 3
        self._retry_delay: float = 0.5
        self._headers: dict[str, str] = {}

    def base_url(self, url: str) -> "ZnVaultSuperadminClientBuilder":
        self._base_url = url
        return self

    def api_key(self, key: str) -> "ZnVaultSuperadminClientBuilder":
        self._api_key = key
        return self

    def timeout(self, seconds: int) -> "ZnVaultSuperadminClientBuilder":
        self._timeout = seconds
        return self

    def verify_ssl(self, verify: bool) -> "ZnVaultSuperadminClientBuilder":
        self._verify_ssl = verify
        return self

    def trust_self_signed(self, trust: bool) -> "ZnVaultSuperadminClientBuilder":
        self._trust_self_signed = trust
        return self

    def retry_attempts(self, attempts: int) -> "ZnVaultSuperadminClientBuilder":
        self._retry_attempts = attempts
        return self

    def retry_delay(self, delay: float) -> "ZnVaultSuperadminClientBuilder":
        self._retry_delay = delay
        return self

    def header(self, name: str, value: str) -> "ZnVaultSuperadminClientBuilder":
        self._headers[name] = value
        return self

    def build(self) -> ZnVaultSuperadminClient:
        if not self._base_url:
            raise ConfigurationError("Base URL is required")
        config = ZnVaultConfig(
            base_url=self._base_url,
            api_key=self._api_key,
            timeout=self._timeout,
            verify_ssl=self._verify_ssl,
            trust_self_signed=self._trust_self_signed,
            retry_attempts=self._retry_attempts,
            retry_delay=self._retry_delay,
            headers=self._headers,
        )
        return ZnVaultSuperadminClient(config)
