# Path: zn-vault-sdk-python/tests/integration/conftest.py
"""Pytest configuration for integration tests.

All test users use the standard password: SdkTest123456#

Usage:
    # Start the SDK test environment first (from zn-vault root):
    npm run test:sdk:start

    # Run integration tests:
    pytest tests/integration/

    # Or run against production (not recommended):
    ZNVAULT_BASE_URL=https://vault.example.com pytest tests/integration/
"""

import os
import uuid
import pytest
from znvault.client import ZnVaultClient


# Standard password for all test users (matches sdk-test-init.js)
STANDARD_PASSWORD = "SdkTest123456#"


class TestConfig:
    """Test configuration for integration tests."""

    # Test server - defaults to SDK test environment (port 9443)
    BASE_URL = os.environ.get("ZNVAULT_BASE_URL", "https://localhost:9443")

    # Default tenant
    DEFAULT_TENANT = os.environ.get("ZNVAULT_TENANT", "sdk-test")

    # Secondary tenant for isolation tests
    TENANT_2 = "sdk-test-2"

    # Test users - can be overridden with environment variables
    # Note: Username must be in format "tenant/username" for non-superadmin users.
    # Superadmin can omit tenant prefix. Email can also be used as username.
    class Users:
        # Superadmin - full access (no tenant prefix required)
        SUPERADMIN_USERNAME = os.environ.get("ZNVAULT_USERNAME", "admin")
        SUPERADMIN_PASSWORD = os.environ.get("ZNVAULT_PASSWORD", "Admin123456#")

        # Tenant admin - manages tenant resources with admin-crypto (requires tenant/username format)
        _tenant = os.environ.get("ZNVAULT_TENANT", "sdk-test")
        TENANT_ADMIN_USERNAME = os.environ.get("ZNVAULT_TENANT_ADMIN_USERNAME", f"{_tenant}/sdk-admin")
        TENANT_ADMIN_PASSWORD = os.environ.get("ZNVAULT_TENANT_ADMIN_PASSWORD", STANDARD_PASSWORD)

        # Read-only user - can only read secrets (requires tenant/username format)
        READER_USERNAME = os.environ.get("ZNVAULT_READER_USERNAME", f"{_tenant}/sdk-reader")
        READER_PASSWORD = os.environ.get("ZNVAULT_READER_PASSWORD", STANDARD_PASSWORD)

        # Read-write user - can read and write secrets (requires tenant/username format)
        WRITER_USERNAME = os.environ.get("ZNVAULT_WRITER_USERNAME", f"{_tenant}/sdk-writer")
        WRITER_PASSWORD = os.environ.get("ZNVAULT_WRITER_PASSWORD", STANDARD_PASSWORD)

        # KMS user - can only use KMS operations (requires tenant/username format)
        KMS_USER_USERNAME = os.environ.get("ZNVAULT_KMS_USER_USERNAME", f"{_tenant}/sdk-kms-user")
        KMS_USER_PASSWORD = os.environ.get("ZNVAULT_KMS_USER_PASSWORD", STANDARD_PASSWORD)

        # Certificate user - can manage certificates (requires tenant/username format)
        CERT_USER_USERNAME = os.environ.get("ZNVAULT_CERT_USER_USERNAME", f"{_tenant}/sdk-cert-user")
        CERT_USER_PASSWORD = os.environ.get("ZNVAULT_CERT_USER_PASSWORD", STANDARD_PASSWORD)

        # Second tenant admin (for isolation testing)
        TENANT2_ADMIN_USERNAME = os.environ.get("ZNVAULT_TENANT2_ADMIN_USERNAME", "sdk-test-2/sdk-admin")
        TENANT2_ADMIN_PASSWORD = os.environ.get("ZNVAULT_TENANT2_ADMIN_PASSWORD", STANDARD_PASSWORD)

    # Pre-created API keys (created by sdk-test-init.js)
    class ApiKeys:
        FULL_ACCESS = os.environ.get("ZNVAULT_API_KEY_FULL")
        READ_ONLY = os.environ.get("ZNVAULT_API_KEY_READONLY")
        KMS_ONLY = os.environ.get("ZNVAULT_API_KEY_KMS")
        WITH_IP_RESTRICTION = os.environ.get("ZNVAULT_API_KEY_WITH_IP")
        PROD_ONLY = os.environ.get("ZNVAULT_API_KEY_PROD_ONLY")

    # Test resources
    class Resources:
        TEST_SECRET_ALIAS = os.environ.get("ZNVAULT_TEST_SECRET_ALIAS", "sdk-test/database/credentials")

    @classmethod
    def create_test_client(cls) -> ZnVaultClient:
        """Create a client for testing (insecure TLS for localhost)."""
        base_url = os.environ.get("ZNVAULT_BASE_URL", cls.BASE_URL)
        return (
            ZnVaultClient.builder()
            .base_url(base_url)
            .trust_self_signed(True)
            .verify_ssl(False)
            .build()
        )

    @classmethod
    def create_superadmin_client(cls) -> ZnVaultClient:
        """Create an authenticated client as superadmin."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.SUPERADMIN_USERNAME, cls.Users.SUPERADMIN_PASSWORD)
        return client

    @classmethod
    def create_tenant_admin_client(cls) -> ZnVaultClient:
        """Create an authenticated client as tenant admin."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.TENANT_ADMIN_USERNAME, cls.Users.TENANT_ADMIN_PASSWORD)
        return client

    @classmethod
    def create_reader_client(cls) -> ZnVaultClient:
        """Create an authenticated client as read-only user."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.READER_USERNAME, cls.Users.READER_PASSWORD)
        return client

    @classmethod
    def create_writer_client(cls) -> ZnVaultClient:
        """Create an authenticated client as read-write user."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.WRITER_USERNAME, cls.Users.WRITER_PASSWORD)
        return client

    @classmethod
    def create_kms_user_client(cls) -> ZnVaultClient:
        """Create an authenticated client as KMS user."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.KMS_USER_USERNAME, cls.Users.KMS_USER_PASSWORD)
        return client

    @classmethod
    def create_cert_user_client(cls) -> ZnVaultClient:
        """Create an authenticated client as certificate user."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.CERT_USER_USERNAME, cls.Users.CERT_USER_PASSWORD)
        return client

    @classmethod
    def create_tenant2_admin_client(cls) -> ZnVaultClient:
        """Create an authenticated client as second tenant admin."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.TENANT2_ADMIN_USERNAME, cls.Users.TENANT2_ADMIN_PASSWORD)
        return client

    @staticmethod
    def unique_id(prefix: str = "test") -> str:
        """Generate a unique ID for testing."""
        short_uuid = str(uuid.uuid4())[:8]
        return f"{prefix}-{short_uuid}"

    @staticmethod
    def unique_alias(prefix: str = "test") -> str:
        """Generate a unique alias for testing."""
        short_uuid = str(uuid.uuid4())[:8]
        return f"{prefix}/sdk-test/{short_uuid}"


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (may require running server)",
    )


def integration_tests_enabled() -> bool:
    """Check if integration tests should run."""
    return os.environ.get("ZNVAULT_BASE_URL") is not None


@pytest.fixture
def test_config():
    """Provide test configuration."""
    return TestConfig


@pytest.fixture
def unauthenticated_client():
    """Create an unauthenticated client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_test_client()


@pytest.fixture
def superadmin_client():
    """Create an authenticated superadmin client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_superadmin_client()


@pytest.fixture
def tenant_admin_client():
    """Create an authenticated tenant admin client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_tenant_admin_client()


@pytest.fixture
def reader_client():
    """Create an authenticated read-only user client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_reader_client()


@pytest.fixture
def writer_client():
    """Create an authenticated read-write user client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_writer_client()


@pytest.fixture
def kms_user_client():
    """Create an authenticated KMS user client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_kms_user_client()


@pytest.fixture
def cert_user_client():
    """Create an authenticated certificate user client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_cert_user_client()


@pytest.fixture
def tenant2_admin_client():
    """Create an authenticated second tenant admin client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_tenant2_admin_client()
