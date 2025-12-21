# Path: zn-vault-sdk-python/tests/integration/conftest.py
"""Pytest configuration for integration tests."""

import os
import uuid
import pytest
from znvault.client import ZnVaultClient


class TestConfig:
    """Test configuration for integration tests."""

    # Test server - can be overridden with ZNVAULT_BASE_URL env var
    BASE_URL = os.environ.get("ZNVAULT_BASE_URL", "https://localhost:8443")

    # Test users - can be overridden with ZNVAULT_USERNAME and ZNVAULT_PASSWORD env vars
    # Note: Username must be in format "tenant/username" for non-superadmin users.
    # Superadmin can omit tenant prefix. Email can also be used as username.
    class Users:
        # Superadmin - full access (no tenant prefix required)
        SUPERADMIN_USERNAME = os.environ.get("ZNVAULT_USERNAME", "admin")
        SUPERADMIN_PASSWORD = os.environ.get("ZNVAULT_PASSWORD", "Admin123456#")

        # Tenant admin - manages tenant resources (requires tenant/username format)
        TENANT_ADMIN_USERNAME = os.environ.get("ZNVAULT_TENANT_ADMIN_USERNAME", "zincapp/zincadmin")
        TENANT_ADMIN_PASSWORD = os.environ.get("ZNVAULT_TENANT_ADMIN_PASSWORD", "Admin123456#")

        # Regular user - limited access (requires tenant/username format)
        REGULAR_USER_USERNAME = os.environ.get("ZNVAULT_REGULAR_USER_USERNAME", "zincapp/zincuser")
        REGULAR_USER_PASSWORD = os.environ.get("ZNVAULT_REGULAR_USER_PASSWORD", "Admin123456#")

    # Default tenant for tests
    DEFAULT_TENANT = os.environ.get("ZNVAULT_DEFAULT_TENANT", "zincapp")

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
    def create_regular_user_client(cls) -> ZnVaultClient:
        """Create an authenticated client as regular user."""
        client = cls.create_test_client()
        client.auth.login(cls.Users.REGULAR_USER_USERNAME, cls.Users.REGULAR_USER_PASSWORD)
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
def regular_user_client():
    """Create an authenticated regular user client."""
    if not integration_tests_enabled():
        pytest.skip("Integration tests require ZNVAULT_BASE_URL environment variable")
    return TestConfig.create_regular_user_client()
