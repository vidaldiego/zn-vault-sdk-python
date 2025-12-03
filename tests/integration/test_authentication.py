# Path: zn-vault-sdk-python/tests/integration/test_authentication.py
"""Authentication integration tests."""

import pytest
from znvault.exceptions import AuthenticationError
from .conftest import TestConfig


@pytest.mark.integration
class TestAuthenticationIntegration:
    """Integration tests for authentication functionality."""

    def test_login_superadmin(self, unauthenticated_client):
        """Test login with valid superadmin credentials."""
        response = unauthenticated_client.auth.login(
            TestConfig.Users.SUPERADMIN_USERNAME,
            TestConfig.Users.SUPERADMIN_PASSWORD,
        )

        assert response.access_token is not None
        assert response.refresh_token is not None
        assert response.expires_in > 0

        print(f"✓ Logged in as superadmin, token expires in {response.expires_in}s")

    def test_login_regular_user(self, unauthenticated_client):
        """Test login with valid regular user credentials."""
        response = unauthenticated_client.auth.login(
            TestConfig.Users.REGULAR_USER_USERNAME,
            TestConfig.Users.REGULAR_USER_PASSWORD,
        )

        assert response.access_token is not None
        print("✓ Logged in as regular user")

    def test_login_invalid_credentials(self, unauthenticated_client):
        """Test login with invalid credentials fails."""
        with pytest.raises(Exception):  # Could be AuthenticationError or generic
            unauthenticated_client.auth.login("invalid_user", "wrong_password")

        print("✓ Invalid credentials correctly rejected")

    def test_get_current_user(self, superadmin_client):
        """Test getting current user info after login."""
        user = superadmin_client.auth.me()

        assert user.username == TestConfig.Users.SUPERADMIN_USERNAME
        assert user.id is not None

        print(f"✓ Current user: {user.username} ({user.role})")

    def test_refresh_token(self, unauthenticated_client):
        """Test refreshing access token."""
        # Login to get tokens
        login_response = unauthenticated_client.auth.login(
            TestConfig.Users.SUPERADMIN_USERNAME,
            TestConfig.Users.SUPERADMIN_PASSWORD,
        )

        # Refresh the token
        refresh_response = unauthenticated_client.auth.refresh(login_response.refresh_token)

        assert refresh_response.access_token is not None
        print("✓ Token refreshed successfully")
