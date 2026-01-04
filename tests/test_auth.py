# Path: zn-vault-sdk-python/tests/test_auth.py
"""Tests for authentication client including API key rotation."""

import os
import time
import pytest
from unittest.mock import Mock, patch

from znvault.auth.client import AuthClient
from znvault.models.auth import ApiKey


class TestAuthClientApiKeys:
    """Test AuthClient API key methods."""

    @pytest.fixture
    def mock_http(self):
        """Create a mock HTTP client."""
        return Mock()

    @pytest.fixture
    def auth_client(self, mock_http):
        """Create an AuthClient with mock HTTP."""
        return AuthClient(mock_http)

    def test_create_api_key(self, auth_client, mock_http):
        """Test creating an API key."""
        mock_http.post.return_value = {
            "id": "key-123",
            "name": "test-key",
            "prefix": "znv_abc",
            "key": "znv_abc123xyz",
            "createdAt": "2024-01-01T00:00:00Z",
            "expiresAt": "2024-04-01T00:00:00Z",
            "permissions": ["secret:read:metadata"],
        }

        result = auth_client.create_api_key(
            "test-key",
            permissions=["secret:read:metadata"],
            expires_in_days=90,
        )

        assert result.id == "key-123"
        assert result.name == "test-key"
        mock_http.post.assert_called_once_with(
            "/auth/api-keys",
            {"name": "test-key", "permissions": ["secret:read:metadata"], "expiresInDays": 90},
        )

    def test_create_api_key_with_tenant(self, auth_client, mock_http):
        """Test creating an API key with tenant ID."""
        mock_http.post.return_value = {
            "id": "key-456",
            "name": "tenant-key",
            "prefix": "znv_xyz",
            "key": "znv_xyz789",
            "tenantId": "acme",
            "permissions": ["secret:read:metadata"],
        }

        result = auth_client.create_api_key(
            "tenant-key",
            permissions=["secret:read:metadata"],
            tenant_id="acme",
        )

        assert result.id == "key-456"
        assert result.tenant_id == "acme"
        mock_http.post.assert_called_once_with(
            "/auth/api-keys?tenantId=acme",
            {"name": "tenant-key", "permissions": ["secret:read:metadata"]},
        )

    def test_create_api_key_with_conditions(self, auth_client, mock_http):
        """Test creating an API key with inline conditions."""
        mock_http.post.return_value = {
            "id": "key-789",
            "name": "restricted-key",
            "prefix": "znv_cond",
            "key": "znv_cond123",
            "permissions": ["secret:read:metadata"],
            "conditions": {"ip": ["10.0.0.0/8"]},
        }

        result = auth_client.create_api_key(
            "restricted-key",
            permissions=["secret:read:metadata"],
            conditions={"ip": ["10.0.0.0/8"]},
        )

        assert result.id == "key-789"
        assert result.conditions is not None
        mock_http.post.assert_called_once_with(
            "/auth/api-keys",
            {
                "name": "restricted-key",
                "permissions": ["secret:read:metadata"],
                "conditions": {"ip": ["10.0.0.0/8"]},
            },
        )

    def test_list_api_keys(self, auth_client, mock_http):
        """Test listing API keys."""
        mock_http.get.return_value = {
            "keys": [
                {"id": "key-1", "name": "key1", "prefix": "znv_a"},
                {"id": "key-2", "name": "key2", "prefix": "znv_b"},
            ]
        }

        result = auth_client.list_api_keys()

        assert len(result) == 2
        assert result[0].name == "key1"
        assert result[1].name == "key2"
        mock_http.get.assert_called_once_with("/auth/api-keys")

    def test_revoke_api_key(self, auth_client, mock_http):
        """Test revoking an API key."""
        mock_http.delete.return_value = {}

        auth_client.revoke_api_key("key-123")

        mock_http.delete.assert_called_once_with("/auth/api-keys/key-123")

    def test_rotate_api_key(self, auth_client, mock_http):
        """Test rotating an API key by ID."""
        mock_http.post.return_value = {
            "id": "key-456",
            "name": "test-key",
            "prefix": "znv_xyz",
            "key": "znv_xyz789abc",
            "createdAt": "2024-01-01T00:00:00Z",
            "expiresAt": "2024-04-01T00:00:00Z",
        }

        result = auth_client.rotate_api_key("key-123")

        assert result.id == "key-456"
        assert result.key_prefix == "znv_xyz"
        mock_http.post.assert_called_once_with("/auth/api-keys/key-123/rotate", {})

    def test_get_current_api_key(self, auth_client, mock_http):
        """Test getting current API key info."""
        mock_http.get.return_value = {
            "id": "key-123",
            "name": "my-service-key",
            "prefix": "znv_abc",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastUsed": "2024-01-15T00:00:00Z",
        }

        result = auth_client.get_current_api_key()

        assert result.id == "key-123"
        assert result.name == "my-service-key"
        mock_http.get.assert_called_once_with("/auth/api-keys/self")

    def test_rotate_current_api_key(self, auth_client, mock_http):
        """Test self-rotating the current API key."""
        mock_http.post.return_value = {
            "id": "key-789",
            "name": "my-service-key",
            "prefix": "znv_new",
            "key": "znv_new123abc",
            "createdAt": "2024-01-15T00:00:00Z",
            "expiresAt": "2024-04-15T00:00:00Z",
        }

        result = auth_client.rotate_current_api_key()

        assert result.id == "key-789"
        assert result.key_prefix == "znv_new"
        assert result.key == "znv_new123abc"
        mock_http.post.assert_called_once_with("/auth/api-keys/self/rotate", {})
