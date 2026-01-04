# Path: zn-vault-sdk-python/tests/integration/test_secrets.py
"""Secrets integration tests."""

import pytest
from znvault.models.secrets import CreateSecretRequest, UpdateSecretRequest, SecretType, SecretFilter
from .conftest import TestConfig


@pytest.mark.integration
class TestSecretsIntegration:
    """Integration tests for secrets management functionality.

    Uses tenant_admin_client which has full permissions including secret:read:value
    and admin-crypto, allowing both creation and decryption of secrets.
    Tenant must have allow_admin_secret_access=true (configured by sdk-test-init.js).
    """

    @pytest.fixture(autouse=True)
    def setup_cleanup(self, tenant_admin_client):
        """Setup and cleanup for each test."""
        self.created_secret_ids = []
        self.client = tenant_admin_client
        yield
        # Cleanup created secrets
        for secret_id in self.created_secret_ids:
            try:
                self.client.secrets.delete(secret_id)
                print(f"  Cleaned up secret: {secret_id}")
            except Exception:
                pass

    def test_create_credential_secret(self):
        """Test creating a credential secret."""
        alias = TestConfig.unique_alias("creds")

        secret = self.client.secrets.create(
            CreateSecretRequest(
                alias=alias,
                tenant=TestConfig.DEFAULT_TENANT,
                type=SecretType.CREDENTIAL,
                data={"username": "testuser", "password": "testpass123"},
                tags=["test", "credential"],
            )
        )

        self.created_secret_ids.append(secret.id)

        assert secret.id is not None
        assert secret.alias == alias
        assert secret.tenant == TestConfig.DEFAULT_TENANT
        assert secret.type == SecretType.CREDENTIAL
        assert secret.version == 1

        print(f"✓ Created credential secret: {secret.id}")
        print(f"  Alias: {secret.alias}")
        print(f"  Version: {secret.version}")

    def test_create_opaque_secret(self):
        """Test creating an opaque secret."""
        alias = TestConfig.unique_alias("opaque")

        secret = self.client.secrets.create(
            CreateSecretRequest(
                alias=alias,
                tenant=TestConfig.DEFAULT_TENANT,
                type=SecretType.OPAQUE,
                data={"api_key": "sk_live_abc123", "api_secret": "secret_xyz789"},
            )
        )

        self.created_secret_ids.append(secret.id)

        assert secret.id is not None
        assert secret.type == SecretType.OPAQUE

        print(f"✓ Created opaque secret: {secret.id}")

    def test_decrypt_secret(self):
        """Test decrypting secret value.

        Tenant admin with admin-crypto and allow_admin_secret_access=true can decrypt.
        """
        alias = TestConfig.unique_alias("decrypt")

        created = self.client.secrets.create(
            CreateSecretRequest(
                alias=alias,
                tenant=TestConfig.DEFAULT_TENANT,
                type=SecretType.CREDENTIAL,
                data={"username": "decryptuser", "password": "decryptpass"},
            )
        )

        self.created_secret_ids.append(created.id)

        # Decrypt it
        data = self.client.secrets.decrypt(created.id)

        assert data.data["username"] == "decryptuser"
        assert data.data["password"] == "decryptpass"

        print("✓ Decrypted secret successfully")
        print(f"  Username: {data.data['username']}")

    def test_update_secret(self):
        """Test updating secret creates new version."""
        alias = TestConfig.unique_alias("update")

        created = self.client.secrets.create(
            CreateSecretRequest(
                alias=alias,
                tenant=TestConfig.DEFAULT_TENANT,
                type=SecretType.OPAQUE,
                data={"key": "original_value"},
            )
        )

        self.created_secret_ids.append(created.id)
        assert created.version == 1

        # Update it
        updated = self.client.secrets.update(
            created.id,
            UpdateSecretRequest(data={"key": "updated_value"}),
        )

        assert updated.version == 2

        print(f"✓ Updated secret, version: {created.version} -> {updated.version}")

    def test_rotate_secret(self):
        """Test rotating secret creates new version."""
        alias = TestConfig.unique_alias("rotate")

        created = self.client.secrets.create(
            CreateSecretRequest(
                alias=alias,
                tenant=TestConfig.DEFAULT_TENANT,
                type=SecretType.CREDENTIAL,
                data={"username": "user", "password": "oldpass"},
            )
        )

        self.created_secret_ids.append(created.id)

        # Rotate it
        rotated = self.client.secrets.rotate(
            created.id,
            new_data={"username": "user", "password": "newpass"},
        )

        assert rotated.version == 2

        print(f"✓ Rotated secret, version: {created.version} -> {rotated.version}")

    def test_list_secrets(self):
        """Test listing secrets with pagination."""
        # Create some secrets
        for i in range(3):
            secret = self.client.secrets.create(
                CreateSecretRequest(
                    alias=TestConfig.unique_alias(f"list-{i}"),
                    tenant=TestConfig.DEFAULT_TENANT,
                    type=SecretType.OPAQUE,
                    data={"index": i},
                )
            )
            self.created_secret_ids.append(secret.id)

        # List secrets
        secrets = self.client.secrets.list(SecretFilter())

        assert len(secrets) >= 3
        print(f"✓ Listed {len(secrets)} secrets")

    def test_delete_secret(self):
        """Test deleting a secret."""
        alias = TestConfig.unique_alias("delete")

        created = self.client.secrets.create(
            CreateSecretRequest(
                alias=alias,
                tenant=TestConfig.DEFAULT_TENANT,
                type=SecretType.OPAQUE,
                data={"key": "value"},
            )
        )

        # Delete it (don't add to cleanup list)
        self.client.secrets.delete(created.id)

        # Verify it's gone
        with pytest.raises(Exception):
            self.client.secrets.get(created.id)

        print(f"✓ Deleted secret: {created.id}")
