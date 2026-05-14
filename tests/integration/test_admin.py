# Path: zn-vault-sdk-python/tests/integration/test_admin.py
"""Admin operations integration tests."""

import pytest
from znvault.models.admin import CreateUserRequest
from .conftest import TestConfig


@pytest.mark.integration
class TestUsersIntegration:
    """Integration tests for user management functionality."""

    @pytest.fixture(autouse=True)
    def setup_cleanup(self, tenant_admin_client):
        """Setup and cleanup for each test.

        /v1/users is tenant-scoped; superadmins are rejected. Use tenant admin.
        """
        self.created_user_ids = []
        self.client = tenant_admin_client
        yield
        # Cleanup created users
        for user_id in self.created_user_ids:
            try:
                self.client.users.delete(user_id)
                print(f"  Cleaned up user: {user_id}")
            except Exception:
                pass

    def test_list_users(self):
        """Test listing users with pagination."""
        users = self.client.users.list()
        assert users is not None
        print(f"✓ Listed {len(users)} users")

    def test_create_user(self):
        """Test creating a new user."""
        username = TestConfig.unique_id("testuser")

        user = self.client.users.create(
            CreateUserRequest(
                username=username,
                password="TestPassword123#",
                email=f"{username}@example.com",
                role="user",
            )
        )

        self.created_user_ids.append(user.id)

        assert user.id is not None
        # Server returns username with tenant prefix for tenant users
        assert user.username == f"{TestConfig.DEFAULT_TENANT}/{username}"

        print(f"✓ Created user: {user.username}")
        print(f"  ID: {user.id}")

    def test_get_user(self):
        """Test getting user by ID."""
        username = TestConfig.unique_id("getuser")

        created = self.client.users.create(
            CreateUserRequest(
                username=username,
                password="TestPassword123#",
            )
        )

        self.created_user_ids.append(created.id)

        # Get it
        user = self.client.users.get(created.id)

        assert user.id == created.id
        # Server returns username with tenant prefix for tenant users
        assert user.username == f"{TestConfig.DEFAULT_TENANT}/{username}"

        print(f"✓ Retrieved user: {user.username}")

    def test_delete_user(self):
        """Test deleting a user."""
        username = TestConfig.unique_id("deleteuser")

        user = self.client.users.create(
            CreateUserRequest(
                username=username,
                password="TestPassword123#",
            )
        )

        # Delete it (don't add to cleanup list)
        self.client.users.delete(user.id)

        print(f"✓ Deleted user: {user.username}")


@pytest.mark.integration
class TestTenantsIntegration:
    """Integration tests for tenant management functionality.

    Tenant CRUD is superadmin-only and lives on ZnVaultSuperadminClient.
    """

    def test_list_tenants(self, superadmin_admin_client):
        """Test listing tenants."""
        tenants = superadmin_admin_client.tenants.list()
        assert tenants is not None
        print(f"✓ Listed {len(tenants)} tenants")

    def test_get_tenant(self, superadmin_admin_client):
        """Test getting tenant by ID."""
        tenant = superadmin_admin_client.tenants.get(TestConfig.DEFAULT_TENANT)
        assert tenant.id == TestConfig.DEFAULT_TENANT
        print(f"✓ Retrieved tenant: {tenant.id}")


@pytest.mark.integration
class TestRolesIntegration:
    """Integration tests for role management functionality.

    /v1/roles is tenant-scoped; use tenant admin.
    """

    def test_list_roles(self, tenant_admin_client):
        """Test listing roles."""
        roles = tenant_admin_client.roles.list()
        assert roles is not None
        print(f"✓ Listed {len(roles)} roles")


@pytest.mark.integration
class TestPoliciesIntegration:
    """Integration tests for policy management functionality.

    /v1/policies is tenant-scoped; use tenant admin.
    """

    def test_list_policies(self, tenant_admin_client):
        """Test listing policies."""
        policies = tenant_admin_client.policies.list()
        assert policies is not None
        print(f"✓ Listed {len(policies)} policies")
