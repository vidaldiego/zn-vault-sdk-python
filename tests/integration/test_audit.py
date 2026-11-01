# Path: zn-vault-sdk-python/tests/integration/test_audit.py
"""Audit integration tests."""

import pytest
from znvault.exceptions import AuthorizationError


@pytest.mark.integration
class TestAuditIntegration:
    """Listing is tenant-scoped; global verification requires superadmin."""

    def test_list_audit_logs(self, tenant_admin_client):
        """Test listing audit logs."""
        logs = tenant_admin_client.audit.list()
        assert logs is not None
        print(f"✓ Listed {len(logs)} audit entries")

    def test_verify_audit_chain(self, superadmin_client):
        """Global evidence requires a superadmin and must not skip errors."""
        result = superadmin_client.audit.verify()
        assert result.status == "verified"
        assert result.valid is True
        assert result.evidence["scope"] == "retained"
        assert result.evidence["historicalCompleteness"] == "not_proven"
        assert result.entries_verified == result.evidence["readEntries"]

    def test_tenant_cannot_verify_global_chain(self, tenant_admin_client):
        with pytest.raises(AuthorizationError) as error:
            tenant_admin_client.audit.verify()
        assert error.value.status_code == 403
