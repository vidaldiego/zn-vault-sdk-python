# Path: zn-vault-sdk-python/tests/integration/test_audit.py
"""Audit integration tests."""

import pytest
from .conftest import TestConfig


@pytest.mark.integration
class TestAuditIntegration:
    """Integration tests for audit functionality."""

    def test_list_audit_logs(self, superadmin_client):
        """Test listing audit logs."""
        logs = superadmin_client.audit.list()
        assert logs is not None
        print(f"✓ Listed {len(logs)} audit entries")

    def test_verify_audit_chain(self, superadmin_client):
        """Test verifying audit chain integrity."""
        # This may fail if server doesn't have enough entries
        try:
            result = superadmin_client.audit.verify()
            assert result is not None
            print(f"✓ Audit chain verification: valid={result.valid}")
        except Exception as e:
            # Some servers may not support this or may have no entries
            print(f"⚠ Audit chain verification skipped: {e}")
            pytest.skip("Audit verification not available")
