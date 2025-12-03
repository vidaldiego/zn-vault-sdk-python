# Path: zn-vault-sdk-python/tests/integration/test_health.py
"""Health check integration tests."""

import pytest
from .conftest import TestConfig


@pytest.mark.integration
class TestHealthIntegration:
    """Integration tests for health check functionality."""

    def test_health_check(self, unauthenticated_client):
        """Test basic health check."""
        health = unauthenticated_client.health.check()
        assert health.status == "ok"
        print(f"✓ Health status: {health.status}")

    def test_is_healthy(self, unauthenticated_client):
        """Test is_healthy returns true."""
        healthy = unauthenticated_client.health.is_healthy()
        assert healthy is True
        print("✓ Server is healthy")
