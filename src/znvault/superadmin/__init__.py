# Path: zn-vault-sdk-python/src/znvault/superadmin/__init__.py
"""Superadmin-scoped client for cross-tenant administrative operations."""

from znvault.superadmin.client import ZnVaultSuperadminClient
from znvault.superadmin.auth import SuperadminAuthClient

__all__ = ["ZnVaultSuperadminClient", "SuperadminAuthClient"]
