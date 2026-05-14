# Path: zn-vault-sdk-python/src/znvault/certificates/client.py
"""Certificates client for ZnVault.

Tenant is always derived from the authenticated principal by the server;
there are no client-supplied tenant parameters. For cross-tenant certificate
operations, use ZnVaultSuperadminClient.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING
from urllib.parse import quote

from znvault.models.certificates import (
    Certificate,
    DecryptedCertificate,
    StoreCertificateRequest,
    UpdateCertificateRequest,
    RotateCertificateRequest,
    CertificateFilter,
    CertificateStats,
    CertificateAccessLogEntry,
    CertificateListResponse,
    CertificateType,
    CertificatePurpose,
)

if TYPE_CHECKING:
    from znvault.http.client import HttpClient


class CertificatesClient:
    """Client for certificate lifecycle management operations."""

    def __init__(self, http: "HttpClient") -> None:
        self._http = http

    def store(self, request: StoreCertificateRequest) -> Certificate:
        """Store a new certificate for custody."""
        response = self._http.post("/v1/certificates", request.to_dict())
        return Certificate.from_dict(response)

    def get(self, certificate_id: str) -> Certificate:
        """Get certificate metadata by ID."""
        response = self._http.get(f"/v1/certificates/{certificate_id}")
        return Certificate.from_dict(response)

    def get_by_identity(self, client_id: str, kind: str, alias: str) -> Certificate:
        """Get certificate by business identity (clientId/kind/alias)."""
        encoded_client_id = quote(client_id, safe="")
        encoded_kind = quote(kind, safe="")
        encoded_alias = quote(alias, safe="")
        response = self._http.get(
            f"/v1/certificates/by-identity/{encoded_client_id}/{encoded_kind}/{encoded_alias}"
        )
        return Certificate.from_dict(response)

    def list(self, filter: CertificateFilter | None = None) -> CertificateListResponse:
        """List certificates with optional filtering."""
        params = filter.to_params() if filter else {}
        response = self._http.get("/v1/certificates", params=params)
        return CertificateListResponse.from_dict(response)

    def get_stats(self) -> CertificateStats:
        """Get certificate statistics."""
        response = self._http.get("/v1/certificates/stats")
        return CertificateStats.from_dict(response)

    def list_expiring(self, days: int = 30) -> list[Certificate]:
        """List certificates expiring within a specified number of days."""
        response = self._http.get("/v1/certificates/expiring", params={"days": str(days)})
        return [Certificate.from_dict(c) for c in response]

    def update(
        self,
        certificate_id: str,
        request: UpdateCertificateRequest,
    ) -> Certificate:
        """Update certificate metadata."""
        response = self._http.patch(f"/v1/certificates/{certificate_id}", request.to_dict())
        return Certificate.from_dict(response)

    def decrypt(self, certificate_id: str, purpose: str) -> DecryptedCertificate:
        """Decrypt certificate (retrieve the actual certificate data).

        Requires business justification — the purpose is logged for audit.
        """
        response = self._http.post(
            f"/v1/certificates/{certificate_id}/decrypt",
            {"purpose": purpose},
        )
        return DecryptedCertificate.from_dict(response)

    def rotate(
        self,
        certificate_id: str,
        request: RotateCertificateRequest,
    ) -> Certificate:
        """Rotate certificate (replace with a new certificate)."""
        response = self._http.post(
            f"/v1/certificates/{certificate_id}/rotate",
            request.to_dict(),
        )
        return Certificate.from_dict(response)

    def delete(self, certificate_id: str) -> None:
        """Delete a certificate. Underlying secret data preserved for audit."""
        self._http.delete(f"/v1/certificates/{certificate_id}")

    def get_access_log(
        self, certificate_id: str, limit: int = 100
    ) -> list[CertificateAccessLogEntry]:
        """Get certificate access log."""
        response = self._http.get(
            f"/v1/certificates/{certificate_id}/access-log",
            params={"limit": str(limit)},
        )
        entries = response.get("entries", [])
        return [CertificateAccessLogEntry.from_dict(e) for e in entries]

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def store_p12(
        self,
        client_id: str,
        kind: str,
        alias: str,
        p12_data: bytes | str,
        passphrase: str,
        purpose: CertificatePurpose,
        *,
        client_name: str | None = None,
        organization_id: str | None = None,
        contact_email: str | None = None,
        tags: list[str] | None = None,
        metadata: dict | None = None,
    ) -> Certificate:
        """Store a P12 certificate with simplified parameters."""
        if isinstance(p12_data, bytes):
            certificate_data = base64.b64encode(p12_data).decode("utf-8")
        else:
            certificate_data = p12_data

        request = StoreCertificateRequest(
            client_id=client_id,
            kind=kind,
            alias=alias,
            certificate_data=certificate_data,
            certificate_type=CertificateType.P12,
            passphrase=passphrase,
            purpose=purpose,
            client_name=client_name,
            organization_id=organization_id,
            contact_email=contact_email,
            tags=tags or [],
            metadata=metadata or {},
        )
        return self.store(request)

    def store_pem(
        self,
        client_id: str,
        kind: str,
        alias: str,
        pem_data: bytes | str,
        purpose: CertificatePurpose,
        *,
        client_name: str | None = None,
        organization_id: str | None = None,
        contact_email: str | None = None,
        tags: list[str] | None = None,
        metadata: dict | None = None,
    ) -> Certificate:
        """Store a PEM certificate with simplified parameters."""
        if isinstance(pem_data, bytes):
            certificate_data = base64.b64encode(pem_data).decode("utf-8")
        else:
            certificate_data = pem_data

        request = StoreCertificateRequest(
            client_id=client_id,
            kind=kind,
            alias=alias,
            certificate_data=certificate_data,
            certificate_type=CertificateType.PEM,
            purpose=purpose,
            client_name=client_name,
            organization_id=organization_id,
            contact_email=contact_email,
            tags=tags or [],
            metadata=metadata or {},
        )
        return self.store(request)

    def list_by_client(
        self,
        client_id: str,
        *,
        page: int = 1,
        page_size: int = 20,
    ) -> CertificateListResponse:
        """List certificates by client ID."""
        return self.list(CertificateFilter(client_id=client_id, page=page, page_size=page_size))

    def list_by_kind(
        self,
        kind: str,
        *,
        page: int = 1,
        page_size: int = 20,
    ) -> CertificateListResponse:
        """List certificates by kind (AEAT, FNMT, CUSTOM, etc.)."""
        return self.list(CertificateFilter(kind=kind, page=page, page_size=page_size))

    def list_active(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
    ) -> CertificateListResponse:
        """List active certificates only."""
        from znvault.models.certificates import CertificateStatus
        return self.list(CertificateFilter(status=CertificateStatus.ACTIVE, page=page, page_size=page_size))

    def list_expired(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
    ) -> CertificateListResponse:
        """List expired certificates only."""
        from znvault.models.certificates import CertificateStatus
        return self.list(CertificateFilter(status=CertificateStatus.EXPIRED, page=page, page_size=page_size))

    def download(self, certificate_id: str, purpose: str) -> bytes:
        """Download certificate as bytes."""
        decrypted = self.decrypt(certificate_id, purpose)
        return base64.b64decode(decrypted.certificate_data)
