# Path: zn-vault-sdk-python/src/znvault/secrets/client.py
"""Secrets client for ZN-Vault."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from znvault.models.secrets import (
    Secret,
    SecretData,
    SecretType,
    SecretVersion,
    CreateSecretRequest,
    UpdateSecretRequest,
    SecretFilter,
)

if TYPE_CHECKING:
    from znvault.http.client import HttpClient


class SecretsClient:
    """Client for secret management operations."""

    def __init__(self, http: "HttpClient") -> None:
        """Initialize the secrets client."""
        self._http = http

    def create(self, request: CreateSecretRequest) -> Secret:
        """
        Create a new secret.

        Args:
            request: The secret creation request.

        Returns:
            The created secret metadata.
        """
        response = self._http.post("/v1/secrets", request.to_dict())
        return Secret.from_dict(response)

    def get(self, secret_id: str) -> Secret:
        """
        Get secret metadata by ID.

        Args:
            secret_id: The secret ID.

        Returns:
            The secret metadata.
        """
        response = self._http.get(f"/v1/secrets/{secret_id}/meta")
        return Secret.from_dict(response)

    def get_by_alias(self, alias: str) -> Secret:
        """
        Get secret metadata by alias.

        Args:
            alias: The secret alias.

        Returns:
            The secret metadata.
        """
        encoded_alias = quote(alias, safe="")
        response = self._http.get(f"/v1/secrets/alias/{encoded_alias}")
        return Secret.from_dict(response)

    def decrypt(self, secret_id: str, version: int | None = None) -> SecretData:
        """
        Decrypt and retrieve secret data.

        Args:
            secret_id: The secret ID.
            version: Optional specific version to decrypt.

        Returns:
            The decrypted secret data.
        """
        path = f"/v1/secrets/{secret_id}/decrypt"
        body = {"version": version} if version else {}
        response = self._http.post(path, body)
        return SecretData.from_dict(response)

    def update(self, secret_id: str, request: UpdateSecretRequest) -> Secret:
        """
        Update a secret (creates new version).

        Args:
            secret_id: The secret ID.
            request: The update request.

        Returns:
            The updated secret metadata.
        """
        response = self._http.put(f"/v1/secrets/{secret_id}", request.to_dict())
        return Secret.from_dict(response)

    def delete(self, secret_id: str) -> None:
        """
        Delete a secret.

        Args:
            secret_id: The secret ID to delete.
        """
        self._http.delete(f"/v1/secrets/{secret_id}")

    def list(self, filter: SecretFilter | None = None) -> list[Secret]:
        """
        List secrets matching the filter.

        Args:
            filter: Optional filter parameters.

        Returns:
            List of secrets.
        """
        params = filter.to_params() if filter else {}
        response = self._http.get("/v1/secrets", params)

        # API returns array directly
        if isinstance(response, list):
            return [Secret.from_dict(s) for s in response]
        # Or wrapped in data/secrets key
        items = response.get("data", response.get("secrets", []))
        return [Secret.from_dict(s) for s in items]

    def get_history(self, secret_id: str) -> list[SecretVersion]:
        """
        Get version history of a secret.

        Args:
            secret_id: The secret ID.

        Returns:
            List of secret versions.
        """
        response = self._http.get(f"/v1/secrets/{secret_id}/history")
        versions = response if isinstance(response, list) else response.get("history", [])
        return [SecretVersion.from_dict(v) for v in versions]

    def rotate(self, secret_id: str, new_data: dict[str, Any]) -> Secret:
        """
        Rotate a secret with new data.

        Args:
            secret_id: The secret ID.
            new_data: The new secret data.

        Returns:
            The rotated secret metadata.
        """
        response = self._http.post(f"/v1/secrets/{secret_id}/rotate", {"data": new_data})
        return Secret.from_dict(response)

    def upload_file(
        self,
        alias: str,
        file_path: str | Path,
        tags: list[str] | None = None,
    ) -> Secret:
        """
        Upload a file as a secret.

        Args:
            alias: The secret alias.
            file_path: Path to the file to upload.
            tags: Optional tags for the secret.

        Returns:
            The created secret metadata.
        """
        path = Path(file_path)
        content = path.read_bytes()
        encoded = base64.b64encode(content).decode("utf-8")

        # Detect content type
        suffix = path.suffix.lower()
        content_types = {
            ".pem": "application/x-pem-file",
            ".crt": "application/x-x509-ca-cert",
            ".key": "application/x-pem-file",
            ".json": "application/json",
            ".txt": "text/plain",
            ".pdf": "application/pdf",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
        }
        content_type = content_types.get(suffix, "application/octet-stream")

        request = CreateSecretRequest(
            alias=alias,
            type=SecretType.OPAQUE,
            data={
                "filename": path.name,
                "content": encoded,
                "contentType": content_type,
            },
            tags=tags or [],
        )

        return self.create(request)

    def download_file(self, secret_id: str, output_path: str | Path) -> Path:
        """
        Download a file secret to disk.

        Args:
            secret_id: The secret ID.
            output_path: Path to save the file.

        Returns:
            Path to the downloaded file.
        """
        data = self.decrypt(secret_id)
        content = data.data.get("content", "")
        decoded = base64.b64decode(content)

        path = Path(output_path)
        path.write_bytes(decoded)
        return path
