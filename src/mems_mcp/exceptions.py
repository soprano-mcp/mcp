"""Custom exceptions for the mems-mcp server."""

from __future__ import annotations


class MemsMcpError(Exception):
    """Base class for all mems-mcp errors."""


class ConnectionConfigError(MemsMcpError):
    """Raised when required X-Soprano-* connection headers are missing or invalid."""


class ServerConfigError(MemsMcpError):
    """Raised at server startup when environment-based server configuration
    (as opposed to per-request Soprano connection info) is missing or invalid -
    e.g. `MCP_CLIENT_AUTH_MODE=oauth2.1` without the required MCP_OAUTH_* env vars.
    """


class SopranoAuthError(MemsMcpError):
    """Raised when authenticating with the Soprano Connect API fails."""


class SopranoAPIError(MemsMcpError):
    """Raised when the Soprano Connect API returns an error response.

    Mirrors the Connect API's error body (see "Response format" in the Connect
    API guide): statusCode, errorCode, errorType, errorDescription.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        error_code: int | None = None,
        error_type: str | None = None,
        error_description: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.error_type = error_type
        self.error_description = error_description
