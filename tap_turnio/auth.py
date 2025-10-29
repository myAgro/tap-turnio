# tap_turnio/auth.py
# -----------------------------------------------------------------------------
# Custom authenticator for Turn.io API using HTTP Basic Auth.
#
# Responsibilities:
#   - Hold username/password/base_url for this tap
#   - Expose an `auth_headers` property so that the Singer SDK + requests.Session
#     can automatically apply the correct Authorization header.
#   - Compatible with the Singer SDK's `APIAuthenticatorBase`.
#
# Notes:
#   - Use simple HTTP Basic Auth (`Authorization: Basic <base64>`)
#   - No token refresh flow required, since credentials are static
#   - A setter is included to satisfy the SDK contract, but is effectively a no-op
# -----------------------------------------------------------------------------

import base64

from singer_sdk.authenticators import APIAuthenticatorBase

############################################################
# TurnAuthenticator
############################################################

# =============================================================================
# Base Class: APIAuthenticatorBase
# Centralizes:
#  - auth_headers property (getter/setter)
#  - integration with requests.Session
# =============================================================================
class TurnAuthenticator(APIAuthenticatorBase):
    """Authenticator for Turn.io supporting Basic or Bearer authentication.

    Args:
        stream: The parent stream object (required by Singer SDK).
        username: The Turn.io account username (optional if using token).
        password: The Turn.io account password (optional if using token).
        token: The Turn.io API token (optional if using username/password).
        base_url: The base URL of the Turn.io API.

    Behavior:
        - If token is provided, uses Bearer authentication.
        - Else, falls back to Basic Auth with username:password.
        - No refresh / token exchange is needed.
    """

    def __init__(self, username: str = None, password: str = None, token: str = None, base_url: str = None) -> None:
        """Initialize authenticator with static credentials."""
        super().__init__()
        self._username = username
        self._password = password
        self._token = token
        self._base_url = base_url

        # Internal placeholder to satisfy the Singer SDK's expected property.
        # Not actually used in this implementation.
        self._auth_headers_cache: dict = {}

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------
    @property
    def auth_headers(self) -> dict:
        """Return dictionary of authentication headers for HTTP Basic Auth."""

        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        elif self._username and self._password:
            credentials = f"{self._username}:{self._password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        else:
            raise ValueError("Either token or username/password must be provided for authentication.")

    @auth_headers.setter
    def auth_headers(self, value: dict) -> None:
        """Setter required by base class; ignored in this implementation."""
        self._auth_headers_cache = value or {}
