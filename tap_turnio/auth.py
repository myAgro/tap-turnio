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
    """Authenticator for Turn.io using HTTP Basic Auth.

    Args:
        stream: The parent stream object (required by Singer SDK).
        username: The Turn.io account username.
        password: The Turn.io account password.
        base_url: The base URL of the Turn.io API.

    Behavior:
        - Returns an Authorization header with `Basic <base64(username:password)>`.
        - No refresh / token exchange is needed.
    """

    def __init__(self, username: str, password: str, base_url: str) -> None:
        """Initialize authenticator with static credentials."""
        super().__init__()
        self._username = username
        self._password = password
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
        credentials = f"{self._username}:{self._password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    @auth_headers.setter
    def auth_headers(self, value: dict) -> None:
        """Setter required by base class; ignored in this implementation."""
        self._auth_headers_cache = value or {}
