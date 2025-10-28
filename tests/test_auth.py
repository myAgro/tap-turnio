import base64

import pytest

from tap_turnio.auth import TurnAuthenticator


class _DummyLogger:
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass

    def __init__(self, config=None):
        # Singer SDK objects typically expose .config as a dict-like
        self.config = config or {}

@pytest.fixture
def base_config():
    return {
        "username": "user@example.com",
        "password": "secret",
        "token": "abc123token",
        "base_url": "https://api.turn.io",
    }

# ---------------------------------------------------------------------------
# Basic Auth Tests
# ---------------------------------------------------------------------------
def test_auth_headers_basic(base_config):
    auth = TurnAuthenticator(
        username=base_config["username"],
        password=base_config["password"],
        base_url=base_config["base_url"],
    )
    hdrs = auth.auth_headers
    creds = f"{base_config['username']}:{base_config['password']}".encode()
    expected = "Basic " + base64.b64encode(creds).decode()
    assert hdrs.get("Authorization") == expected

# --------------------------------------------------------------------------
# Bearer Token test
# --------------------------------------------------------------------------
def test_auth_headers_bearer(base_config):
    auth = TurnAuthenticator(
        username=base_config["username"],
        token=base_config["token"],
        base_url=base_config["base_url"],
    )
    hdrs = auth.auth_headers
    expected = f"Bearer {base_config['token']}"
    assert hdrs.get("Authorization") == expected

# --------------------------------------------------------------------------
# Missing Credentials test
# --------------------------------------------------------------------------
def test_auth_headers_missing_credentials(base_config):
    auth = TurnAuthenticator(
        base_url=base_config["base_url"],
    )
    with pytest.raises(ValueError) as excinfo:
        _ = auth.auth_headers
    assert "Either token or username/password must be provided" in str(excinfo.value)