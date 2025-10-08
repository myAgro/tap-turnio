import base64

from tap_turnio.auth import TurnAuthenticator


class _DummyLogger:
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass

class _DummyStream:
    # Minimal attributes the SDK may touch
    tap_name = "tap-turnio"
    logger = _DummyLogger()

    def __init__(self, config=None):
        # Singer SDK objects typically expose .config as a dict-like
        self.config = config or {}

def test_auth_headers_basic(base_config):
    auth = TurnAuthenticator(
        _DummyStream(),
        base_config["username"],
        base_config["password"],
        base_config["base_url"],
    )
    hdrs = auth.auth_headers
    creds = f"{base_config['username']}:{base_config['password']}".encode()
    expected = "Basic " + base64.b64encode(creds).decode()
    assert hdrs.get("Authorization") == expected
