import base64
import pytest

@pytest.fixture
def base_config():
    return {
        "username": "alice",
        "password": "secret",
        "base_url": "https://whatsapp.turn.io/",
        "start_date": "2025-01-01T00:00:00Z",
        "page_size": 2,
        "max_pages": 0,
        "lookback_sec": 0,
        "messages_cursor_json": {},
        "statuses_cursor_json": {},
    }

@pytest.fixture
def expected_basic_header(base_config):
    creds = f"{base_config['username']}:{base_config['password']}"
    return "Basic " + base64.b64encode(creds.encode()).decode()

@pytest.fixture
def dummy_context():
    return {}

class DummyResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, text=""):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if 400 <= self.status_code:
            import requests
            raise requests.HTTPError(f"status {self.status_code}")

@pytest.fixture
def dummy_response_cls():
    return DummyResponse
