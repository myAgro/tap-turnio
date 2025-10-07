from datetime import timedelta
from dateutil.parser import isoparse
from tap_turnio.streams import MessagesStream, StatusesStream
from tap_turnio.tap import TapTurnio


def _tap(base_config):
    # TapTurnio is a Singer SDK Tap; it expects a dict-like config
    return TapTurnio(config=base_config)

def test_turn_stream_url_base_trims_slash(base_config):
    tap = _tap(base_config)
    s = MessagesStream(tap)
    assert s.url_base == "https://whatsapp.turn.io"  # no trailing slash

def test_http_client_has_headers(base_config):
    tap = _tap(base_config)
    s = MessagesStream(tap)
    client = s.http_client
    # Accept header per class attribute
    assert client.headers.get("Accept") == "application/vnd.v1+json"
    # Authorization header comes from authenticator (Basic)
    assert "Authorization" in client.headers

def test_messages_parse_and_post_process(base_config, dummy_context):
    tap = _tap(base_config)
    s = MessagesStream(tap)
    payload = {
        "data": [
            {
                "contacts": [{"wa_id": "250700111222"}],
                "messages": [
                    {
                        "id": "m1",
                        "timestamp": "2025-03-01T12:00:00Z",
                        "_vnd": {
                            "v1": {"direction": "inbound"},
                        },
                        "from": "250700111222",
                    },
                    {
                        "id": "m2",
                        "timestamp": "1740000000",  # epoch string
                    },
                ],
            }
        ]
    }
    items = list(s.parse_response(payload))
    assert len(items) == 2
    out = [s.post_process(i, dummy_context) for i in items]
    assert {o["id"] for o in out if o} == {"m1", "m2"}
    for o in out:
        assert "timestamp" in o
        dt = isoparse(o["timestamp"])
        assert dt.utcoffset() == timedelta(0)
        assert "payload_json" in o


def test_statuses_parse_and_post_process(base_config, dummy_context):
    tap = _tap(base_config)
    s = StatusesStream(tap)
    payload = {
        "data": [
            {
                "statuses": [
                    {
                        "id": "s1",
                        "message_id": "m1",
                        "status": "delivered",
                        "timestamp": "2025-03-01T12:00:00Z",
                        "recipient_id": "250700111222",
                    },
                    {
                        "id": "s2",
                        "message_id": "m2",
                        "status": "read",
                        "timestamp": "1740000000",
                        "recipient_id": "250700111222",
                    },
                ]
            }
        ]
    }
    items = list(s.parse_response(payload))
    assert len(items) == 2
    out = [s.post_process(i, dummy_context) for i in items]
    assert {o["id"] for o in out if o} == {"s1", "s2"}
    for o in out:
        assert "timestamp" in o
        dt = isoparse(o["timestamp"])
        assert dt.utcoffset() == timedelta(0)
        assert "payload_json" in o

def test_messages_cursor_json_accepts_dict_or_string(base_config, monkeypatch):
    # dict case (valid per schema)
    tap = _tap({**base_config, "messages_cursor_json": {"foo": "bar"}})
    s = MessagesStream(tap)
    assert s.cursor_json == {"foo": "bar"}

    # string case: monkeypatch the config property to a mutable dict copy
    tap2 = _tap(base_config)   # valid config
    s2 = MessagesStream(tap2)

    fake_cfg = dict(s2.config)  # make a writable copy
    fake_cfg["messages_cursor_json"] = '{"foo":"bar"}'

    # Patch the class property for this test run
    monkeypatch.setattr(type(s2), "config", property(lambda self: fake_cfg))
    assert s2.cursor_json == {"foo": "bar"}


def test_statuses_cursor_json_accepts_dict_or_string(base_config, monkeypatch):
    tap = _tap({**base_config, "statuses_cursor_json": {"hello": 1}})
    s = StatusesStream(tap)
    assert s.cursor_json == {"hello": 1}

    tap2 = _tap(base_config)
    s2 = StatusesStream(tap2)

    fake_cfg = dict(s2.config)
    fake_cfg["statuses_cursor_json"] = '{"hello":1}'

    monkeypatch.setattr(type(s2), "config", property(lambda self: fake_cfg))
    assert s2.cursor_json == {"hello": 1}
