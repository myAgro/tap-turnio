from tap_turnio.streams import MessagesStream, StatusesStream
from tap_turnio.tap import TapTurnio  # 


def test_discover_streams_returns_messages_and_statuses(base_config):
    tap = TapTurnio(config=base_config)
    streams = tap.discover_streams()
    names = {type(s).__name__ for s in streams}
    assert names == {"MessagesStream", "StatusesStream"}
    assert any(isinstance(s, MessagesStream) for s in streams)
    assert any(isinstance(s, StatusesStream) for s in streams)
