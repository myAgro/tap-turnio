from tap_turnio.streams import MessageLabelsStream, MessagesStream, StatusesStream
from tap_turnio.tap import TapTurnio  # 


def test_discover_streams_returns_messages_statuses_and_labels(base_config):
    tap = TapTurnio(config=base_config)
    streams = tap.discover_streams()
    names = {type(s).__name__ for s in streams}
    assert names == {"MessagesStream", "StatusesStream", "MessageLabelsStream"}
    assert any(isinstance(s, MessagesStream) for s in streams)
    assert any(isinstance(s, StatusesStream) for s in streams)
    assert any(isinstance(s, MessageLabelsStream) for s in streams)
