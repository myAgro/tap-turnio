from datetime import timedelta

import pytest
from dateutil.parser import isoparse
from singer_sdk.exceptions import TapStreamConnectionFailure

from tap_turnio.streams import MessageLabelsStream, coerce_timestamp
from tap_turnio.tap import TapTurnio


def _stream(base_config, overrides=None):
    tap = TapTurnio(config={**base_config, **(overrides or {})})
    return MessageLabelsStream(tap)


def _wire(stream, routes, dummy_response_cls, calls=None):
    """Answer each GET from `routes`, keyed by the requested URL."""

    def fake_request(prepared_request, context):
        url = prepared_request.url
        if calls is not None:
            calls.append(url)
        if url not in routes:
            raise AssertionError(f"unexpected URL: {url}")
        body = routes[url]
        if isinstance(body, tuple):
            status_code, body = body
        else:
            status_code = 200
        return dummy_response_cls(status_code=status_code, json_data=body, text=str(body))

    stream._request = fake_request


LABELS_URL = "https://whatsapp.turn.io/v1/labels"
MESSAGES_URL = "https://whatsapp.turn.io/v1/labels/lbl-1/messages"


def _label_page(message_ids, has_more=False, next_pointer=None):
    return {
        "has_more": has_more,
        "next": next_pointer,
        "message_labels": [
            {
                "confidence": 0.8,
                "metadata": {},
                "deleted": False,
                "message": {"id": mid, "timestamp": "2026-09-21T03:38:00Z"},
            }
            for mid in message_ids
        ],
    }


ONE_LABEL = {"labels": [{"uuid": "lbl-1", "value": "AgTraining/Information", "color": "yellow"}]}


# =============================================================================
# Timestamp helper
# =============================================================================
@pytest.mark.parametrize(
    ("raw", "expected_year"),
    [("2026-09-21T03:38:00Z", 2026), ("1740000000", 2025), (1740000000, 2025)],
)
def test_coerce_timestamp_accepts_iso_and_epoch(raw, expected_year):
    parsed = isoparse(coerce_timestamp(raw))
    assert parsed.year == expected_year
    assert parsed.utcoffset() == timedelta(0)


@pytest.mark.parametrize("raw", [None, "", "not-a-date", {}])
def test_coerce_timestamp_returns_none_when_unusable(raw):
    assert coerce_timestamp(raw) is None


# =============================================================================
# Stream declaration
# =============================================================================
def test_stream_is_full_table(base_config):
    stream = _stream(base_config)
    assert stream.replication_key is None
    assert stream.replication_method == "FULL_TABLE"
    assert stream.primary_keys == ["message_id", "label_uuid"]


# =============================================================================
# Happy path
# =============================================================================
def test_yields_one_row_per_message_label_pair(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(
        stream,
        {LABELS_URL: ONE_LABEL, MESSAGES_URL: _label_page(["m1", "m2"])},
        dummy_response_cls,
    )

    rows = list(stream.request_records(dummy_context))

    assert [r["message_id"] for r in rows] == ["m1", "m2"]
    assert {r["label_uuid"] for r in rows} == {"lbl-1"}
    assert rows[0]["label_value"] == "AgTraining/Information"
    assert rows[0]["label_color"] == "yellow"
    assert rows[0]["confidence"] == 0.8
    assert rows[0]["deleted"] is False
    assert isoparse(rows[0]["message_timestamp"]).year == 2026


def test_follows_next_pointer_until_has_more_is_false(base_config, dummy_response_cls, dummy_context):
    page_two = "https://whatsapp.turn.io/v1/labels/lbl-1/messages?p=1"
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer="/v1/labels/lbl-1/messages?p=1"),
            page_two: _label_page(["m2"]),
        },
        dummy_response_cls,
    )

    rows = list(stream.request_records(dummy_context))

    assert [r["message_id"] for r in rows] == ["m1", "m2"]


def test_stops_when_has_more_is_false_even_with_a_next_pointer(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=False, next_pointer="/v1/labels/lbl-1/messages?p=1"),
        },
        dummy_response_cls,
    )

    assert len(list(stream.request_records(dummy_context))) == 1


def test_emits_deleted_links_so_removals_reach_the_warehouse(base_config, dummy_response_cls, dummy_context):
    page = _label_page(["m1"])
    page["message_labels"][0]["deleted"] = True
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: ONE_LABEL, MESSAGES_URL: page}, dummy_response_cls)

    rows = list(stream.request_records(dummy_context))

    assert len(rows) == 1
    assert rows[0]["deleted"] is True


# =============================================================================
# Reliability
# =============================================================================
def test_a_repeated_link_keeps_the_later_state(base_config, dummy_response_cls, dummy_context):
    """The loader is last-write-wins on the key, so repeats must pass through.

    Filtering them would pin the first state seen, which is the stale one when
    a label is removed between pages.
    """
    page_two = "https://whatsapp.turn.io/v1/labels/lbl-1/messages?p=1"
    later = _label_page(["m1", "m2"])
    later["message_labels"][0]["deleted"] = True

    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer=page_two),
            page_two: later,
        },
        dummy_response_cls,
    )

    rows = list(stream.request_records(dummy_context))

    assert [r["message_id"] for r in rows] == ["m1", "m1", "m2"]
    assert [r["deleted"] for r in rows if r["message_id"] == "m1"] == [False, True]


def test_refuses_a_next_pointer_on_another_host(base_config, dummy_response_cls, dummy_context):
    """The session carries the bearer token on every request."""
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer="https://attacker.invalid/collect"),
        },
        dummy_response_cls,
    )

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))


def test_accepts_an_absolute_next_pointer_on_the_configured_host(base_config, dummy_response_cls, dummy_context):
    page_two = "https://whatsapp.turn.io/v1/labels/lbl-1/messages?p=1"
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer=page_two),
            page_two: _label_page(["m2"]),
        },
        dummy_response_cls,
    )

    assert [r["message_id"] for r in list(stream.request_records(dummy_context))] == ["m1", "m2"]


def test_more_pages_with_no_pointer_fails_the_run(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer=None),
        },
        dummy_response_cls,
    )

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(True, True), (False, False), ("true", True), ("false", False), ("FALSE", False), (None, False)],
)
def test_reads_the_deleted_flag_without_coercing(base_config, dummy_response_cls, dummy_context, raw, expected):
    """bool("false") is True, which would unlabel the message."""
    page = _label_page(["m1"])
    page["message_labels"][0]["deleted"] = raw
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: ONE_LABEL, MESSAGES_URL: page}, dummy_response_cls)

    assert list(stream.request_records(dummy_context))[0]["deleted"] is expected


def test_an_unrecognised_deleted_value_keeps_the_label(base_config, dummy_response_cls, dummy_context):
    page = _label_page(["m1"])
    page["message_labels"][0]["deleted"] = {"unexpected": "shape"}
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: ONE_LABEL, MESSAGES_URL: page}, dummy_response_cls)

    assert list(stream.request_records(dummy_context))[0]["deleted"] is False


def test_a_page_loop_fails_the_run(base_config, dummy_response_cls, dummy_context):
    """Paging in a circle leaves the rest of the label unreachable."""
    calls = []
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer=MESSAGES_URL),
        },
        dummy_response_cls,
        calls=calls,
    )

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))
    assert calls.count(MESSAGES_URL) == 1


def test_honours_labels_max_pages_per_label(base_config, dummy_response_cls, dummy_context):
    page_two = "https://whatsapp.turn.io/v1/labels/lbl-1/messages?p=1"
    stream = _stream(base_config, {"labels_max_pages_per_label": 1})
    _wire(
        stream,
        {
            LABELS_URL: ONE_LABEL,
            MESSAGES_URL: _label_page(["m1"], has_more=True, next_pointer=page_two),
            page_two: _label_page(["m2"]),
        },
        dummy_response_cls,
    )

    rows = list(stream.request_records(dummy_context))

    assert [r["message_id"] for r in rows] == ["m1"]


def test_skips_entries_without_a_usable_message(base_config, dummy_response_cls, dummy_context):
    page = _label_page(["m1"])
    page["message_labels"].append({"deleted": False, "message": {}})
    page["message_labels"].append({"deleted": False})
    page["message_labels"].append("not-json-at-all")
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: ONE_LABEL, MESSAGES_URL: page}, dummy_response_cls)

    rows = list(stream.request_records(dummy_context))

    assert [r["message_id"] for r in rows] == ["m1"]


def test_keeps_the_link_when_the_message_timestamp_is_unusable(base_config, dummy_response_cls, dummy_context):
    page = _label_page(["m1"])
    page["message_labels"][0]["message"]["timestamp"] = "nonsense"
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: ONE_LABEL, MESSAGES_URL: page}, dummy_response_cls)

    rows = list(stream.request_records(dummy_context))

    assert len(rows) == 1
    assert rows[0]["message_timestamp"] is None


def test_stores_null_for_an_unparseable_confidence(base_config, dummy_response_cls, dummy_context):
    page = _label_page(["m1"])
    page["message_labels"][0]["confidence"] = "high"
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: ONE_LABEL, MESSAGES_URL: page}, dummy_response_cls)

    assert list(stream.request_records(dummy_context))[0]["confidence"] is None


def test_a_failing_label_page_fails_the_run(base_config, dummy_response_cls, dummy_context):
    """A short read must not look like an unlabelling to the loader."""
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: {
                "labels": [
                    {"uuid": "lbl-1", "value": "AgTraining/Information"},
                    {"uuid": "lbl-2", "value": "Other"},
                ]
            },
            MESSAGES_URL: (500, {}),
            "https://whatsapp.turn.io/v1/labels/lbl-2/messages": _label_page(["m2"]),
        },
        dummy_response_cls,
    )

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))


def test_a_failing_label_listing_fails_the_run(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: (500, {})}, dummy_response_cls)

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))


def test_a_malformed_message_page_fails_the_run(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(
        stream,
        {LABELS_URL: ONE_LABEL, MESSAGES_URL: {"has_more": False, "message_labels": "not-a-list"}},
        dummy_response_cls,
    )

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))


def test_skips_labels_without_a_uuid(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: {"labels": [{"value": "no uuid"}, {"uuid": "lbl-1", "value": "ok"}]},
            MESSAGES_URL: _label_page(["m1"]),
        },
        dummy_response_cls,
    )

    assert [r["message_id"] for r in list(stream.request_records(dummy_context))] == ["m1"]


def test_a_malformed_label_listing_fails_the_run(base_config, dummy_response_cls, dummy_context):
    stream = _stream(base_config)
    _wire(stream, {LABELS_URL: {"labels": "not-a-list"}}, dummy_response_cls)

    with pytest.raises(TapStreamConnectionFailure):
        list(stream.request_records(dummy_context))


def test_label_uuid_is_url_encoded(base_config, dummy_response_cls, dummy_context):
    calls = []
    stream = _stream(base_config)
    _wire(
        stream,
        {
            LABELS_URL: {"labels": [{"uuid": "a b/c", "value": "odd"}]},
            "https://whatsapp.turn.io/v1/labels/a+b%2Fc/messages": _label_page(["m1"]),
        },
        dummy_response_cls,
        calls=calls,
    )

    list(stream.request_records(dummy_context))

    assert "https://whatsapp.turn.io/v1/labels/a+b%2Fc/messages" in calls


def test_never_emits_activate_version_messages(base_config):
    """The loader acts on those before the first record, so a failed sweep
    would blank every label."""
    stream = _stream(base_config)
    assert stream.emit_activate_version_messages is False

    # The SDK reads this from config, so prove config cannot turn it back on.
    forced = dict(stream.config)
    forced["emit_activate_version_messages"] = True
    # Shadow the config property so the SDK would see the flag turned on.
    type(stream).config = property(lambda self: forced)
    try:
        assert stream.emit_activate_version_messages is False
    finally:
        del type(stream).config


def test_epoch_like_dates_are_rejected_rather_than_read_as_seconds():
    """"20260921" is a date without separators, not an epoch."""
    assert coerce_timestamp("20260921") is None
    assert coerce_timestamp(True) is None
    assert coerce_timestamp(False) is None
    assert coerce_timestamp("1740000000") is not None


def test_the_sweep_reuses_one_session(base_config):
    stream = _stream(base_config)
    assert stream.http_client is stream.http_client
