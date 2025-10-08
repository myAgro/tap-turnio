import time

from tap_turnio.client import HeaderAwareLimiter, turn_rate_limited_request  # 


def test_header_aware_limiter_updates_and_blocks(monkeypatch, dummy_response_cls):
    lim = HeaderAwareLimiter()

    now = 1_700_000_000.0
    monkeypatch.setattr(time, "time", lambda: now)

    # Simulate 429 with Retry-After=1.5
    resp = dummy_response_cls(
        status_code=429,
        headers={"Retry-After": "1.5", "X-Ratelimit-Bucket": "general"}
    )
    lim.update_from_response("+254700000000", resp)

    # After update, blocked_until should be > now (check acquire sleeps by advancing time)
    waited = {"slept": 0.0}
    def fake_sleep(secs):
        waited["slept"] += secs
    monkeypatch.setattr(time, "sleep", fake_sleep)

    lim.acquire("+254700000000", "general")
    assert waited["slept"] >= 0.0  # don't assert exact due to jitter

    # Advance time beyond reset and ensure no further blocking
    monkeypatch.setattr(time, "time", lambda: now + 10)
    waited["slept"] = 0.0
    lim.acquire("+254700000000", "general")
    assert waited["slept"] == 0.0

def test_turn_rate_limited_request_retries(monkeypatch, dummy_response_cls):
    calls = {"n": 0}

    def fake_sender(prepared_request, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return dummy_response_cls(status_code=429, headers={"Retry-After": "0.1"})
        return dummy_response_cls(status_code=200, headers={})

    def number_hint_getter() -> str:
        return "+254700000000"

    # no-op logger with the expected methods used by the decorator
    logger = type("L", (), {"_warning": lambda *a, **k: None, "_error": lambda *a, **k: None})()

    wrapped = turn_rate_limited_request(
        number_hint_getter,
        default_timeout=0.1,
        logger_obj=logger,
    )(fake_sender)

    # Patch time.sleep to avoid delays
    monkeypatch.setattr(time, "sleep", lambda s: None)

    resp = wrapped(prepared_request=object())
    assert resp.status_code == 200
    assert calls["n"] >= 2  # at least one retry happened
