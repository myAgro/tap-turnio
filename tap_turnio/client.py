# tap_turnio/client.py
# -----------------------------------------------------------------------------
# Custom HTTP client helpers for the Turn.io tap.
#
# Responsibilities:
#   - Enforce Turn.io’s documented rate limits using response headers:
#       * Retry-After
#       * X-Ratelimit-Bucket / X-Ratelimit-Limit / X-Ratelimit-Remaining
#       * X-Ratelimit-Reset (epoch seconds)
#       * X-throttling (server may hold connection open)
#   - Provide a decorator (`turn_rate_limited_request`) that wraps low-level
#     request senders with:
#       * Header-aware rate limiting
#       * Retry/backoff logic (handles 429s and transient RequestExceptions)
#
# Usage:
#   def request_decorator(self, func):
#       return turn_rate_limited_request(
#           number_hint_getter=self._number_hint,
#           default_timeout=120,
#           logger_obj=self,
#       )(func)
#
# Notes:
#   - Limits are per number, not per account. Always provide a stable
#     number_hint (E.164 preferred).
#   - If `logger_obj` is provided and has `_warning/_error` methods (like
#     TurnStream), those are used. Otherwise fallback to no-op loggers.
# -----------------------------------------------------------------------------

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps

import requests
from requests import Response

############################################################
# DATA STRUCTURES
############################################################

@dataclass
class BucketPolicy:
    """Policy snapshot for a (number, bucket)."""
    limit: int | None = None
    remaining: int | None = None
    reset_epoch: float | None = None  # epoch seconds (float)
    blocked_until: float = 0.0           # unix timestamp until allowed
    last_seen: float = field(default_factory=time.time)


############################################################
# HEADER-AWARE LIMITER
############################################################

# =============================================================================
# Base Class: HeaderAwareLimiter
# Centralizes:
#   - Tracking per-(number, bucket) policies
#   - Blocking acquires based on current policy state
#   - Updating policies from Turn.io response headers
# =============================================================================
class HeaderAwareLimiter:
    """Central rate limiter using Turn.io response headers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._policies: dict[str, BucketPolicy] = {}

    # =============================================================================
    # Internal helpers
    # =============================================================================

    def _key(self, number_hint: str, bucket: str) -> str:
        """Build a unique key from number + bucket."""
        return f"{number_hint}:{(bucket or 'general').lower()}"

    # =============================================================================
    # Acquire & wait
    # =============================================================================

    def acquire(self, number_hint: str, bucket: str = "general") -> None:
        """Block if this bucket is currently throttled."""
        key = self._key(number_hint, bucket)
        with self._lock:
            pol = self._policies.setdefault(key, BucketPolicy())
            wait = max(0.0, pol.blocked_until - time.time())
        if wait > 0:
            time.sleep(wait)

    # =============================================================================
    # Process headers
    # =============================================================================

    def update_from_response(self, number_hint: str, resp: Response) -> None:
        """Update limiter state from Turn.io headers."""
        h = resp.headers
        bucket = (h.get("X-Ratelimit-Bucket") or "general").strip().lower()
        key = self._key(number_hint, bucket)
        now = time.time()

        def _to_int(x) -> int | None:
            try:
                return int(x)
            except Exception:
                return None

        def _to_float(x) -> float | None:
            try:
                return float(x)
            except Exception:
                return None

        retry_after = _to_float(h.get("Retry-After"))
        limit = _to_int(h.get("X-Ratelimit-Limit"))
        remaining = _to_int(h.get("X-Ratelimit-Remaining"))
        reset_epoch = _to_float(h.get("X-Ratelimit-Reset"))
        throttled = _to_int(h.get("X-throttling") or 0) or 0

        with self._lock:
            pol = self._policies.setdefault(key, BucketPolicy())
            pol.last_seen = now
            if limit is not None:
                pol.limit = limit
            if remaining is not None:
                pol.remaining = remaining
            if reset_epoch is not None:
                pol.reset_epoch = reset_epoch

            block_seconds: float | None = None

            if resp.status_code == 429:
                if retry_after is not None:
                    block_seconds = retry_after
                elif pol.reset_epoch is not None:
                    block_seconds = max(0.0, pol.reset_epoch - now)
                else:
                    block_seconds = 2.0
            else:
                if (
                    pol.remaining is not None
                    and pol.reset_epoch is not None
                    and pol.remaining <= 0
                ):
                    block_seconds = max(0.0, pol.reset_epoch - now)

            if block_seconds is not None:
                jitter = random.uniform(0.05, 0.25)
                pol.blocked_until = max(pol.blocked_until, now + block_seconds + jitter)

            if throttled > 0:
                # Cap the extra delay to avoid excessive waits
                throttle_floor = min(throttled * 0.5, 5.0)
                jitter = random.uniform(0.05, 0.25)
                extra = now + throttle_floor + jitter
                pol.blocked_until = max(pol.blocked_until, extra)


############################################################
# DECORATOR FACTORY
############################################################

# Shared limiter instance
_header_limiter = HeaderAwareLimiter()


def turn_rate_limited_request(
    number_hint_getter: Callable[[], str],
    default_timeout: float = 120.0,
    logger_obj=None,
):
    """Wrap outgoing requests with Turn.io header-aware rate limiting."""

    warn = getattr(logger_obj, "_warning", None) or (lambda *a, **k: None)
    err  = getattr(logger_obj, "_error", None) or (lambda *a, **k: None)

    def outer(func):
        @wraps(func)
        def inner(prepared_request, *args, **kwargs):
            number_hint = number_hint_getter() or "unknown"

            _header_limiter.acquire(number_hint, "general")
            kwargs.setdefault("timeout", default_timeout)

            backoff = 1.0
            max_retries = 6

            for attempt in range(max_retries):
                resp: Response | None = None
                try:
                    resp = func(prepared_request, *args, **kwargs)
                    _header_limiter.update_from_response(number_hint, resp)

                    if resp.status_code == 429:
                        _header_limiter.acquire(number_hint, "general")
                        continue

                    resp.raise_for_status()
                    return resp

                except requests.HTTPError as e:
                    if resp is not None and resp.status_code == 429:
                        _header_limiter.acquire(number_hint, "general")
                        continue
                    if attempt == max_retries - 1:
                        err("HTTP error after retries: %s", e, exc_info=True)
                        raise
                    time.sleep(min(backoff, 10.0))
                    backoff *= 2

                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        err("Request failed after retries: %s", e, exc_info=True)
                        raise
                    warn("Transient error '%s' -> retry in %.1fs", e, backoff)
                    time.sleep(min(backoff, 10.0))
                    backoff *= 2

            raise RuntimeError("Turn request retries exhausted")

        return inner

    return outer
