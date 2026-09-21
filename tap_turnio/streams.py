# tap_turnio/streams.py
# -----------------------------------------------------------------------------
# Stream definitions for the tap-turnio Singer tap.
# All routine logging goes through the helpers in the "Logging Helpers" section.
# -----------------------------------------------------------------------------

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from json import JSONDecodeError
from typing import Any
from urllib.parse import quote_plus

import pendulum
import requests
from dateutil.parser import isoparse
from requests import PreparedRequest, Request, Response
from singer_sdk import typing as th
from singer_sdk.exceptions import TapStreamConnectionFailure
from singer_sdk.streams.rest import RESTStream

from tap_turnio.auth import TurnAuthenticator
from tap_turnio.client import turn_rate_limited_request


# =============================================================================
# Module helpers
# =============================================================================
def coerce_timestamp(value: Any) -> str | None:
    """Return a UTC ISO-8601 string for a Turn timestamp, or None if unusable.

    Turn sends either an ISO-8601 string or a Unix epoch, and the epoch arrives
    as a bare integer on some endpoints and a digit string on others.
    """
    if value is None or value == "":
        return None
    try:
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, int | float):
            return datetime.fromtimestamp(value, tz=UTC).isoformat()
        return isoparse(value).astimezone(UTC).isoformat()
    except Exception:
        return None


# =============================================================================
# Base Class: RESTStream
# Centralizes:
#   - Config & auth
#   - HTTP client prep + request lifecycle
#   - Logging helpers (preferred for all logs)
#   - Window/bookmark utilities
#   - Request construction (URL, payload)
#   - Pagination & record iteration
#   - Response parsing & post-processing scaffolding
# =============================================================================
class TurnStream(RESTStream):
    """Base class for Turn.io REST streams.

    Provides common functionality for API requests, authentication, pagination,
    logging, and data processing for Turn.io streams.
    """

    # ---- JSON extraction / headers ------------------------------------------------
    records_jsonpath = "$.data[*]"
    extra_headers = {"Accept": "application/vnd.v1+json"}

    # =============================================================================
    # Config, Auth, and HTTP setup
    # =============================================================================
    @property
    def url_base(self) -> str:
        """Return base URL from config, stripping trailing slash."""
        return self.config["base_url"].rstrip("/")

    @property
    def authenticator(self) -> TurnAuthenticator:
        """Return authenticator initialized with config credentials."""
        return TurnAuthenticator(
            self.config.get("username"),
            self.config.get("password"),
            self.config.get("token"),
            self.url_base,
        )

    @property
    def http_client(self) -> requests.Session:
        """Configure and return an HTTP session."""
        session = requests.Session()
        session.headers.update(self.extra_headers)
        session.headers.update(self.authenticator.auth_headers)
        session.verify = not self.config.get("insecure", False)
        return session

    # =============================================================================
    # Logging Helpers
    # Use these everywhere unless logging directly is required (e.g., inside except).
    # Centralizing here makes it easy to adjust verbosity/format globally.
    # =============================================================================
    def _log(self, level: int, msg: str, *args, **kwargs) -> None:
        """Log with correct color and message type."""
        # Detect if stdout is a terminal (so colors only show in dev)
        use_color = sys.stdout.isatty() or sys.stderr.isatty() or bool(os.getenv("FORCE_COLOR", ""))
        level_name = logging.getLevelName(level)
        color_map = {
            "DEBUG": "\033[90m",    # gray
            "INFO": "\033[37m",     # white
            "WARNING": "\033[33m",  # yellow
            "ERROR": "\033[31m",    # red
            "CRITICAL": "\033[91m"  # bright red
        }
        reset = "\033[0m"
        # Colorize message if interactive
        if use_color and level_name in color_map:
            msg = f"{color_map[level_name]}[{level_name}] {msg}{reset}"
        else:
            msg = f"[{level_name}] {msg}"
        self.logger.log(level, msg, *args, **kwargs)

    def _info(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.INFO, msg, *args, **kwargs)

    def _debug(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def _warning(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.WARNING, msg, *args, **kwargs)

    def _error(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.ERROR, msg, *args, **kwargs)

    # --- Redaction / prettifiers --------------------------------------------------
    def _redact_headers(self, headers: dict) -> dict:
        """Redact sensitive headers like authorization tokens."""
        SENSITIVE = {
            "owner",
            "contact_id",
            "recipient_id",
            "username",
            "password",
            "authorization",
            "cookie",
            "x-api-key",
            "set-cookie",
        }
        return {
            k: ("<redacted>" if k.lower() in SENSITIVE else v)
            for k, v in dict(headers or {}).items()
        }

    def _pretty(self, obj: Any, limit: int = 1500) -> str:
        """Pretty-print object as JSON, truncating if longer than limit."""
        try:
            s = json.dumps(obj, ensure_ascii=False, default=str)
        except Exception:
            s = str(obj)
        return s if len(s) <= limit else s[:limit] + f"... <truncated {len(s) - limit} chars>"

    # --- Structured HTTP logging --------------------------------------------------
    def _log_http_response(
        self,
        resp: Response,
        *,
        level_ok: int = logging.DEBUG,
        level_err: int = logging.ERROR,
        note: str = "",
    ) -> None:
        """Log HTTP response details."""
        preq = getattr(resp, "request", None)
        method = getattr(preq, "method", "?")
        url = getattr(preq, "url", getattr(resp, "url", "?"))
        status = resp.status_code
        ok = 200 <= status < 400

        body = getattr(preq, "body", None)
        try:
            body_txt = body.decode() if isinstance(body, bytes | bytearray) else body
            body_json = json.loads(body_txt) if body_txt else None
        except Exception:
            body_json = body if body else None

        label = "HTTP OK" if ok else "HTTP ERROR"
        level = level_ok if ok else level_err

        self._log(
            level,
            "%s %s %s -> %s %s | req_headers=%s | req_json=%s | resp_headers=%s | resp_text=%s",
            label,
            method,
            url,
            status,
            getattr(resp, "reason", ""),
            self._redact_headers(getattr(preq, "headers", {})),
            self._pretty(body_json),
            dict(getattr(resp, "headers", {}) or {}),
            self._pretty(getattr(resp, "text", "")),
        )
        if note:
            self._log(level, "%s note: %s", label, note)

    def _log_request_exception(
        self,
        err: Exception,
        preq: PreparedRequest | Request | None,
    ) -> None:
        """Log request exception details."""
        method = getattr(preq, "method", "?")
        url = getattr(preq, "url", "?")
        headers = self._redact_headers(getattr(preq, "headers", {}))
        body = getattr(preq, "body", None)
        try:
            body_txt = body.decode() if isinstance(body, bytes | bytearray) else body
            body_json = json.loads(body_txt) if body_txt else None
        except Exception:
            body_json = body if body else None
        self._error(
            "HTTP EXCEPTION %s %s | headers=%s | json=%s | error=%r",
            method,
            url,
            headers,
            self._pretty(body_json),
            err,
            exc_info=True,
        )

    def _log_prepared_request(self, prepared_request: PreparedRequest, label: str) -> None:
        """Log prepared request details including method, URL, headers, and body."""
        body = prepared_request.body
        try:
            body_txt = body.decode() if isinstance(body, bytes | bytearray) else body
            body_json = json.loads(body_txt) if body_txt else None
        except Exception:
            body_json = body  # not JSON or None

        self._info(
            "REQ[%s] %s %s headers=%s json=%s",
            label,
            getattr(prepared_request, "method", "NA"),
            prepared_request.url,
            self._redact_headers(prepared_request.headers),
            self._pretty(body_json),
        )

    def _preview_message(self, obj: dict, level: int = logging.INFO) -> None:
        """Log preview of a message or the first message in a container."""
        m = obj
        if isinstance(obj, dict) and isinstance(obj.get("messages"), list) and obj["messages"]:
            m = obj["messages"][0]

        direction = None
        if isinstance(m, dict):
            vnd = m.get("_vnd", {})
            v1 = vnd.get("v1", {}) if isinstance(vnd, dict) else {}
            direction = v1.get("direction")

        language = None
        if isinstance(m, dict):
            tmpl = m.get("template") or {}
            lang = tmpl.get("language") or {}
            language = lang.get("code")

        preview = {
            "id": m.get("id") if isinstance(m, dict) else None,
            "type": m.get("type") if isinstance(m, dict) else None,
            "from": m.get("from") if isinstance(m, dict) else None,
            "to": m.get("to") if isinstance(m, dict) else None,
            "direction": direction,
            "timestamp": m.get("timestamp") if isinstance(m, dict) else None,
            "template": (m.get("template") or {}).get("name") if isinstance(m, dict) else None,
            "language": language,
            "has_media": bool(
                isinstance(m, dict)
                and (m.get("audio") or m.get("video") or m.get("image") or m.get("document"))
            ),
            "text": (m.get("text") or {}).get("body") if isinstance(m, dict) else None,
        }
        self._log(level, "MSG PREVIEW %s", self._pretty(preview, limit=2000))

    # =============================================================================
    # HTTP lifecycle hooks
    # =============================================================================
    def validate_response(self, response: Response) -> None:
        """Validate HTTP response, logging details if configured or on error."""
        if response is None:
            self._error("HTTP ERROR: response is None")
            return super().validate_response(response)

        status = response.status_code
        if self.config.get("log_http_success", False) and 200 <= status < 400:
            self._log_http_response(response)  # HTTP OK
        if status >= 400:
            self._log_http_response(response)  # HTTP ERROR
        return super().validate_response(response)

    # =============================================================================
    # Window & bookmark utilities
    # =============================================================================
    def _coerce_utc(self, v: Any) -> datetime | None:
        """Convert input to UTC datetime."""
        if v is None:
            return None
        if isinstance(v, datetime):
            return v.astimezone(UTC)
        try:
            return pendulum.parse(v).astimezone(UTC)
        except Exception:
            return None

    def _compute_window(self, context: dict) -> tuple[datetime, datetime]:
        """Compute sync window: bookmark or static start to now."""
        now = datetime.now(UTC)
        bookmark = self.get_starting_timestamp(context)
        if bookmark:
            start = bookmark
            src = "state"
        else:
            start = self._pick_static_start_date()
            src = "static"

        lb = int(self.config.get("lookback_sec", 0) or 0)
        if src == "state" and lb > 0:
            start = start - timedelta(seconds=lb)

        self._info(
            "%s window source=%s start=%s end=%s",
            self.kind,
            src,
            start.isoformat(),
            now.isoformat(),
        )
        return start, now

    def get_starting_timestamp(self, context: dict) -> datetime | None:
        """Fetch bookmark using Singer SDK logic and coerce to UTC."""
        raw = super().get_starting_replication_key_value(context)
        dt = self._coerce_utc(raw)
        self._info("%s: SDK starting bookmark raw=%r -> %s", self.kind, raw, dt.isoformat() if dt else None)
        return dt

    def _pick_static_start_date(self) -> datetime:
        """Select start date from config, cursor_json, or default to 24h ago."""
        cfg = self.config.get("start_date")
        if cfg:
            try:
                return isoparse(cfg).astimezone(UTC)
            except Exception as e:
                self._warning("Invalid config start_date %r: %s", cfg, e)

        try:
            cj = self.cursor_json if isinstance(getattr(self, "cursor_json", None), dict) else {}
        except Exception:
            cj = {}
        sd = cj.get("start_date")
        if sd:
            try:
                return isoparse(sd).astimezone(UTC)
            except Exception as e:
                self._warning("Invalid cursor_json.start_date %r: %s", sd, e)

        return datetime.now(UTC) - timedelta(hours=24)

    def get_starting_replication_key_value(self, context: dict) -> datetime:
        """Override to handle start_date fallback."""
        start_date = self.config.get("start_date")
        if start_date:
            try:
                return isoparse(start_date).astimezone(UTC)
            except Exception as e:
                self._warning("Invalid start_date: %s, falling back to 24h ago", e)
        return datetime.now(UTC) - timedelta(hours=24)

    # =============================================================================
    # Request construction (URL, payload, preparation)
    # =============================================================================
    def get_url(self, context: dict) -> str:
        """Return the base URL for cursor creation."""
        return f"{self.url_base}/v1/data/{self.kind}/cursor"

    def prepare_request_payload(self, context: dict, next_page_token: str | None):
        """Build POST payload for cursor creation, avoiding date overrides."""
        if next_page_token:
            return None

        start_dt, end_dt = self._compute_window(context)
        try:
            cj = self.cursor_json if isinstance(getattr(self, "cursor_json", None), dict) else {}
        except Exception:
            cj = {}

        _exclude = {"start_date", "end_date", "from", "until", "page_size"}
        extras = {k: v for k, v in cj.items() if k not in _exclude}
        page_size = self.config.get("page_size", cj.get("page_size", 500))

        payload = {
            "start_date": start_dt.isoformat(),
            "end_date": end_dt.isoformat(),
            "from": start_dt.isoformat(),
            "until": end_dt.isoformat(),
            "page_size": page_size,
            **extras,
        }

        self._info(
            "%s payload window start=%s end=%s (page_size=%s, extras=%s)",
            self.kind,
            payload["start_date"],
            payload["end_date"],
            page_size,
            list(extras.keys()),
        )
        return payload

    def prepare_request(self, context: dict, next_page_token: str | None) -> PreparedRequest:
        """Prepare HTTP request with dynamic method and parameters."""
        method = "POST" if not next_page_token else "GET"
        url = next_page_token if next_page_token else self.get_url(context)
        request_data = self.prepare_request_payload(context, next_page_token)
        headers = self.http_headers
        request = Request(method=method, url=url, json=request_data, headers=headers)
        return self.http_client.prepare_request(request)

    # =============================================================================
    # Pagination (cursor creation + page fetching)
    # =============================================================================
    def _create_cursor(self, context: dict) -> tuple[str | None, dict | None]:
        """Create cursor for paginated API requests."""
        prepared_request = self.prepare_request(context, None)
        self._log_prepared_request(prepared_request, "create_cursor")
        response = self._request(prepared_request, context)
        """Log and parse cursor creation response."""
        self._log_http_response(response, note="Cursor creation response")
        if response.status_code == 403:
            self._error("Access forbidden (403) when creating cursor for %s. Check credentials and permissions.", self.kind)
            raise TapStreamConnectionFailure("403 Forbidden")
        if not getattr(response, "text", "").strip():
            self._warning(
                "Empty response body when creating cursor for %s (HTTP %s)",
                self.kind,
                getattr(response, "status_code", "unknown"),
            )
            return None, None
        try:
            meta = response.json()
        except JSONDecodeError:
            self._error("Invalid JSON response when creating cursor for %s: %s", self.kind, response.text)
            raise
        cursor = meta.get("cursor")
        if not cursor:
            self._error("No cursor returned for %s: %s", self.kind, meta)
            return None, None
        self._info("Created cursor for %s: %s", self.kind, cursor)
        if "expires_at" in meta:
            self._info("Cursor for %s expires at: %s", self.kind, meta["expires_at"])
        return cursor, meta

    def _extract_next_pointer(self, page: dict | None) -> str | None:
        """Extract 'next' pagination pointer from API response."""
        if not isinstance(page, dict):
            self._debug("page is not a dict (%s); cannot extract next", type(page).__name__)
            return None

        for key in ("links", "paging"):
            section = page.get(key)
            if section is None:
                continue
            if not isinstance(section, dict):
                self._debug("page['%s'] is %s, skipping", key, type(section).__name__)
                continue
            nxt = section.get("next")
            if isinstance(nxt, str) and nxt.strip():
                return nxt.strip()
            if nxt not in (None, "", []):
                self._debug("Unexpected next type under '%s': %s -> %s", key, type(nxt).__name__, nxt)
        return None

    def _fetch_pages(self, cursor: str, context: dict) -> Iterable[dict]:
        """Fetch paginated data using cursor, yielding records in batches."""
        max_pages = self.config.get("max_pages", 0)
        page_num = context.get("page_num", 0)
        batch: list[dict] = []
        batch_size = self.config.get("batch_size", 100)
        max_bookmark: str | None = None

        def _emit_batch() -> Iterable[dict]:
            nonlocal batch
            if not batch:
                return
            self._debug("Yielding batch of %d records", len(batch))
            for b in batch:
                if not isinstance(b, dict):
                    self._error("Invalid batch record in %s: expected dict, got %s", self.kind, type(b).__name__)
                    continue
                yield b
            batch = []

        while cursor:
            url = f"{self.url_base}/v1/data/{self.kind}/cursor/{quote_plus(cursor)}"
            prepared_request = self.prepare_request(context, url)
            self._log_prepared_request(prepared_request, f"pagination {self.kind} page{page_num + 1}")
            response = self._request(prepared_request, context)

            try:
                page = response.json()
                if not isinstance(page, dict):
                    self._error(
                        "Invalid JSON page for %s page %d: expected dict, got %s",
                        self.kind,
                        page_num + 1,
                        type(page).__name__,
                    )
                    break
            except JSONDecodeError as e:
                self._error("Invalid JSON response for %s page %d: %s, error: %s", self.kind, page_num + 1, response.text, e)
                break
            except Exception as e:
                self._error("Unexpected error parsing response for %s page %d: %s", self.kind, page_num + 1, e)
                break

            if page is None:
                self._error("Parsed page is None for %s page %d", self.kind, page_num + 1)
                break

            page_records: list[dict] = []
            for record in self.parse_response(page):
                if self.config.get("log_message_preview", True):
                    try:
                        self._preview_message(record, level=logging.INFO)
                    except Exception as e:
                        self._debug("MSG PREVIEW failed: %s", e)

                # Filter by allowed message types if configured
                allowed = set(self.config.get("allowed_message_types", []))
                msg_type = record.get("type") if isinstance(record, dict) else None
                if allowed and msg_type not in allowed:
                    self._preview_message(record, level=logging.WARNING)
                    continue

                if not isinstance(record, dict):
                    self._warning("Skipping invalid record in %s: expected dict, got %s", self.kind, type(record).__name__)
                    continue
                processed_record = self.post_process(record, context)
                if processed_record is None or not isinstance(processed_record, dict):
                    self._debug("Skipping None/non-dict record after post_process in %s", self.kind)
                    continue

                ts = processed_record.get("timestamp")
                if ts and (max_bookmark is None or ts > max_bookmark):
                    max_bookmark = ts

                page_records.append(processed_record)
                batch.append(processed_record)

                if len(batch) >= batch_size:
                    yield from _emit_batch()

            self._info("Fetched %s page %d with %d valid records", self.kind, page_num + 1, len(page_records))

            page_num += 1
            if max_pages > 0 and page_num >= max_pages:
                self._info("Reached max_pages (%s) for %s", max_pages, self.kind)
                break

            nxt = self._extract_next_pointer(page)
            self._debug("Next pointer for %s page %d: %s", self.kind, page_num + 1, nxt)

            if isinstance(nxt, str) and nxt.strip():
                if nxt.startswith("http"):
                    req = Request(method="GET", url=nxt, headers=self.http_headers)
                    prepared_next = self.http_client.prepare_request(req)
                    self._log_prepared_request(prepared_next, f"links.next {self.kind} page{page_num + 1}")
                    response = self._request(prepared_next, context)
                    try:
                        page = response.json()
                    except JSONDecodeError as e:
                        self._error("Invalid JSON at next URL for %s: %s, error: %s", self.kind, nxt, e)
                        break
                    except Exception as e:
                        self._error("Error fetching next URL for %s: %s", self.kind, e)
                        break

                    page_records = []
                    for record in self.parse_response(page):
                        if not isinstance(record, dict):
                            self._warning("Skipping invalid record in %s: expected dict, got %s", self.kind, type(record).__name__)
                            continue
                        processed_record = self.post_process(record, context)
                        if processed_record is None or not isinstance(processed_record, dict):
                            continue
                        ts = processed_record.get("timestamp")
                        if ts and (max_bookmark is None or ts > max_bookmark):
                            max_bookmark = ts
                        page_records.append(processed_record)
                        batch.append(processed_record)
                        if len(batch) >= batch_size:
                            yield from _emit_batch()

                    self._info("Fetched %s page %d with %d valid records (via links.next)", self.kind, page_num + 1, len(page_records))
                    page_num += 1
                    if max_pages > 0 and page_num >= max_pages:
                        self._info("Reached max_pages (%s) for %s", max_pages, self.kind)
                        break

                    cursor = self._extract_next_pointer(page)
                    self._debug("Next cursor for %s page %d: %s", self.kind, page_num + 1, cursor)
                    if not cursor and not page.get("links", {}).get("next"):
                        yield from _emit_batch()
                        break
                    continue
                else:
                    cursor = nxt
            else:
                cursor = None

            context["page_num"] = page_num
            context["next_page_token"] = cursor

        # last batch
        yield from _emit_batch()

        from_dt, until_dt = self._compute_window(context)
        self._info("%s sync window: from %s until %s", self.kind, from_dt.isoformat(), until_dt.isoformat())
        if max_bookmark:
            self._info("Max bookmark (%s) for %s: %s", self.replication_key, self.kind, max_bookmark)

    def fetch_pages(self, context: dict) -> Iterable[dict]:
        """Fetch pages, initializing cursor if needed."""
        cursor, _ = self._create_cursor(context)
        if not cursor:
            return
        yield from self._fetch_pages(cursor, context)

    # =============================================================================
    # Response parsing & record emission
    # =============================================================================
    def parse_response(self, response: Response | dict) -> Iterable[dict]:
        """Yield each item from 'data' list in response."""
        try:
            data = response if isinstance(response, dict) else response.json()
        except JSONDecodeError:
            self._error(
                "Invalid JSON response for %s: %s",
                self.kind,
                response.text if hasattr(response, "text") else response,
            )
            return
        records = data.get("data", [])
        if not isinstance(records, list):
            self._error("Expected 'data' to be a list in %s, got %s", self.kind, type(records).__name__)
            return
        for item in records:
            if isinstance(item, str):
                try:
                    item = json.loads(item)
                except JSONDecodeError:
                    self._error("Failed to parse string item as JSON in %s: %s", self.kind, item)
                    continue
            if not isinstance(item, dict):
                self._warning("Skipping invalid item in %s: expected dict, got %s", self.kind, type(item).__name__)
                continue
            yield item

    def post_process(self, row: Any, context: dict) -> dict | None:
        """Ensure row is a dict, parsing strings if needed."""
        if isinstance(row, str):
            try:
                row = json.loads(row)
            except JSONDecodeError:
                self._error("Failed to parse string row as JSON in %s: %s", self.kind, row)
                return None
        if not isinstance(row, dict):
            self._error("Invalid record in %s: expected dict, got %s", self.kind, type(row).__name__)
            return None
        return row

    # =============================================================================
    # Public record request entrypoint
    # =============================================================================
    def request_records(self, context: dict | None) -> Iterable[dict]:
        """Yield processed records with essential field validation."""
        context = context or {}
        for record in self.fetch_pages(context):
            if not isinstance(record, dict):
                self._error("Invalid record in request_records for %s: expected dict, got %s", self.kind, type(record).__name__)
                continue
            if "id" not in record:
                self._error("Record missing 'id' in %s: %s", self.kind, record)
                continue
            if "timestamp" not in record:
                self._error("Record missing 'timestamp' in %s: %s", self.kind, record)
                continue
            yield record

    # ---------------------------------------------------------------------
    # Stable per-number identifier for the limiter
    # ---------------------------------------------------------------------
    def _number_hint(self) -> str:
        """Return a stable identifier that maps 1:1 to the Turn number.

        Prefer an explicit E.164 number in config if its there.
        Fallback to a stable username that maps to a single number.
        """
        # Do not remove this — the limiter uses this to separate buckets per number.
        return str(self.config.get("e164_number")
                   or self.config.get("number")
                   or self.config.get("username")
                   or "unknown")

    # =============================================================================
    # Request decorator (rate limiting + exception logging)
    # =============================================================================
    def request_decorator(self, func):
        """Singer SDK gives us the low-level sender here; return a decorated version."""
        request_timeout = float(self.config.get("request_timeout_sec", 120.0))
        return turn_rate_limited_request(
            number_hint_getter=self._number_hint,
            default_timeout=request_timeout,
            logger_obj=self,
        )(func)

    # ---------------------------------------------------------------------
    # OPTIONAL SAFETY: centralize sending through a method that can be called
    # everywhere in this class. The SDK will still run the decorator above.
    # ---------------------------------------------------------------------
    def _send(self, prepared_request, **kwargs):
        """Delegate to the underlying http_client.send.

        Keeping a single send path makes it harder to accidentally bypass the
        decorator in future code changes.
        """
        return self.http_client.send(prepared_request, **kwargs)

    # ---------------------------------------------------------------------
    # Call self._send on send requests
    # ---------------------------------------------------------------------
    def _request(self, prepared_request, context):
        """(On override _request) Always go through self._send."""
        return self._send(prepared_request)


# =============================================================================
# Messages Stream
# Focused overrides:
#   - cursor_json property
#   - parse_response: flatten container 'messages'
#   - post_process: normalize into schema with contact/direction/timestamp
# =============================================================================
class MessagesStream(TurnStream):
    """Stream for Turn.io message data."""

    name = "messages"
    kind = "messages"
    path = "/v1/data/messages/cursor"
    primary_keys = ["id"]
    replication_key = "timestamp"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("contact_id", th.StringType),
        th.Property("direction", th.StringType),
        th.Property("timestamp", th.DateTimeType),
        th.Property("payload_json", th.ObjectType(additional_properties=True)),
    ).to_dict()

    @property
    def cursor_json(self) -> dict:
        """Return messages cursor JSON, parsing if string."""
        cursor_json = self.config.get("messages_cursor_json", "{}")
        self._debug("messages_cursor_json type: %s", type(cursor_json).__name__)
        if isinstance(cursor_json, dict):
            return cursor_json
        try:
            return json.loads(cursor_json)
        except JSONDecodeError as e:
            self._error("Invalid messages_cursor_json: %s", e)
            return {}

    def parse_response(self, response: Response | dict) -> Iterable[dict]:
        """Flatten response, yielding each inner message."""
        try:
            data = response if isinstance(response, dict) else response.json()
        except JSONDecodeError:
            self._error(
                "Invalid JSON response for %s: %s",
                self.kind,
                response.text if hasattr(response, "text") else response,
            )
            return
        items = data.get("data", [])
        if not isinstance(items, list):
            self._error("Expected 'data' to be a list in %s, got %s", self.kind, type(items).__name__)
            return

        for item in items:
            if isinstance(item, str):
                try:
                    item = json.loads(item)
                except JSONDecodeError:
                    self._error("Failed to parse string item as JSON in %s: %s", self.kind, item)
                    continue
            if not isinstance(item, dict):
                continue

            msgs = item.get("messages")
            if isinstance(msgs, list) and msgs:
                contacts = item.get("contacts")
                for m in msgs:
                    if isinstance(m, dict):
                        if contacts is not None:
                            m = {**m, "_container": {"contacts": contacts}}
                        yield m
                continue

            if any(k in item for k in ("id", "type", "timestamp", "_vnd")):
                yield item

    def post_process(self, message: Any, context: dict) -> dict | None:
        """Process message into schema-safe output."""
        message = super().post_process(message, context)
        if message is None:
            return None

        mid = message.get("id")
        if not mid:
            self._error("Missing 'id' in message for %s: %s", self.kind, message)
            return None

        ts = message.get("timestamp")
        if not ts:
            self._error("Missing 'timestamp' in message for %s: %s", self.kind, message)
            return None

        try:
            if isinstance(ts, str) and ts.isdigit():
                ts = int(ts)
            timestamp = (
                datetime.fromtimestamp(ts, tz=UTC).isoformat()
                if isinstance(ts, int)
                else isoparse(ts).astimezone(UTC).isoformat()
            )
        except Exception as e:
            self._error("Invalid timestamp in %s message: %r, error: %s", self.kind, ts, e)
            return None

        contact_id = message.get("from", "")
        direction = message.get("_vnd", {}).get("v1", {}).get("direction", "")

        return {
            "id": mid,
            "contact_id": contact_id,
            "direction": direction,
            "timestamp": timestamp,
            "payload_json": message,
        }


# =============================================================================
# Statuses Stream
# Focused overrides:
#   - cursor_json property
#   - parse_response: flatten container 'statuses'
#   - post_process: normalize into schema with message_id/recipient/timestamp
# =============================================================================
class StatusesStream(TurnStream):
    """Stream for Turn.io status updates."""

    name = "statuses"
    kind = "statuses"
    path = "/v1/data/statuses/cursor"
    primary_keys = ["id", "status", "timestamp"]
    replication_key = "timestamp"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("message_id", th.StringType),
        th.Property("status", th.StringType),
        th.Property("timestamp", th.DateTimeType),
        th.Property("recipient_id", th.StringType),
        th.Property("payload_json", th.ObjectType(additional_properties=True)),
    ).to_dict()

    @property
    def cursor_json(self) -> dict:
        """Return statuses cursor JSON, parsing if string."""
        cursor_json = self.config.get("statuses_cursor_json", "{}")
        self._debug("statuses_cursor_json type: %s", type(cursor_json).__name__)
        if isinstance(cursor_json, dict):
            return cursor_json
        try:
            return json.loads(cursor_json)
        except JSONDecodeError as e:
            self._error("Invalid statuses_cursor_json: %s", e)
            return {}

    def parse_response(self, response: Response | dict) -> Iterable[dict]:
        """Flatten response, yielding each inner status."""
        try:
            data = response if isinstance(response, dict) else response.json()
        except JSONDecodeError:
            self._error(
                "Invalid JSON response for %s: %s",
                self.kind,
                response.text if hasattr(response, "text") else response,
            )
            return

        items = data.get("data", [])
        if not isinstance(items, list):
            self._error("Expected 'data' to be a list in %s, got %s", self.kind, type(items).__name__)
            return

        for item in items:
            if isinstance(item, str):
                try:
                    item = json.loads(item)
                except JSONDecodeError:
                    self._error("Failed to parse string item as JSON in %s: %s", self.kind, item)
                    continue
            if not isinstance(item, dict):
                continue

            sts = item.get("statuses")
            if isinstance(sts, list) and sts:
                for s in sts:
                    if isinstance(s, dict):
                        yield s
                continue

            if any(k in item for k in ("id", "status", "timestamp")):
                yield item

    def post_process(self, status: Any, context: dict) -> dict | None:
        """Process status into schema-safe output."""
        status = super().post_process(status, context)
        if status is None:
            return None

        sid = status.get("id")
        if not sid:
            self._error("Missing 'id' in status record: %s", status)
            return None

        ts = status.get("timestamp")
        if not ts:
            self._error("Missing 'timestamp' in status record: %s", status)
            return None

        try:
            if isinstance(ts, str) and ts.isdigit():
                ts = int(ts)
            iso_ts = (
                datetime.fromtimestamp(ts, tz=UTC).isoformat()
                if isinstance(ts, int)
                else isoparse(ts).astimezone(UTC).isoformat()
            )
        except Exception as e:
            self._error("Invalid timestamp in %s record: %r, error: %s", self.kind, ts, e)
            return None

        status_val = status.get("status", "")
        recipient_id = status.get("recipient_id", "")
        message_id = status.get("message_id") or sid

        return {
            "id": sid,
            "message_id": message_id,
            "status": status_val,
            "timestamp": iso_ts,
            "recipient_id": recipient_id,
            "payload_json": status,
        }


# =============================================================================
# Message Labels Stream
#
# Why this stream exists:
#   Turn paginates the message export by `inserted_at` and never re-emits a
#   message once it is logged, so a label applied minutes or days after the
#   message arrived can never reach us through `messages`. The label endpoints
#   are the only read path that reflects the current state, so labels are
#   pulled from there and joined back on message_id downstream.
#
# Shape:
#   One row per (message, label) pair, including pairs Turn has marked
#   `deleted`, so that an unlabelled message can be reconciled downstream
#   rather than silently keeping a stale label.
#
# Focused overrides:
#   - request_records: walks /v1/labels, then /v1/labels/<uuid>/messages
#   - no cursor endpoint, so the base window/bookmark machinery is unused
#
# Partial sweeps are treated as failures. On a full-table stream a short read
# is indistinguishable from "this label lost its messages", and the loader
# would carry that straight through to the warehouse as an unlabelling. Every
# transport or shape error therefore raises and fails the run, leaving the
# previous good copy in place.
# =============================================================================
class MessageLabelsStream(TurnStream):
    """Stream of message-to-label links read from the Turn label endpoints."""

    name = "message_labels"
    kind = "message_labels"
    path = "/v1/labels"
    primary_keys = ["message_id", "label_uuid"]
    # Full table on purpose. The only usable ordering here is the message
    # timestamp, and bookmarking on it would re-create the very bug this
    # stream fixes: a label applied today to an old message sorts below the
    # bookmark and would be skipped forever.
    replication_key = None
    replication_method = "FULL_TABLE"
    schema = th.PropertiesList(
        th.Property("message_id", th.StringType),
        th.Property("label_uuid", th.StringType),
        th.Property("label_value", th.StringType),
        th.Property("label_color", th.StringType),
        th.Property("confidence", th.NumberType),
        th.Property("deleted", th.BooleanType),
        th.Property("message_timestamp", th.DateTimeType),
        th.Property("metadata", th.ObjectType(additional_properties=True)),
    ).to_dict()

    # =============================================================================
    # HTTP helper
    # =============================================================================
    def _get_json(self, url: str, context: dict, label: str) -> dict | None:
        """GET a URL and return the decoded body, or None when unusable."""
        request = Request(method="GET", url=url, headers=self.http_headers)
        prepared_request = self.http_client.prepare_request(request)
        self._log_prepared_request(prepared_request, label)
        response = self._request(prepared_request, context)
        self._log_http_response(response, note=label)

        status_code = getattr(response, "status_code", 0)
        if status_code == 403:
            self._error("Access forbidden (403) on %s for %s. Check credentials and permissions.", url, self.kind)
            raise TapStreamConnectionFailure("403 Forbidden")
        if status_code >= 400:
            self._error("HTTP %s on %s for %s", status_code, url, self.kind)
            return None

        try:
            payload = response.json()
        except JSONDecodeError as e:
            self._error("Invalid JSON on %s for %s: %s", url, self.kind, e)
            return None
        if not isinstance(payload, dict):
            self._error("Expected an object on %s for %s, got %s", url, self.kind, type(payload).__name__)
            return None
        return payload

    def _absolute(self, url: str) -> str:
        """Resolve a possibly relative 'next' pointer against the base URL."""
        return url if url.startswith("http") else f"{self.url_base}/{url.lstrip('/')}"

    # =============================================================================
    # Label listing
    # =============================================================================
    def _iter_labels(self, context: dict) -> Iterable[dict]:
        """Yield every label currently linked to the number."""
        payload = self._get_json(f"{self.url_base}/v1/labels", context, "labels list")
        if payload is None:
            raise TapStreamConnectionFailure("Could not list labels")

        labels = payload.get("labels")
        if not isinstance(labels, list):
            raise TapStreamConnectionFailure(f"Expected 'labels' to be a list, got {type(labels).__name__}")

        for label in labels:
            if not isinstance(label, dict):
                self._warning("Skipping non-dict label in %s: %s", self.kind, type(label).__name__)
                continue
            if not label.get("uuid"):
                self._warning("Skipping label without uuid in %s: %s", self.kind, self._pretty(label))
                continue
            yield label

    # =============================================================================
    # Labelled messages per label
    # =============================================================================
    def _iter_label_messages(self, label: dict, context: dict) -> Iterable[dict]:
        """Yield every message linked to one label, following 'next'."""
        label_uuid = str(label["uuid"])
        max_pages = int(self.config.get("labels_max_pages_per_label", 0) or 0)

        url: str | None = f"{self.url_base}/v1/labels/{quote_plus(label_uuid)}/messages"
        visited: set[str] = set()
        seen_message_ids: set[str] = set()
        page_num = 0

        while url:
            if url in visited:
                # Turn pointing back at a page it already served would page
                # forever; stopping here is safe because every link on that
                # page has already been emitted.
                self._warning("Repeated page URL for label %s in %s; stopping to avoid a loop", label_uuid, self.kind)
                break
            visited.add(url)

            payload = self._get_json(url, context, f"label {label_uuid} page{page_num + 1}")
            if payload is None:
                raise TapStreamConnectionFailure(f"Could not read page {page_num + 1} of label {label_uuid}")

            items = payload.get("message_labels")
            if not isinstance(items, list):
                raise TapStreamConnectionFailure(
                    f"Expected 'message_labels' to be a list for label {label_uuid}, got {type(items).__name__}"
                )

            emitted = 0
            for item in items:
                record = self._build_record(item, label)
                if record is None:
                    continue
                # Turn may repeat a link across pages while labels are being
                # applied. Duplicates inside one batch break the target's
                # upsert, so drop them here.
                if record["message_id"] in seen_message_ids:
                    self._debug("Duplicate link %s/%s in %s; skipping", record["message_id"], label_uuid, self.kind)
                    continue
                seen_message_ids.add(record["message_id"])
                emitted += 1
                yield record

            page_num += 1
            self._info("Fetched label %s page %d with %d links for %s", label_uuid, page_num, emitted, self.kind)

            if max_pages > 0 and page_num >= max_pages:
                self._warning("Reached labels_max_pages_per_label (%s) for label %s", max_pages, label_uuid)
                break

            next_pointer = payload.get("next")
            if not payload.get("has_more") or not isinstance(next_pointer, str) or not next_pointer.strip():
                break
            url = self._absolute(next_pointer.strip())

    # =============================================================================
    # Record construction
    # =============================================================================
    def _build_record(self, item: Any, label: dict) -> dict | None:
        """Turn one message_labels entry into a schema-safe row."""
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except JSONDecodeError:
                self._error("Failed to parse string entry as JSON in %s: %s", self.kind, item)
                return None
        if not isinstance(item, dict):
            self._error("Invalid entry in %s: expected dict, got %s", self.kind, type(item).__name__)
            return None

        message = item.get("message")
        if not isinstance(message, dict):
            self._error("Entry without a message object in %s: %s", self.kind, self._pretty(item))
            return None

        message_id = message.get("id")
        if not message_id:
            self._error("Entry without a message id in %s: %s", self.kind, self._pretty(message))
            return None

        confidence = item.get("confidence")
        if confidence is not None:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                self._warning("Invalid confidence %r in %s; storing null", confidence, self.kind)
                confidence = None

        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        return {
            "message_id": str(message_id),
            "label_uuid": str(label["uuid"]),
            "label_value": label.get("value"),
            "label_color": label.get("color"),
            "confidence": confidence,
            "deleted": bool(item.get("deleted", False)),
            # Best effort. A link is still valid when the timestamp is not.
            "message_timestamp": coerce_timestamp(message.get("timestamp")),
            "metadata": metadata,
        }

    # =============================================================================
    # Public record request entrypoint
    # =============================================================================
    def request_records(self, context: dict | None) -> Iterable[dict]:
        """Yield one record per message-label link across every label."""
        context = context or {}
        total = 0
        label_count = 0

        for label in self._iter_labels(context):
            label_count += 1
            per_label = 0
            for record in self._iter_label_messages(label, context):
                per_label += 1
                total += 1
                yield record
            self._info("Label %r yielded %d links for %s", label.get("value"), per_label, self.kind)

        self._info("Fetched %d links across %d labels for %s", total, label_count, self.kind)
