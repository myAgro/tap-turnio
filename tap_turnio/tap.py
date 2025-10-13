# tap_turnio/tap.py
# -----------------------------------------------------------------------------
# Entry point / Tap definition for tap-turnio.
#
# Responsibilities:
#   - Define the tap's configuration schema (validated by Singer SDK).
#   - Instantiate and return the list of streams (Messages, Statuses).
#   - Provide a CLI entrypoint.
#
# Env vars:
#   The Singer SDK will read config from environment variables using the tap's
#   prefix. For Meltano or direct CLI, typical variables are:
#     TAP_TURNIO_USERNAME
#     TAP_TURNIO_PASSWORD
#     TAP_TURNIO_BASE_URL
#     TAP_TURNIO_START_DATE
#     TAP_TURNIO_PAGE_SIZE
#     TAP_TURNIO_MAX_PAGES
#     TAP_TURNIO_LOOKBACK_SEC
#     TAP_TURNIO_MESSAGES_CURSOR_JSON
#     TAP_TURNIO_STATUSES_CURSOR_JSON
#
# Notes:
#   - This file keeps only tap-level concerns; stream logic lives in streams.py.
#   - Config defaults keep the tap safe/sane out of the box.
# -----------------------------------------------------------------------------

from __future__ import annotations

from singer_sdk import Tap
from singer_sdk.exceptions import TapStreamConnectionFailure
from singer_sdk.plugin_base import PluginBase  # noqa: F401  # (kept for IDE refs / parity)

from tap_turnio.streams import MessagesStream, StatusesStream

############################################################
# TapTurnio
############################################################

# =============================================================================
# Base Class: Tap
# Centralizes:
#  - Config schema declaration
#  - Stream discovery
# =============================================================================
class TapTurnio(Tap):
    """Singer Tap for Turn.io.

    Declares the configuration schema and returns the tap's streams.
    """

    name = "tap-turnio"

    # =============================================================================
    # Configuration schema
    # =============================================================================
    # Keep these aligned with what the deployment expects (Meltano, env, etc.)
    config_jsonschema = {
        "type": "object",
        "properties": {
            # --- Auth & endpoint ---------------------------------------------------
            "username": {"type": "string"},
            "password": {"type": "string"},
            "base_url": {
                "type": "string",
                "default": "https://whatsapp.turn.io",
                "description": "Base URL for the Turn.io API",
            },

            # --- Replication window -----------------------------------------------
            # start_date is the earliest possible starting point if no bookmark exists.
            "start_date": {"type": "string", "format": "date-time"},

            # --- Pagination / batching --------------------------------------------
            "page_size": {
                "type": "integer",
                "default": 100,
                "description": "Page size requested when creating cursors",
            },
            "max_pages": {
                "type": "integer",
                "default": 0,
                "description": "Hard cap on pages per run (0 = no cap)",
            },

            # --- Safety overlap ----------------------------------------------------
            "lookback_sec": {
                "type": "integer",
                "default": 0,
                "description": "Seconds to subtract from bookmark to include overlap",
            },

            # --- Stream-specific cursor hints -------------------------------------
            # These allow passing extra POST params for cursor creation.
            "messages_cursor_json": {"type": "object", "default": {}},
            "statuses_cursor_json": {"type": "object", "default": {}},
        },
        "required": ["username", "password"],
        "additionalProperties": False,
    }

    # =============================================================================
    # Stream discovery
    # =============================================================================
    def discover_streams(self) -> list[MessagesStream | StatusesStream]:
        """Return all stream instances managed by this tap.

        Add/remove stream classes here to change which endpoints the tap exposes.
        """
        return [
            MessagesStream(self),
            StatusesStream(self),
        ]


# =============================================================================
# CLI Entrypoint
# =============================================================================
def cli() -> None:
    """Run the tap via Click-based CLI provided by Singer SDK."""
    try:
        TapTurnio.cli()
    except TapStreamConnectionFailure as exc:
        raise SystemExit(f"Tap failed: {exc}") from exc
