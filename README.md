# tap-turnio

**`tap-turnio`** is a [Singer](https://www.singer.io/) tap built with the [Singer SDK](https://sdk.meltano.com/) for extracting WhatsApp message and status data from the **Turn.io** API.

It provides structured, incremental replication of message and status records for analytics pipelines and data warehouses.

----

## 🧩 Capabilities

* ✅ **Incremental replication** using timestamp bookmarks
* ✅ **Two streams**: `messages` and `statuses`
* ✅ **Configurable pagination and overlap (`lookback_sec`)**
* ✅ **HTTP Basic authentication**
* ✅ **HTTP Token authentication** (via API token)
* ✅ **Rate limiting** with Turn.io headers (`X-Ratelimit-*`, `Retry-After`)
* ✅ **JSON flattening** and safe post-processing
* ✅ **Singer-compatible output** (SCHEMA + RECORD + STATE messages)

---

## ⚙️ Installation

You can install directly from source or with `pip`:

```bash
pip install -e .
```

If developing within [Meltano](https://meltano.com):

```bash
meltano add extractor tap-turnio
```

---

## 🧠 Configuration

The tap reads credentials and parameters from environment variables prefixed with `TAP_TURNIO_`.

| Setting                | Type              | Required | Default                    | Description                                 |
| ---------------------- | ----------------- | -------- | -------------------------- | ------------------------------------------- |
| `username`             | string            | ✅        | —                          | Turn.io account username (required)         |
| `password`             | string            | ✅        | —                          | Turn.io account password (optional)         |
| `token`                | string            | ✅        | —                          | Turn.io account token (if not basic auth)   |
| `base_url`             | string            | ❌        | `https://whatsapp.turn.io` | Base URL for the Turn.io API                |
| `start_date`           | string (ISO 8601) | ❌        | —                          | Earliest replication start date             |
| `page_size`            | integer           | ❌        | 100                        | API page size                               |
| `max_pages`            | integer           | ❌        | 0                          | Hard cap on pages per run (0 = unlimited)   |
| `lookback_sec`         | integer           | ❌        | 0                          | Overlap (in seconds) from previous bookmark |
| `messages_cursor_json` | object            | ❌        | `{}`                       | Optional POST cursor params for messages    |
| `statuses_cursor_json` | object            | ❌        | `{}`                       | Optional POST cursor params for statuses    |

### Example basic auth configuration file (`config.json`)

```json
{
  "username": "your-turnio-username",
  "password": "your-turnio-password",
  "base_url": "https://whatsapp.turn.io",
  "start_date": "2024-01-01T00:00:00Z",
  "page_size": 100,
  "lookback_sec": 120
}
```

or via environment variables:

```bash
export TAP_TURNIO_USERNAME="your-turnio-username"
export TAP_TURNIO_PASSWORD="your-turnio-password"
```

### Example token auth configuration file (`config.json`)

```json
{
  "username": "your-turnio-username",
  "token": "my-token-abc-123",
  "base_url": "https://whatsapp.turn.io",
  "start_date": "2024-01-01T00:00:00Z",
  "page_size": 100,
  "lookback_sec": 120
}
```

or via environment variables:

```bash
export TAP_TURNIO_USERNAME="your-turnio-username"
export TAP_TURNIO_TOKEN="my-token-abc-123"
```

---

## 🔄 Streams

### `messages`

Extracts message data sent and received via Turn.io.

| Property       | Type     | Description           |
| -------------- | -------- | --------------------- |
| `id`           | string   | Message ID            |
| `contact_id`   | string   | WhatsApp contact ID   |
| `direction`    | string   | Inbound or outbound   |
| `timestamp`    | datetime | Message timestamp     |
| `payload_json` | object   | Full raw message JSON |

### `statuses`

Extracts message status updates (delivered, read, failed, etc.).

| Property       | Type     | Description            |
| -------------- | -------- | ---------------------- |
| `id`           | string   | Status ID              |
| `message_id`   | string   | Associated message ID  |
| `status`       | string   | Status type            |
| `timestamp`    | datetime | Timestamp of status    |
| `recipient_id` | string   | Recipient phone number |
| `payload_json` | object   | Full raw status JSON   |

---

## 🧪 Example Usage

### Singer CLI

Run discovery:

```bash
tap-turnio --discover
```

Run sync:

```bash
tap-turnio --config config.json --catalog catalog.json
```

### Meltano

In your `meltano.yml`:

```yaml
plugins:
  extractors:
    - name: tap-turnio
      namespace: tap_turnio
      pip_url: -e .
      config:
        username: ${TAP_TURNIO_USERNAME}
        password: ${TAP_TURNIO_PASSWORD}
        base_url: https://whatsapp.turn.io

  loaders:
    - name: target-postgres
      namespace: target_postgres
      pip_url: target-postgres
      config:
        host: localhost
        port: 5432
        user: your_db_user
        password: your_db_password
        dbname: your_db_name

```

or

```yaml
plugins:
  extractors:
    - name: tap-turnio
      namespace: tap_turnio
      pip_url: -e .
      config:
        username: ${TAP_TURNIO_USERNAME}
        token: ${TAP_TURNIO_TOKEN}
        base_url: https://whatsapp.turn.io

  loaders:
    - name: target-postgres
      namespace: target_postgres
      pip_url: target-postgres
      config:
        host: localhost
        port: 5432
        user: your_db_user
        password: your_db_password
        dbname: your_db_name

```

Then:

```bash
meltano run tap-turnio target-postgres
```

---

## 🧰 Development

### Local Environment

```bash
# Clone and create virtual environment
git clone https://github.com/myAgro/tap-turnio.git
cd tap-turnio
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
tap-turnio --help
tap-turnio --discover
tap-turnio
```

Run tests and linting:

```bash
pytest
ruff check .
```

---

## 🚦 Rate Limiting

This tap includes a **header-aware rate limiter** (`HeaderAwareLimiter`) that inspects Turn.io’s headers:

* `Retry-After`
* `X-Ratelimit-Bucket`, `X-Ratelimit-Limit`, `X-Ratelimit-Remaining`, `X-Ratelimit-Reset`
* `X-throttling`

If rate limits are reached, requests are automatically paused and retried with exponential backoff.

---

## 🔐 Authentication

The tap uses static **HTTP Basic Auth**, encoded as:

```
Authorization: Basic base64(username:password)
```

or supports **Token Auth** via:

```
token: <your-token-value>
```

implemented via the `TurnAuthenticator` class in [`auth.py`](./tap_turnio/auth.py).

---

## 🪣 Code Overview

| Module                  | Purpose                                 |
| ----------------------- | --------------------------------------- |
| `tap_turnio/tap.py`     | Tap entrypoint and configuration schema |
| `tap_turnio/streams.py` | Stream logic, parsing, post-processing  |
| `tap_turnio/client.py`  | Rate limiter and retry decorator        |
| `tap_turnio/auth.py`    | Basic authentication handler            |

---

## 🧾 Example Output (Singer messages)

```json
{"type": "SCHEMA", "stream": "messages", "schema": { ... }}
{"type": "RECORD", "stream": "messages", "record": {"id": "abc123", "timestamp": "2024-06-01T12:00:00Z", "contact_id": "250700123456"}}
{"type": "STATE", "value": {"messages": {"replication_key": "2024-06-01T12:00:00Z"}}}
```

---

## 🧩 Contributing

Pull requests are welcome!
Please ensure:

* Code passes `pytest`
* Follows `black` + `ruff` formatting
* Includes docstrings for any new functionality

---

## 🏷️ Releases

Use semantic versioning (`v1.0.0`, `v1.1.0`, …):

```bash
git tag v1.0.0
git push origin v1.0.0
gh release create v1.0.0 --notes "Initial stable release"
```

---

## 🧑‍💻 Maintainers

Built with ❤️ using the [Singer SDK](https://sdk.meltano.com/)
Maintained by the **Data Engineering Team**.
