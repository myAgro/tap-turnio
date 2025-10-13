# 🧾 Changelog
All notable changes to this project will be documented in this file.  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]
> Placeholder for upcoming changes.  
> Use this section during development before tagging the next release.

### Added
- 

### Changed
- 

### Fixed
- 403 Forbidden handling:
  - Added graceful error raising (TapStreamConnectionFailure) to stop execution cleanly when authentication fails.
  - Prevented unnecessary pagination or further stream processing after failed auth.
- Deprecation warning:
  - Removed deprecated stream argument from TurnAuthenticator initializer (auth.py), aligning with latest Singer SDK standards.
- Logging levels:
  - Restored correct log severity output ([ERROR], [WARNING], [INFO]) across SDK integrations.
  - Introduced optional ANSI color formatting for human-friendly local debugging (FORCE_COLOR=1).

### Deprecated
- 

### Removed
- 

---

## [0.1.0] - 2025-10-07
### 🎉 Initial Release — *Outreach Edition*
This version marks the first tagged release of **tap-turnio**, an open-source [Singer](https://www.singer.io/) extractor for the [Turn.io API](https://www.turn.io/).

#### ✨ Added
- **Core extractor** built on the [Singer SDK](https://sdk.meltano.com/).
- Implemented the following **streams**:
  - `messages`
  - `statuses`
- Basic **rate limiting**, **retry**, and **backoff** handling.
- Configuration options for:
  - API token authentication.
  - Start date for incremental sync.
  - Stream selection and state persistence.
- **Incremental sync** and **state bookmarking**.
- CLI options for:
  - `--discover` (schema discovery)
  - `--catalog` (select specific streams)
- **Dockerfile** and **Meltano integration** support.
- **Basic unit tests** and developer scaffolding.

#### 🔖 Tag
- **Version:** `v0.1.0`
- **Codename:** *Outreach*
- **Purpose:** Establish baseline functionality for Turn.io extraction and Meltano integration.

---

## [0.2.0] - YYYY-MM-DD *(Upcoming)*
> Sample template for the next release.

### Added
- _e.g. support for the “broadcasts” stream._
- _e.g. pagination support for contacts API._

### Changed
- _e.g. refactored rate limiter for cleaner logic._
- _e.g. updated Singer SDK dependency._

### Fixed
- _e.g. resolved missing field errors on message payloads._
- _e.g. fixed 429 retry logic._

### Deprecated
- _e.g. deprecated legacy config key `auth_token` in favor of `api_key`._

### Removed
- _e.g. removed unused schema files._

---

## [0.3.0] - YYYY-MM-DD *(Planned)*
> Future milestone placeholder.

### Added
- _e.g. support for media downloads and attachments._

### Changed
- _e.g. switched HTTP client from `requests` to `httpx`._

### Fixed
- _e.g. fixed incremental cursor reset issue._

---

## 📜 Versioning Policy
- **Major (`X`)** → Breaking changes in config or API behavior.  
- **Minor (`Y`)** → New features or streams added (non-breaking).  
- **Patch (`Z`)** → Bug fixes, docs, or internal improvements.

---

## 🧰 Maintenance Notes
- To generate changelogs automatically, use [Conventional Commits](https://www.conventionalcommits.org/):
  ```
  feat: add incremental sync for statuses
  fix: handle 429 rate limit retry
  chore: update dependencies
  docs: improve README with examples
  ```
- Automate changelog generation using:
  ```bash
  npx conventional-changelog -p conventionalcommits -i CHANGELOG.md -s
  ```

---
