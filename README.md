# IP Proxy Checker

A local web application for checking and analyzing IP addresses with the
[IPQualityScore](https://www.ipqualityscore.com/) service. It detects proxies,
VPNs, TOR exit nodes, bots, recent abuse and a fraud score, then lets you filter
and export the results.

> Built to run **locally, single-user**. It is not hardened for public exposure
> (no auth, dev server, listens on `127.0.0.1`).

## Features

- Single IP, multiple IPs (max 20 pasted), or `.txt` upload (max 500 IPs)
- Accepts proxy lines in any common format and **preserves the original format
  on export**: `ip`, `ip:port`, `ip:port:user:pass`, `ip,user,pass`,
  `ip user pass`, and bracketed IPv6 `[2001:db8::1]:8080`
- **Asynchronous scanning with real progress** (live count, resumes after a
  page refresh)
- **Post-scan summary** dashboard (total, clean, proxy/VPN, TOR, avg fraud, top
  countries)
- **Scan history** — every scan is saved; reload or delete past batches
- **Cache control** — TTL cache (re-scans are instant & free), a "re-verify
  (ignore cache)" toggle, a clear-cache button, and live API-call / cache counters
- **Results persist** across refresh and app restart (SQLite)
- Automatic IP validation (IPv4 + IPv6) and de-duplication by IP
- **Select rows by hand (checkboxes) or filter by criteria**, then export only
  what you picked
- **Drag & drop** a `.txt` file to import
- Export the matching proxy lines as `.txt` (original format kept), or the full
  analysis as **CSV or JSON**; copy the proxy list to the clipboard
- All rendered values are HTML-escaped (no XSS from IP/ISP/org fields)

## Requirements

- Python 3.x
- Flask, pandas, requests, python-dotenv (see `requirements.txt`)
- SQLite, `ipaddress`, `csv`, `html` are used from the Python standard library
  (no extra install)

## Installation

```bash
# 1. Get the code, then create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure the API key
copy .env.example .env   # Windows  (cp on macOS/Linux)
# then edit .env and set your real key:
#   API_KEY=your_real_key_here
```

Get a free API key from [IPQualityScore](https://www.ipqualityscore.com/)
(free tier: 1,000 checks/month, ~2 requests/second). Until a real key is set the
UI loads but shows a warning banner and every lookup returns an error.

## Configuration (`.env`)

| Variable          | Default            | Description                                             |
| ----------------- | ------------------ | ------------------------------------------------------- |
| `API_KEY`         | `YOUR_API_KEY`     | IPQualityScore API key (required for real checks)       |
| `CACHE_TTL_HOURS` | `24`               | How long a cached IP lookup stays fresh                 |
| `FLASK_DEBUG`     | `0`                | Set to `1` to enable the Flask debugger (local only)    |

## Usage

```bash
python app.py
```

Then open `http://localhost:5050`.

1. Drag & drop a `.txt`, browse for it, paste a list (max 20), or type a single
   IP. Lines may be `ip`, `ip:port`, `ip:port:user:pass`, `ip,user,pass`, etc. —
   the whole line is kept for export. Tick **Re-verifică** to ignore the cache.
2. Click **Scanează**. Progress is live; the summary cards and results table
   appear, and the scan is saved to **Istoric** + restored after a refresh.
3. Narrow the table with the sidebar filters (they apply automatically) or the
   **✨ Doar curate** preset, and/or tick individual rows.
4. Export with the sidebar: **Descarcă** (`.txt` proxy list in the original
   format, `.csv`, or `.json` analysis) or **Copiază** to the clipboard. With no
   row ticked, the export uses everything currently shown.
5. **Istoric** reloads/deletes past scans; **Sistem** clears the cache or resets
   the current data.

## How it works

- `app.py` — Flask routes. Scanning is async: `POST /scan` starts a background
  job, the browser polls `GET /progress/<job_id>` for real progress, the
  rendered table and a summary. `/filter`, `/export`, `/copy-clean`, `/history*`,
  `/stats`, `/cache/clear` and `/reset` operate on the stored results.
- `ip_checker.py` — input parsing/validation, the rate-limited threaded scan
  (with caching + de-dup), filtering, summary, escaped HTML table building, and
  CSV/JSON/clipboard export.
- `storage.py` — SQLite (WAL): `ip_cache` (TTL memoization), `app_state` (last
  scan + API-call counter, restored on startup) and `scans` (history, last 50).

### Endpoints

| Method | Path                  | Purpose                                       |
| ------ | --------------------- | --------------------------------------------- |
| GET    | `/`                   | UI; restores the last scan if present         |
| POST   | `/scan`               | Start a scan (JSON `{ips, source, bypass_cache}`) |
| GET    | `/progress/<id>`      | Job progress + finished table + summary       |
| GET    | `/filter`             | Filtered results `{table, summary}` (JSON)    |
| POST   | `/export`             | Export `{ips, format}` (clean/full/json)      |
| POST   | `/copy-clean`         | Clean proxy lines for `{ips}` (JSON)          |
| GET    | `/history`            | List saved scans                              |
| POST   | `/history/load/<id>`  | Load a saved scan as the current set          |
| POST   | `/history/delete/<id>`| Delete a saved scan                           |
| POST   | `/history/clear`      | Clear all history                             |
| GET    | `/stats`              | API-call + cache counters                     |
| POST   | `/cache/clear`        | Empty the IP lookup cache                     |
| POST   | `/reset`              | Clear current + persisted results             |

## Data & limits

- Runtime data lives in `data/ipchecker.db` (git-ignored). Delete it to wipe the
  cache and saved results.
- Caps: 20 pasted IPs, 500 IPs per file, 1 MB upload, 2 MB request body.
- Caching respects the IPQualityScore rate limit (~2 req/s) via a small thread
  pool + shared rate limiter.

## Output schema

Each result row exposes: IP, Country, City, ISP, Organization, Proxy/VPN, VPN,
TOR, Bot Status, Fraud Score, Recent Abuse, Crawler. The fraud score is colored:
≤10 excellent, 11–30 acceptable, 31–50 suspect, >50 risky.

## Not included (by design, for local use)

Auth, CSRF, a production WSGI server, multi-user isolation and rate limiting are
intentionally omitted. Add them before exposing this on a network.

## License

[MIT](LICENSE).

## Author

Built and maintained by [N.Stefan](https://graffro.dev).

## Acknowledgments

- [IPQualityScore](https://www.ipqualityscore.com/) for the IP verification API
- Flask, pandas and the DataTables project
