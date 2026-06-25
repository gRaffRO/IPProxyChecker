"""Core IP verification logic for the IPQualityScore-backed checker.

Design notes:
- Internal record keys are plain ASCII (``ip``, ``fraud_score`` ...) so the
  filtering/CSV logic never depends on Romanian labels with diacritics. The
  human-facing labels live in ``FIELD_LABELS`` and are only used when building
  the HTML table.
- All values rendered into HTML are escaped (the only intentional markup is the
  country flag image, built from a validated 2-letter code).
- Scanning runs on a small thread pool with a shared rate limiter so we respect
  the IPQualityScore free-tier limit (~2 requests/second) while still being far
  faster than the old sequential loop.
"""

import csv
import html
import io
import ipaddress
import json
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests

# Ordered (internal_key, display_label) pairs. Order defines column order.
FIELDS = [
    ("ip", "IP"),
    ("country", "Țară"),
    ("city", "Oraș"),
    ("isp", "ISP"),
    ("organization", "Organizație"),
    ("proxy", "Proxy/VPN"),
    ("vpn", "VPN"),
    ("tor", "TOR"),
    ("bot_status", "Bot Status"),
    ("fraud_score", "Scor Fraudă"),
    ("recent_abuse", "Abuz Recent"),
    ("crawler", "Crawler"),
]
FIELD_LABELS = dict(FIELDS)

# Visual grouping for the table header (label -> internal keys).
SECTIONS = [
    ("Informații de bază", ["ip", "country", "city", "isp", "organization"]),
    ("Securitate", ["proxy", "vpn", "tor", "bot_status"]),
    ("Risc", ["fraud_score", "recent_abuse", "crawler"]),
]

BOOL_FIELDS = {"proxy", "vpn", "tor", "bot_status", "recent_abuse", "crawler"}

PLACEHOLDER_KEYS = {"", "your_api_key", "your_api_key_here"}


class RateLimiter:
    """Allow at most ``rate_per_sec`` actions per second across threads."""

    def __init__(self, rate_per_sec):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0
        self._lock = threading.Lock()
        self._next_time = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                time.sleep(self._next_time - now)
                now = time.monotonic()
            self._next_time = now + self.min_interval


class IPChecker:
    MAX_WORKERS = 2  # keep within the ~2 req/s free-tier rate limit

    def __init__(self, api_key, cache_get=None, cache_put=None, cache_ttl_seconds=None):
        self.api_key = (api_key or "").strip()
        self.latest_records = []   # list of internal dicts
        self.latest_raw = []       # original input lines (with port/credentials)
        self._rate_limiter = RateLimiter(self.MAX_WORKERS)
        # Optional persistence hooks (wired to storage.py by the app).
        self._cache_get = cache_get
        self._cache_put = cache_put
        self._cache_ttl = cache_ttl_seconds
        # Count of real API lookups performed (since process start).
        self.api_calls = 0
        self._api_lock = threading.Lock()

    @property
    def is_configured(self):
        """True when a real API key (not the placeholder) is set."""
        return self.api_key.lower() not in PLACEHOLDER_KEYS

    # ----- input parsing -------------------------------------------------
    @staticmethod
    def extract_ip(line):
        """Return a valid IP string from a raw line, or ``None``.

        Handles the common proxy-list shapes regardless of delimiter:
          ``ip``, ``ip:port``, ``ip:port:user:pass``,
          ``ip,user,pass``, ``ip,port,user,pass``, ``ip user pass``,
          and bracketed IPv6 ``[2001:db8::1]:8080``.
        Validates both IPv4 and IPv6.
        """
        if not line:
            return None
        token = line.strip()
        if not token:
            return None

        # Bracketed IPv6 with optional port: [2001:db8::1]:8080
        if token.startswith("["):
            inner = token[1:].split("]")[0]
            try:
                return str(ipaddress.ip_address(inner))
            except ValueError:
                return None

        # Whole token is already a valid IP (bare IPv4 or bare IPv6).
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            pass

        # Proxy formats: first field is the IP. Split on comma / whitespace,
        # then strip a trailing ``:port`` (and any ``:user:pass``) from IPv4.
        first = re.split(r"[,\s]", token, maxsplit=1)[0]
        if ":" in first:
            first = first.split(":")[0]
        try:
            return str(ipaddress.ip_address(first))
        except ValueError:
            return None

    # ----- single lookup -------------------------------------------------
    def check_ip(self, ip):
        url = f"https://ipqualityscore.com/api/json/ip/{self.api_key}/{ip}"
        try:
            self._rate_limiter.wait()
            with self._api_lock:
                self.api_calls += 1
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=2)
            session.mount("https://", adapter)
            response = session.get(url, timeout=30)

            if response.status_code != 200:
                return self._error_response(ip, f"Eroare API: {response.status_code}")

            data = response.json()
            if "success" in data and not data["success"]:
                return self._error_response(
                    ip, f"Eroare API: {data.get('message', 'Necunoscută')}"
                )

            return {
                "ip": ip,
                "country": data.get("country_code", "") or "",
                "city": data.get("city", "") or "",
                "isp": data.get("ISP", "") or "",
                "organization": data.get("organization", "") or "",
                "proxy": bool(data.get("proxy", False)),
                "vpn": bool(data.get("vpn", False)),
                "tor": bool(data.get("tor", False)),
                "bot_status": bool(data.get("bot_status", False)),
                "fraud_score": int(data.get("fraud_score", 0) or 0),
                "recent_abuse": bool(data.get("recent_abuse", False)),
                "crawler": bool(data.get("crawler", False)),
                "error": None,
            }
        except requests.exceptions.Timeout:
            return self._error_response(ip, "Timeout - API nu a răspuns la timp")
        except requests.exceptions.RequestException as exc:
            return self._error_response(ip, f"Eroare conexiune: {exc}")
        except ValueError:
            return self._error_response(ip, "Răspuns invalid de la API (nu este JSON)")
        except Exception as exc:  # pragma: no cover - defensive
            return self._error_response(ip, f"Eroare neașteptată: {exc}")

    def _error_response(self, ip, error_message):
        return {
            "ip": ip,
            "country": "",
            "city": "",
            "isp": error_message,
            "organization": "",
            "proxy": False,
            "vpn": False,
            "tor": False,
            "bot_status": False,
            "fraud_score": 0,
            "recent_abuse": False,
            "crawler": False,
            "error": error_message,
        }

    # ----- batch scan ----------------------------------------------------
    def scan(self, lines, progress_cb=None, bypass_cache=False):
        """Scan a list of raw input lines.

        Deduplicates IPs, serves fresh results from the cache (unless
        ``bypass_cache``), and only hits the API for the remaining unique IPs
        (on a rate-limited thread pool). ``progress_cb(completed, total)``
        reports progress over the unique IPs. Returns the result list in input
        order and stores it as the latest results for filtering/export.
        """
        raw_lines = [ln.strip() for ln in lines if ln and ln.strip()]
        parsed = [(raw, self.extract_ip(raw)) for raw in raw_lines]

        # Unique, valid IPs to resolve (preserve first-seen order).
        unique_ips = []
        seen = set()
        for _, ip in parsed:
            if ip and ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)

        results_by_ip = {}
        to_fetch = []
        for ip in unique_ips:
            cached = None
            if not bypass_cache and self._cache_get is not None:
                try:
                    cached = self._cache_get(ip, self._cache_ttl)
                except Exception:
                    cached = None
            if cached is not None:
                results_by_ip[ip] = cached
            else:
                to_fetch.append(ip)

        total = len(unique_ips)
        completed = {"n": len(unique_ips) - len(to_fetch)}
        lock = threading.Lock()
        if progress_cb:
            progress_cb(completed["n"], total)

        def work(ip):
            res = self.check_ip(ip)
            if self._cache_put is not None and not res.get("error"):
                try:
                    self._cache_put(ip, res)
                except Exception:
                    pass
            with lock:
                results_by_ip[ip] = res
                completed["n"] += 1
                if progress_cb:
                    progress_cb(completed["n"], total)

        if to_fetch:
            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
                for ip in to_fetch:
                    pool.submit(work, ip)

        # Rebuild results, one row per unique IP (and one per unique invalid
        # line). The full original lines are kept in ``latest_raw`` so export
        # can return every proxy line that maps to a selected IP.
        results = []
        emitted = set()
        for raw, ip in parsed:
            if ip:
                if ip in emitted:
                    continue
                emitted.add(ip)
                results.append(results_by_ip.get(ip) or self._error_response(raw, "Rezultat indisponibil"))
            else:
                key = "__invalid__" + raw
                if key in emitted:
                    continue
                emitted.add(key)
                results.append(self._error_response(raw, "Format IP invalid"))

        self.latest_records = results
        self.latest_raw = raw_lines
        return self.latest_records

    # ----- filtering -----------------------------------------------------
    def filter_records(self, records, f):
        def keep(r):
            if f["proxy"] and r["proxy"] != f["proxy_value"]:
                return False
            if f["vpn"] and r["vpn"] != f["vpn_value"]:
                return False
            if f["tor"] and r["tor"] != f["tor_value"]:
                return False
            if f["bot"] and r["bot_status"] != f["bot_value"]:
                return False
            if f["fraud_score"] and not (r["fraud_score"] <= f["fraud_score_value"]):
                return False
            if f["abuse"] and r["recent_abuse"] != f["abuse_value"]:
                return False
            if f["crawler"] and r["crawler"] != f["crawler_value"]:
                return False
            return True

        return [r for r in records if keep(r)]

    # ----- rendering -----------------------------------------------------
    def build_table_html(self, records):
        if not records:
            return ""

        def flag(country):
            code = (country or "").strip()
            if len(code) == 2 and code.isalpha():
                low = code.lower()
                return (
                    f"<img src='https://flagcdn.com/16x12/{low}.png' "
                    f"alt='{html.escape(code)}' style='margin-right:4px;'> "
                    f"{html.escape(code.upper())}"
                )
            return html.escape(code) or "-"

        def cell(key, value, record):
            css = ""
            if key == "fraud_score":
                score = value if isinstance(value, (int, float)) else 0
                if score <= 10:
                    css = "score-green"
                elif score <= 30:
                    css = "score-yellow"
                elif score <= 50:
                    css = "score-orange"
                else:
                    css = "score-red"
            elif key in BOOL_FIELDS and value is True:
                css = "vpn-tor"

            if key == "country":
                display = flag(value)
            elif isinstance(value, bool):
                display = "Da" if value else "Nu"
            elif value in (None, ""):
                display = "-"
            else:
                display = html.escape(str(value))

            # Mark IPs that were served from the cache (no fresh API call).
            if key == "ip" and record.get("cached"):
                display += " <span class='cache-badge' title='Din cache'>⚡</span>"

            cls = f' class="{css}"' if css else ""
            return f"<td{cls}>{display}</td>"

        html_parts = ['<table class="data" id="results-table">', "<thead>"]

        # Grouped section header row (+ a leading selection column).
        html_parts.append('<tr class="section-header">')
        html_parts.append('<th rowspan="2" class="select-col"><input type="checkbox" id="select-all" title="Selectează tot"></th>')
        for section, keys in SECTIONS:
            html_parts.append(f'<th colspan="{len(keys)}">{html.escape(section)}</th>')
        html_parts.append("</tr>")

        # Column header row.
        html_parts.append("<tr>")
        for _, keys in SECTIONS:
            for key in keys:
                html_parts.append(f"<th>{html.escape(FIELD_LABELS[key])}</th>")
        html_parts.append("</tr></thead><tbody>")

        for record in records:
            row_cls = ' class="row-error"' if record.get("error") else ""
            html_parts.append(f"<tr{row_cls}>")
            ip_attr = html.escape(str(record.get("ip", "")), quote=True)
            html_parts.append(
                f'<td class="select-col"><input type="checkbox" class="row-select" data-ip="{ip_attr}"></td>'
            )
            for _, keys in SECTIONS:
                for key in keys:
                    html_parts.append(cell(key, record.get(key), record))
            html_parts.append("</tr>")

        html_parts.append("</tbody></table>")
        return "".join(html_parts)

    # ----- export --------------------------------------------------------
    def records_for_ips(self, ips):
        """Return the latest records whose IP is in ``ips`` (order preserved)."""
        wanted = set(ips)
        return [r for r in self.latest_records if r["ip"] in wanted]

    def clean_lines(self, records):
        """Return every original input line (verbatim, with port/credentials)
        whose IP matches one of ``records``. Preserves the exact imported
        format, so ``ip:port:user:pass`` comes back as ``ip:port:user:pass``."""
        ip_to_lines = {}
        for raw in self.latest_raw:
            ip = self.extract_ip(raw)
            if ip:
                ip_to_lines.setdefault(ip, []).append(raw)
        out = []
        seen = set()
        for record in records:
            ip = record["ip"]
            if ip in seen:
                continue
            seen.add(ip)
            out.extend(ip_to_lines.get(ip, []))
        return out

    def clean_text(self, records):
        """Plain-text proxy list (one original line per row)."""
        return "\n".join(self.clean_lines(records))

    def clean_lines_csv(self, records):
        """CSV of the clean proxy lines (one per row)."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        for line in self.clean_lines(records):
            writer.writerow([line])
        return buffer.getvalue()

    def full_csv(self, records):
        """CSV of the full analysis (all columns, with labels)."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([label for _, label in FIELDS])
        for record in records:
            writer.writerow([record.get(key, "") for key, _ in FIELDS])
        return buffer.getvalue()

    def records_json(self, records):
        """JSON array of the analysis (internal keys) for the given records."""
        keys = [k for k, _ in FIELDS]
        out = [{k: r.get(k) for k in keys} for r in records]
        return json.dumps(out, ensure_ascii=False, indent=2)

    # ----- summary -------------------------------------------------------
    def summary(self, records):
        """Aggregate stats for a set of records (for the dashboard)."""
        total = len(records)
        valid = [r for r in records if not r.get("error")]
        n_valid = len(valid)

        def cnt(key):
            return sum(1 for r in valid if r.get(key))

        clean = sum(
            1 for r in valid
            if not r["proxy"] and not r["vpn"] and not r["tor"]
            and not r["recent_abuse"] and r["fraud_score"] <= 30
        )
        avg_fraud = round(sum(r["fraud_score"] for r in valid) / n_valid, 1) if n_valid else 0
        countries = Counter(r["country"] for r in valid if r.get("country"))
        top = [{"code": c, "count": n} for c, n in countries.most_common(3)]

        return {
            "total": total,
            "valid": n_valid,
            "errors": total - n_valid,
            "clean": clean,
            "proxies": cnt("proxy"),
            "vpn": cnt("vpn"),
            "tor": cnt("tor"),
            "bot": cnt("bot_status"),
            "abuse": cnt("recent_abuse"),
            "avg_fraud": avg_fraud,
            "top_countries": top,
        }
