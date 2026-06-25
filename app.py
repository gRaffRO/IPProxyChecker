"""Flask front-end for the IPQualityScore proxy/VPN checker (local, single-user).

Scanning is asynchronous: the browser POSTs a list of IPs to ``/scan`` which
starts a background job and returns a ``job_id``. The browser polls
``/progress/<job_id>`` for real progress, the rendered table and a summary.

Persistence (SQLite via storage.py):
- the last scan is saved and restored on refresh / restart;
- every scan is also kept in a browsable history;
- IP lookups are cached with a TTL to save API quota.
"""

import io
import os
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file

import storage
from ip_checker import IPChecker

from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

MAX_PASTE_IPS = 20
MAX_FILE_IPS = 500
CACHE_TTL_SECONDS = int(float(os.getenv("CACHE_TTL_HOURS", "24")) * 3600)
LAST_SCAN_KEY = "last_scan"

storage.init_db()

ip_checker = IPChecker(
    os.getenv("API_KEY", "YOUR_API_KEY"),
    cache_get=storage.cache_get,
    cache_put=storage.cache_put,
    cache_ttl_seconds=CACHE_TTL_SECONDS,
)

# Restore the last working set on startup.
_restored = storage.load_state(LAST_SCAN_KEY, default=None)
if _restored:
    ip_checker.latest_records = _restored.get("records", [])
    ip_checker.latest_raw = _restored.get("raw", [])

_jobs = {}
_jobs_lock = threading.Lock()
JOB_RETENTION_SECONDS = 1800


def _cleanup_jobs():
    now = time.monotonic()
    with _jobs_lock:
        stale = [
            jid for jid, j in _jobs.items()
            if j.get("finished") and (now - j.get("finished_at", now)) > JOB_RETENTION_SECONDS
        ]
        for jid in stale:
            _jobs.pop(jid, None)


def _persist_current():
    storage.save_state(LAST_SCAN_KEY, {
        "records": ip_checker.latest_records,
        "raw": ip_checker.latest_raw,
    })


def _run_scan_job(job_id, ips, bypass_cache):
    def progress(completed, total):
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["completed"] = completed
                job["total"] = total

    try:
        before = ip_checker.api_calls
        records = ip_checker.scan(ips, progress_cb=progress, bypass_cache=bypass_cache)
        storage.incr_api_calls(ip_checker.api_calls - before)

        table = ip_checker.build_table_html(records)
        summary = ip_checker.summary(records)
        _persist_current()
        # Save to history with an auto name.
        name = datetime.now().strftime("%d.%m %H:%M") + f" · {len(records)} IP-uri"
        storage.save_scan(name, records, ip_checker.latest_raw)

        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job.update({
                    "table": table,
                    "summary": summary,
                    "count": len(records),
                    "finished": True,
                    "finished_at": time.monotonic(),
                })
    except Exception as exc:  # pragma: no cover - defensive
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["error"] = str(exc)
                job["finished"] = True
                job["finished_at"] = time.monotonic()


def _parse_filters(args):
    def truthy(name):
        return args.get(name) == "true"

    try:
        fraud_value = int(args.get("fraud_score_value", 50))
    except (TypeError, ValueError):
        fraud_value = 50

    return {
        "proxy": truthy("proxy"), "proxy_value": truthy("proxy_value"),
        "vpn": truthy("vpn"), "vpn_value": truthy("vpn_value"),
        "tor": truthy("tor"), "tor_value": truthy("tor_value"),
        "bot": truthy("bot"), "bot_value": truthy("bot_value"),
        "fraud_score": truthy("fraud_score"), "fraud_score_value": fraud_value,
        "abuse": truthy("abuse"), "abuse_value": truthy("abuse_value"),
        "crawler": truthy("crawler"), "crawler_value": truthy("crawler_value"),
    }


@app.route("/")
def index():
    table = ip_checker.build_table_html(ip_checker.latest_records) if ip_checker.latest_records else None
    summary = ip_checker.summary(ip_checker.latest_records) if ip_checker.latest_records else None
    return render_template("index.html", configured=ip_checker.is_configured, table=table, summary=summary)


@app.route("/scan", methods=["POST"])
def scan():
    _cleanup_jobs()
    payload = request.get_json(silent=True) or {}
    ips = [str(x).strip() for x in (payload.get("ips") or []) if str(x).strip()]
    source = payload.get("source", "paste")
    bypass_cache = bool(payload.get("bypass_cache", False))

    if not ips:
        return jsonify({"error": "Nu ai introdus nicio adresă IP."}), 400

    cap = MAX_FILE_IPS if source == "file" else MAX_PASTE_IPS
    if len(ips) > cap:
        if source == "file":
            return jsonify({"error": f"Fișierul conține {len(ips)} IP-uri. Maximul permis este {MAX_FILE_IPS}."}), 400
        return jsonify({"error": f"Ai introdus mai mult de {MAX_PASTE_IPS} IP-uri. Folosește un fișier .txt pentru liste mai mari."}), 400

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {"completed": 0, "total": len(ips), "finished": False,
                         "table": None, "summary": None, "count": 0, "error": None}

    threading.Thread(target=_run_scan_job, args=(job_id, ips, bypass_cache), daemon=True).start()
    return jsonify({"job_id": job_id, "total": len(ips)})


@app.route("/progress/<job_id>")
def progress(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Job inexistent", "missing": True}), 404
        snapshot = dict(job)
    snapshot.pop("finished_at", None)
    return jsonify(snapshot)


@app.route("/filter")
def filter_results():
    if not ip_checker.latest_records:
        return jsonify({"table": "<p class='empty-msg'>Nu există date. Scanează mai întâi.</p>", "summary": None})
    filtered = ip_checker.filter_records(ip_checker.latest_records, _parse_filters(request.args))
    if not filtered:
        return jsonify({"table": "<p class='empty-msg'>Niciun rezultat nu corespunde filtrelor.</p>",
                        "summary": ip_checker.summary([])})
    return jsonify({"table": ip_checker.build_table_html(filtered), "summary": ip_checker.summary(filtered)})


@app.route("/export", methods=["POST"])
def export():
    data = request.get_json(silent=True) or {}
    ips = data.get("ips") or []
    fmt = data.get("format", "clean")

    records = ip_checker.records_for_ips(ips)
    if not records:
        return jsonify({"error": "Nimic de exportat."}), 404

    if fmt == "full":
        payload, mimetype, name = ip_checker.full_csv(records), "text/csv", "ip_analysis.csv"
    elif fmt == "json":
        payload, mimetype, name = ip_checker.records_json(records), "application/json", "ip_analysis.json"
    else:
        payload = ip_checker.clean_text(records)
        if not payload:
            return jsonify({"error": "Niciuna dintre selecțiile nu are o linie proxy validă."}), 404
        mimetype, name = "text/plain", "clean_proxies.txt"

    return send_file(io.BytesIO(payload.encode("utf-8")), mimetype=mimetype,
                     as_attachment=True, download_name=name)


@app.route("/copy-clean", methods=["POST"])
def copy_clean():
    data = request.get_json(silent=True) or {}
    records = ip_checker.records_for_ips(data.get("ips") or [])
    return jsonify({"lines": ip_checker.clean_lines(records)})


# ----- history -----------------------------------------------------------
@app.route("/history")
def history():
    return jsonify({"scans": storage.list_scans()})


@app.route("/history/load/<int:scan_id>", methods=["POST"])
def history_load(scan_id):
    data = storage.get_scan(scan_id)
    if not data:
        return jsonify({"error": "Scanarea nu există."}), 404
    ip_checker.latest_records = data["records"]
    ip_checker.latest_raw = data["raw"]
    _persist_current()
    return jsonify({
        "table": ip_checker.build_table_html(ip_checker.latest_records),
        "summary": ip_checker.summary(ip_checker.latest_records),
    })


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
def history_delete(scan_id):
    storage.delete_scan(scan_id)
    return jsonify({"ok": True, "scans": storage.list_scans()})


@app.route("/history/clear", methods=["POST"])
def history_clear():
    storage.clear_scans()
    return jsonify({"ok": True})


# ----- stats / cache -----------------------------------------------------
@app.route("/stats")
def stats():
    return jsonify({"api_calls": storage.get_api_calls(), "cache_count": storage.cache_count()})


@app.route("/cache/clear", methods=["POST"])
def cache_clear():
    storage.cache_clear()
    return jsonify({"ok": True, "cache_count": 0})


@app.route("/reset", methods=["POST"])
def reset_data():
    ip_checker.latest_records = []
    ip_checker.latest_raw = []
    storage.clear_state(LAST_SCAN_KEY)
    return jsonify({"ok": True})


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=5050)
