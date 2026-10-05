"""Local VirusTotal folder scanner.

The browser only selects files. The API key is loaded from .env on the server.
"""

from __future__ import annotations

import os
import json
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
VT_API = "https://www.virustotal.com/api/v3"
MAX_FILE_SIZE = 650 * 1024 * 1024
DIRECT_UPLOAD_SIZE = 32 * 1024 * 1024
REQUESTS_PER_MINUTE = 4
RATE_WINDOW = 60.0
DATABASE = Path(os.getenv("VT_DATABASE", str(BASE_DIR / "history.sqlite3")))

app = Flask(__name__, static_folder=str(PUBLIC_DIR), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + 2 * 1024 * 1024
load_dotenv(BASE_DIR / ".env")

_rate_lock = threading.Lock()
_request_times: deque[float] = deque()


def api_key() -> str:
    return configured_api_key()


def configured_api_key() -> str:
    value = os.getenv("VT_API_KEY", "").strip()
    if len(value) < 20:
        raise ValueError("Configura una clave API válida en el archivo .env.")
    return value


def database() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    with database() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                analysis_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'queued',
                stats TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )


def save_scan(file_name: str, size: int, analysis_id: str) -> int:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with database() as connection:
        cursor = connection.execute(
            """INSERT INTO scans
               (file_name, size, analysis_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (file_name, size, analysis_id, now, now),
        )
        return int(cursor.lastrowid)


def update_scan(analysis_id: str, status: str, stats: dict[str, Any] | None = None,
                error: str | None = None) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with database() as connection:
        connection.execute(
            """UPDATE scans SET status = ?, stats = ?, error = ?, updated_at = ?
               WHERE analysis_id = ?""",
            (status, json.dumps(stats) if stats is not None else None, error, now, analysis_id),
        )


def scan_history() -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 500"
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["stats"] = json.loads(item["stats"]) if item["stats"] else {}
        result.append(item)
    return result


def monitor_analysis() -> None:
    while True:
        try:
            key = configured_api_key()
            with database() as connection:
                row = connection.execute(
                    """SELECT analysis_id FROM scans
                       WHERE status NOT IN ('completed', 'failed')
                       ORDER BY updated_at LIMIT 1"""
                ).fetchone()
            if row:
                analysis_id = row["analysis_id"]
                try:
                    result = vt_request(f"{VT_API}/analyses/{quote(analysis_id, safe='')}",
                                        key, method="GET")
                    attributes = result.get("data", {}).get("attributes", {})
                    status = attributes.get("status", "queued")
                    stats = attributes.get("stats", {})
                    update_scan(analysis_id, status, stats)
                except (RuntimeError, ValueError, KeyError) as error:
                    update_scan(analysis_id, "failed", error=str(error))
            else:
                time.sleep(15)
        except (ValueError, sqlite3.Error):
            time.sleep(15)


def vt_request(url: str, key: str, **kwargs: Any) -> Any:
    """Make a rate-limited VirusTotal request and return its JSON response."""
    with _rate_lock:
        while True:
            now = time.monotonic()
            while _request_times and now - _request_times[0] >= RATE_WINDOW:
                _request_times.popleft()
            if len(_request_times) < REQUESTS_PER_MINUTE:
                _request_times.append(now)
                break
            time.sleep(RATE_WINDOW - (now - _request_times[0]))
    headers = dict(kwargs.pop("headers", {}))
    headers["x-apikey"] = key
    try:
        response = requests.request(
            timeout=(30, 900), headers=headers, url=url, **kwargs
        )
    except requests.RequestException as error:
        wrapped = RuntimeError(f"No se pudo conectar con VirusTotal: {error}")
        setattr(wrapped, "status_code", 502)
        raise wrapped from error

    if not response.ok:
        detail = response.text[:300].replace("\n", " ")
        error = RuntimeError(f"VirusTotal respondió {response.status_code}: {detail}")
        setattr(error, "status_code", response.status_code)
        raise error
    return response.json()


def send_file(uploaded_file: Any, key: str) -> dict[str, Any]:
    size = uploaded_file.content_length or 0
    if not size:
        uploaded_file.stream.seek(0, os.SEEK_END)
        size = uploaded_file.stream.tell()
        uploaded_file.stream.seek(0)
    if size > MAX_FILE_SIZE:
        raise ValueError("El archivo supera el límite de 650 MB de VirusTotal.")
    endpoint = f"{VT_API}/files"
    if size > DIRECT_UPLOAD_SIZE:
        upload_url = vt_request(f"{VT_API}/files/upload_url", key, method="GET")
        endpoint = upload_url["data"]

    filename = secure_filename(uploaded_file.filename or "archivo")
    uploaded_file.stream.seek(0)
    result = vt_request(
        endpoint,
        key,
        method="POST",
        files={"file": (filename, uploaded_file.stream, uploaded_file.mimetype)},
    )
    analysis_id = result.get("data", {}).get("id", "")
    return {
        "analysisId": analysis_id,
        "analysisUrl": f"https://www.virustotal.com/gui/file-analysis/{analysis_id}",
        "fileName": uploaded_file.filename,
        "size": size,
    }


@app.get("/")
def index() -> Any:
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.post("/api/scan")
def scan() -> Any:
    try:
        key = api_key()
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return jsonify(error="No se recibió ningún archivo."), 400
        result = send_file(uploaded, key)
        result["recordId"] = save_scan(
            result["fileName"], result["size"], result["analysisId"]
        )
        return jsonify(result)
    except (ValueError, KeyError) as error:
        return jsonify(error=str(error)), 400
    except RuntimeError as error:
        return jsonify(error=str(error)), getattr(error, "status_code", 502)


@app.get("/api/usage")
def usage() -> Any:
    try:
        key = api_key()
        user = vt_request(f"{VT_API}/users/{quote(key, safe='')}", key, method="GET")
        user_data = user.get("data", {})
        user_id = user_data.get("id")
        api_usage = None
        if user_id:
            api_usage = vt_request(
                f"{VT_API}/users/{quote(user_id, safe='')}/api_usage", key, method="GET"
            )
        return jsonify(
            userId=user_id,
            quotas=user_data.get("attributes", {}).get("quotas", {}),
            usage=api_usage.get("data") if api_usage else None,
        )
    except (ValueError, KeyError) as error:
        return jsonify(error=str(error)), 400
    except RuntimeError as error:
        return jsonify(error=str(error)), getattr(error, "status_code", 502)


@app.get("/api/history")
def history() -> Any:
    return jsonify(scans=scan_history())


@app.errorhandler(RequestEntityTooLarge)
def too_large(_: RequestEntityTooLarge) -> Any:
    return jsonify(error="El archivo supera el límite de 650 MB de VirusTotal."), 413


init_database()

if __name__ == "__main__":
    threading.Thread(target=monitor_analysis, daemon=True, name="vt-analysis-monitor").start()
    port = int(os.getenv("PORT", "3000"))
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=port, debug=False)
