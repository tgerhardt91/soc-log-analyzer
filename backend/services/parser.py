import csv
import uuid
from datetime import datetime
from urllib.parse import urlparse

PIPE_FIELDS = [
    "timestamp", "username", "src_ip", "dst_url", "category", "action",
    "bytes_sent", "bytes_received", "http_method", "response_code",
    "user_agent", "threat_name", "duration_ms",
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%b/%Y:%H:%M:%S %z",
    "%a %b %d %H:%M:%S %Y",
]


def _parse_ts(raw: str) -> datetime | None:
    raw = raw.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def _safe_int(val: str, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _row_to_entry(row: dict, analysis_id: str) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "analysis_id": analysis_id,
        "timestamp": _parse_ts(row.get("timestamp", "")),
        "username": row.get("username", "").strip() or None,
        "src_ip": row.get("src_ip", "").strip() or None,
        "dst_url": row.get("dst_url", "").strip() or None,
        "dst_hostname": _hostname(row.get("dst_url", "").strip()),
        "category": row.get("category", "").strip() or None,
        "action": row.get("action", "").strip() or None,
        "bytes_sent": _safe_int(row.get("bytes_sent", "0")),
        "bytes_received": _safe_int(row.get("bytes_received", "0")),
        "http_method": row.get("http_method", "").strip() or None,
        "response_code": _safe_int(row.get("response_code", "0")) or None,
        "user_agent": row.get("user_agent", "").strip() or None,
        "threat_name": row.get("threat_name", "").strip() or None,
    }


def parse_log_file(filepath: str, analysis_id: str) -> list[dict]:
    ext = filepath.rsplit(".", 1)[-1].lower()
    entries = []

    if ext == "csv":
        with open(filepath, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Normalise header names to our field names
                normalised = {k.strip().lower().replace(" ", "_"): v for k, v in row.items()}
                entries.append(_row_to_entry(normalised, analysis_id))
    else:
        # Pipe-delimited (.log / .txt)
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                row = dict(zip(PIPE_FIELDS, parts))
                entries.append(_row_to_entry(row, analysis_id))

    return entries
