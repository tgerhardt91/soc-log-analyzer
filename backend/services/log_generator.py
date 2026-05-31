"""Generate synthetic ZScaler Web Proxy log files for testing anomaly detection."""
import random
from datetime import datetime, timedelta
from urllib.parse import urlparse

USERS = [
    "jsmith@corp.com", "amartinez@corp.com", "lchen@corp.com",
    "bwilson@corp.com", "kpatel@corp.com", "emorgan@corp.com",
]
ALLOWED_DOMAINS = [
    "github.com", "stackoverflow.com", "docs.microsoft.com",
    "slack.com", "zoom.us", "google.com", "linkedin.com",
    "aws.amazon.com", "jira.atlassian.com", "confluence.atlassian.com",
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io",
]
CATEGORIES = [
    "Business and Economy", "Software/Technology", "News and Media",
    "Social Networking", "Shopping", "Reference and Research",
    "Health", "Financial Services", "Education",
]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]
METHODS = ["GET", "GET", "GET", "POST", "GET", "GET"]

_BASE = datetime(2024, 6, 10, 8, 0, 0)

_HEADER = (
    "# ZScaler Web Proxy Log — generated sample\n"
    "# Fields: timestamp|username|src_ip|dst_url|category|action"
    "|bytes_sent|bytes_received|method|response_code|user_agent|threat_name|duration_ms\n"
)


def _row(*fields) -> str:
    return "|".join(str(f) for f in fields)


def _parse_row(row: str) -> dict:
    f = row.split("|")
    url = f[3] if len(f) > 3 else ""
    return {
        "timestamp":      f[0]  if len(f) > 0 else "",
        "username":       f[1]  if len(f) > 1 else "",
        "src_ip":         f[2]  if len(f) > 2 else "",
        "dst_url":        url,
        "dst_hostname":   urlparse(url).netloc or url,
        "category":       f[4]  if len(f) > 4 else "",
        "action":         f[5]  if len(f) > 5 else "",
        "bytes_sent":     int(f[6]) if len(f) > 6 and f[6].isdigit() else 0,
        "bytes_received": int(f[7]) if len(f) > 7 and f[7].isdigit() else 0,
        "method":         f[8]  if len(f) > 8 else "",
        "response_code":  int(f[9]) if len(f) > 9 and f[9].isdigit() else 0,
        "user_agent":     f[10] if len(f) > 10 else "",
        "threat_name":    f[11] if len(f) > 11 else "",
    }


def _background(n: int) -> list[str]:
    rows = []
    for _ in range(n):
        ts = _BASE + timedelta(seconds=random.randint(0, 8 * 3600))
        src_ip = f"192.168.{random.randint(1, 5)}.{random.randint(10, 200)}"
        domain = random.choice(ALLOWED_DOMAINS)
        url = f"https://{domain}{random.choice(['/', '/page', '/api/data', '/repo', '/docs'])}"
        rows.append(_row(
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            random.choice(USERS), src_ip, url,
            random.choice(CATEGORIES), "Allowed",
            random.randint(200, 5000), random.randint(2000, 80000),
            random.choice(METHODS),
            random.choice([200, 200, 200, 301, 304, 404]),
            random.choice(BROWSER_UAS), "",
            random.randint(50, 800),
        ))
    return rows


# ---------------------------------------------------------------------------
# Rule-based anomaly seeders — each returns a list of rows
# ---------------------------------------------------------------------------

def _seed_ip_spike() -> list[str]:
    rows = []
    spike_base = _BASE + timedelta(hours=2, minutes=30)
    for _ in range(60):
        ts = spike_base + timedelta(seconds=random.randint(0, 240))
        rows.append(_row(
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            "kpatel@corp.com", "192.168.99.99",
            "https://pastebin.com/raw/xK9mzP", "Unknown", "Allowed",
            random.randint(100, 500), random.randint(500, 2000),
            "GET", 200, BROWSER_UAS[0], "", 100,
        ))
    return rows


def _seed_data_exfil() -> list[str]:
    ts = _BASE + timedelta(hours=6, minutes=22)
    return [_row(
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        "emorgan@corp.com", "192.168.3.77",
        "https://transfer.sh/upload/data.zip", "Unknown", "Allowed",
        26_214_400, 1024, "POST", 200, BROWSER_UAS[0], "", 12000,
    )]


def _seed_off_hours() -> list[str]:
    ts = datetime(2024, 6, 10, 2, 15, 0)
    return [_row(
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        "jsmith@corp.com", "192.168.1.10",
        "https://mega.nz/folder/xyzxyz", "File Sharing", "Allowed",
        4096, 1_048_576, "GET", 200, BROWSER_UAS[0], "", 3400,
    )]


def _seed_blocked_threat() -> list[str]:
    ts = _BASE + timedelta(hours=3, minutes=5)
    return [_row(
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        "bwilson@corp.com", "192.168.2.44",
        "http://malware-c2.ru/beacon", "Malicious URLs", "Blocked",
        512, 0, "GET", 403, BROWSER_UAS[1], "Win32.Trojan.Agent", 20,
    )]


def _seed_rare_destination() -> list[str]:
    ts = _BASE + timedelta(hours=7, minutes=44)
    return [_row(
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        "amartinez@corp.com", "192.168.4.22",
        "https://x93kqzpwlm.top/gate.php", "Unknown", "Allowed",
        256, 128, "POST", 200, BROWSER_UAS[2], "", 300,
    )]


# ---------------------------------------------------------------------------
# AI-detected anomaly seeders
# ---------------------------------------------------------------------------

def _seed_beaconing() -> list[str]:
    rows = []
    beacon_base = _BASE + timedelta(hours=1)
    for i in range(24):
        ts = beacon_base + timedelta(minutes=5 * i, seconds=random.randint(-8, 8))
        rows.append(_row(
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            "kpatel@corp.com", "192.168.7.42",
            "https://c2-panel.darknet.cc/check", "Unknown", "Allowed",
            random.randint(128, 512), random.randint(256, 1024),
            "GET", 200, BROWSER_UAS[0], "", random.randint(50, 200),
        ))
    return rows


def _seed_slow_exfil() -> list[str]:
    rows = []
    exfil_base = _BASE + timedelta(hours=4)
    for i in range(30):
        ts = exfil_base + timedelta(minutes=i * 8)
        rows.append(_row(
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            "amartinez@corp.com", "192.168.6.88",
            "https://dropbox-backup.io/upload/chunk", "Unknown", "Allowed",
            random.randint(1_800_000, 2_500_000), random.randint(512, 2048),
            "POST", 200, BROWSER_UAS[0], "", random.randint(5000, 15000),
        ))
    return rows


def _seed_ua_anomaly() -> list[str]:
    rows = []
    ua = "python-requests/2.28.0"
    targets = [
        "https://api.github.com/users", "https://api.slack.com/methods",
        "https://api.jira.atlassian.com/rest", "https://graph.microsoft.com/v1.0",
        "https://api.zoom.us/v2/users",
    ]
    ua_base = _BASE + timedelta(hours=5)
    for _ in range(20):
        ts = ua_base + timedelta(seconds=random.randint(0, 3600))
        rows.append(_row(
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            "lchen@corp.com", "192.168.8.15",
            random.choice(targets), "Software/Technology", "Allowed",
            random.randint(200, 1000), random.randint(500, 5000),
            "GET", 200, ua, "", random.randint(100, 500),
        ))
    return rows


def _seed_auth_abuse() -> list[str]:
    rows = []
    targets = [
        "hr.internal.corp.com", "vpn.corp.com", "mail.corp.com",
        "sharepoint.corp.com", "gitlab.corp.com", "jenkins.corp.com",
        "grafana.corp.com", "kibana.corp.com",
    ]
    auth_base = _BASE + timedelta(hours=3, minutes=30)
    for _ in range(40):
        ts = auth_base + timedelta(seconds=random.randint(0, 1800))
        code = 401 if random.random() < 0.70 else 200
        domain = random.choice(targets)
        rows.append(_row(
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            "bwilson@corp.com", "192.168.9.55",
            f"https://{domain}/api/login", "Business and Economy",
            "Allowed", random.randint(200, 800), random.randint(100, 500),
            "POST", code, BROWSER_UAS[0], "", random.randint(50, 300),
        ))
    return rows


_SEEDERS: dict[str, callable] = {
    "ip_spike":         _seed_ip_spike,
    "data_exfil":       _seed_data_exfil,
    "off_hours":        _seed_off_hours,
    "blocked_threat":   _seed_blocked_threat,
    "rare_destination": _seed_rare_destination,
    "beaconing":        _seed_beaconing,
    "slow_exfil":       _seed_slow_exfil,
    "ua_anomaly":       _seed_ua_anomaly,
    "auth_abuse":       _seed_auth_abuse,
}


def generate_log(anomaly_types: list[str], n_background: int = 450) -> str:
    rows = _background(n_background)
    for t in anomaly_types:
        if t in _SEEDERS:
            rows.extend(_SEEDERS[t]())
    rows.sort(key=lambda r: r.split("|")[0])
    return _HEADER + "\n".join(rows) + "\n"


def generate_preview(anomaly_types: list[str], n_background: int = 450) -> dict:
    """Return structured preview data with each entry tagged by its anomaly type."""
    tagged: list[tuple[str, str | None]] = [
        (row, None) for row in _background(n_background)
    ]
    for t in anomaly_types:
        if t in _SEEDERS:
            for row in _SEEDERS[t]():
                tagged.append((row, t))

    tagged.sort(key=lambda x: x[0].split("|")[0])

    seeded_counts: dict[str, int] = {}
    entries = []
    for row, anomaly_type in tagged:
        entry = _parse_row(row)
        entry["anomaly_type"] = anomaly_type
        entries.append(entry)
        if anomaly_type:
            seeded_counts[anomaly_type] = seeded_counts.get(anomaly_type, 0) + 1

    return {
        "total_entries": len(tagged),
        "seeded_counts": seeded_counts,
        "entries": entries,
    }
