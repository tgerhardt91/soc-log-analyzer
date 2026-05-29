"""Generate a realistic sample ZScaler Web Proxy log file for testing."""
import random
from datetime import datetime, timedelta

USERS = [
    "jsmith@corp.com", "amartinez@corp.com", "lchen@corp.com",
    "bwilson@corp.com", "kpatel@corp.com", "emorgan@corp.com",
]
CATEGORIES = [
    "Business and Economy", "Software/Technology", "News and Media",
    "Social Networking", "Shopping", "Reference and Research",
    "Health", "Financial Services", "Education",
]
ALLOWED_DOMAINS = [
    "github.com", "stackoverflow.com", "docs.microsoft.com",
    "slack.com", "zoom.us", "google.com", "linkedin.com",
    "aws.amazon.com", "jira.atlassian.com", "confluence.atlassian.com",
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]
METHODS = ["GET", "GET", "GET", "POST", "GET", "GET"]

def generate(path: str, n: int = 500):
    base = datetime(2024, 6, 10, 8, 0, 0)
    entries = []

    # Normal traffic: spread over 8 hours, 9 hours
    for i in range(n - 30):
        ts = base + timedelta(seconds=random.randint(0, 8 * 3600))
        user = random.choice(USERS)
        src_ip = f"192.168.{random.randint(1, 5)}.{random.randint(10, 200)}"
        domain = random.choice(ALLOWED_DOMAINS)
        path_part = random.choice(["/", "/page", "/api/data", "/repo", "/docs"])
        url = f"https://{domain}{path_part}"
        cat = random.choice(CATEGORIES)
        bs = random.randint(200, 5000)
        br = random.randint(2000, 80000)
        code = random.choice([200, 200, 200, 200, 301, 304, 404])
        entries.append((ts, user, src_ip, url, cat, "Allowed", bs, br, random.choice(METHODS), code, random.choice(USER_AGENTS), "", random.randint(50, 800)))

    # Anomaly 1: IP spike — 192.168.99.99 makes 60 requests in 4 minutes starting at 10:30
    spike_base = datetime(2024, 6, 10, 10, 30, 0)
    for i in range(60):
        ts = spike_base + timedelta(seconds=random.randint(0, 240))
        entries.append((ts, "kpatel@corp.com", "192.168.99.99", "https://pastebin.com/raw/xK9mzP", "Unknown", "Allowed", random.randint(100, 500), random.randint(500, 2000), "GET", 200, USER_AGENTS[0], "", 100))

    # Anomaly 2: large upload (data exfil) — 25 MB sent to unknown host
    exfil_ts = datetime(2024, 6, 10, 14, 22, 0)
    entries.append((exfil_ts, "emorgan@corp.com", "192.168.3.77", "https://transfer.sh/upload/data.zip", "Unknown", "Allowed", 26_214_400, 1024, "POST", 200, USER_AGENTS[0], "", 12000))

    # Anomaly 3: blocked malware
    mal_ts = datetime(2024, 6, 10, 11, 5, 0)
    entries.append((mal_ts, "bwilson@corp.com", "192.168.2.44", "http://malware-c2.ru/beacon", "Malicious URLs", "Blocked", 512, 0, "GET", 403, USER_AGENTS[1], "Win32.Trojan.Agent", 20))

    # Anomaly 4: off-hours access (2:15 AM)
    oh_ts = datetime(2024, 6, 10, 2, 15, 0)
    entries.append((oh_ts, "jsmith@corp.com", "192.168.1.10", "https://mega.nz/folder/xyzxyz", "File Sharing", "Allowed", 4096, 1_048_576, "GET", 200, USER_AGENTS[0], "", 3400))

    # Anomaly 5: rare unknown domain
    rare_ts = datetime(2024, 6, 10, 15, 44, 0)
    entries.append((rare_ts, "amartinez@corp.com", "192.168.4.22", "https://x93kqzpwlm.top/gate.php", "Unknown", "Allowed", 256, 128, "POST", 200, USER_AGENTS[2], "", 300))

    entries.sort(key=lambda e: e[0])

    with open(path, "w") as f:
        f.write("# ZScaler Web Proxy Log — generated sample\n")
        f.write("# Fields: timestamp|username|src_ip|dst_url|category|action|bytes_sent|bytes_received|method|response_code|user_agent|threat_name|duration_ms\n")
        for e in entries:
            ts_str = e[0].strftime("%Y-%m-%d %H:%M:%S")
            f.write("|".join([
                ts_str, e[1], e[2], e[3], e[4], e[5],
                str(e[6]), str(e[7]), e[8], str(e[9]), e[10], e[11], str(e[12]),
            ]) + "\n")

    print(f"Wrote {len(entries)} entries to {path}")

if __name__ == "__main__":
    import os
    out = os.path.join(os.path.dirname(__file__), "sample_zscaler.log")
    generate(out)
