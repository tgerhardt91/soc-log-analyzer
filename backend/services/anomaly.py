from collections import defaultdict
from datetime import timedelta

BYTES_EXFIL_THRESHOLD = 10 * 1024 * 1024  # 10 MB
IP_SPIKE_THRESHOLD = 50                    # requests per 5-minute window
OFF_HOURS_START = 23                       # 11 PM
OFF_HOURS_END = 5                          # 5 AM


def _time_windows(entries, window_minutes=5):
    """Group entries by (src_ip, 5-min bucket) and return counts."""
    counts = defaultdict(int)
    for e in entries:
        if e.timestamp and e.src_ip:
            bucket = e.timestamp.replace(
                minute=(e.timestamp.minute // window_minutes) * window_minutes,
                second=0, microsecond=0,
            )
            counts[(e.src_ip, bucket)] += 1
    return counts


def screen_anomalies(entries: list) -> list[dict]:
    results = []
    seen_entry_ids = set()

    hostname_counts = defaultdict(int)
    for e in entries:
        if e.dst_hostname:
            hostname_counts[e.dst_hostname] += 1

    ip_windows = _time_windows(entries)
    spike_ips = {ip for (ip, _), cnt in ip_windows.items() if cnt >= IP_SPIKE_THRESHOLD}

    for e in entries:
        flags = []

        if e.src_ip and e.src_ip in spike_ips:
            flags.append({
                "anomaly_type": "ip_spike",
                "explanation": f"High request volume from {e.src_ip} — preliminary flag for AI review.",
                "confidence": 0.75,
            })

        if (e.bytes_sent or 0) > BYTES_EXFIL_THRESHOLD:
            flags.append({
                "anomaly_type": "data_exfil",
                "explanation": f"Large outbound transfer ({e.bytes_sent:,} bytes) to {e.dst_hostname}.",
                "confidence": 0.85,
            })

        if e.timestamp:
            hour = e.timestamp.hour
            if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                flags.append({
                    "anomaly_type": "off_hours",
                    "explanation": f"Activity at {e.timestamp.strftime('%H:%M')} — outside normal business hours.",
                    "confidence": 0.60,
                })

        if e.action and e.action.lower() == "blocked" and e.threat_name:
            flags.append({
                "anomaly_type": "blocked_threat",
                "explanation": f"Blocked threat '{e.threat_name}' from {e.src_ip} to {e.dst_hostname}.",
                "confidence": 0.95,
            })

        if (
            e.dst_hostname
            and hostname_counts[e.dst_hostname] == 1
            and (e.category or "").lower() in ("unknown", "")
        ):
            flags.append({
                "anomaly_type": "rare_destination",
                "explanation": f"Single request to unknown-category domain {e.dst_hostname}.",
                "confidence": 0.55,
            })

        for flag in flags:
            if e.id not in seen_entry_ids:
                seen_entry_ids.add(e.id)
            results.append({**flag, "log_entry_id": e.id})

    return results
