from collections import defaultdict

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

    hostname_counts = defaultdict(int)
    for e in entries:
        if e.dst_hostname:
            hostname_counts[e.dst_hostname] += 1

    # --- ip_spike: one anomaly per offending IP, linked to all its entries ---
    ip_windows = _time_windows(entries)
    spike_ips = {ip for (ip, _), cnt in ip_windows.items() if cnt >= IP_SPIKE_THRESHOLD}

    entries_by_spike_ip = defaultdict(list)
    for e in entries:
        if e.src_ip and e.src_ip in spike_ips:
            entries_by_spike_ip[e.src_ip].append(e)

    for ip, ip_entries in entries_by_spike_ip.items():
        timestamps = sorted(t.timestamp for t in ip_entries if t.timestamp)
        window_str = ""
        if timestamps:
            window_str = f" between {timestamps[0].strftime('%H:%M')} and {timestamps[-1].strftime('%H:%M')}"
        top_dest = max(
            defaultdict(int, {e.dst_hostname: 1 for e in ip_entries if e.dst_hostname}),
            key=lambda h: sum(1 for e in ip_entries if e.dst_hostname == h),
            default="unknown",
        )
        results.append({
            "anomaly_type": "ip_spike",
            "explanation": (
                f"{ip} made {len(ip_entries)} requests{window_str} "
                f"(top destination: {top_dest}) — possible scanning or automated activity."
            ),
            "confidence": 0.75,
            "log_entry_ids": [e.id for e in ip_entries],
        })

    # --- data_exfil: individual records (each large transfer is a distinct finding) ---
    for e in entries:
        if (e.bytes_sent or 0) > BYTES_EXFIL_THRESHOLD:
            results.append({
                "anomaly_type": "data_exfil",
                "explanation": f"Large outbound transfer ({e.bytes_sent:,} bytes) to {e.dst_hostname}.",
                "confidence": 0.85,
                "log_entry_ids": [e.id],
            })

    # --- off_hours: one anomaly per src_ip, linked to all that IP's off-hours events ---
    off_hours_by_ip = defaultdict(list)
    for e in entries:
        if e.timestamp:
            hour = e.timestamp.hour
            if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                off_hours_by_ip[e.src_ip or "unknown"].append(e)

    for ip, ip_entries in off_hours_by_ip.items():
        timestamps = sorted(e.timestamp for e in ip_entries if e.timestamp)
        time_range = (
            f"{timestamps[0].strftime('%H:%M')}–{timestamps[-1].strftime('%H:%M')}"
            if timestamps else ""
        )
        results.append({
            "anomaly_type": "off_hours",
            "explanation": (
                f"{len(ip_entries)} off-hours request(s) from {ip} ({time_range}) "
                f"— outside normal business hours."
            ),
            "confidence": 0.60,
            "log_entry_ids": [e.id for e in ip_entries],
        })

    # --- blocked_threat: one anomaly per (src_ip, threat_name) pair ---
    blocked_by_key = defaultdict(list)
    for e in entries:
        if e.action and e.action.lower() == "blocked" and e.threat_name:
            blocked_by_key[(e.src_ip, e.threat_name)].append(e)

    for (ip, threat), threat_entries in blocked_by_key.items():
        count = len(threat_entries)
        dst = threat_entries[0].dst_hostname
        results.append({
            "anomaly_type": "blocked_threat",
            "explanation": (
                f"Blocked threat '{threat}' from {ip} to {dst}"
                + (f" ({count} events)" if count > 1 else "") + "."
            ),
            "confidence": 0.95,
            "log_entry_ids": [e.id for e in threat_entries],
        })

    # --- rare_destination: individual records (each unknown domain is a distinct finding) ---
    for e in entries:
        if (
            e.dst_hostname
            and hostname_counts[e.dst_hostname] == 1
            and (e.category or "").lower() in ("unknown", "")
        ):
            results.append({
                "anomaly_type": "rare_destination",
                "explanation": f"Single request to unknown-category domain {e.dst_hostname}.",
                "confidence": 0.55,
                "log_entry_ids": [e.id],
            })

    return results
