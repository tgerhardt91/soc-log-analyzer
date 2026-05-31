import json
import statistics
from collections import Counter, defaultdict
import anthropic
import config

_client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
MODEL = "claude-sonnet-4-6"
ENRICH_MODEL = "claude-haiku-4-5-20251001"
MAX_ENRICH = 25
MAX_ENTRIES_PER_ANOMALY = 5  # representative sample; Claude doesn't need all linked events

# Cached system prompt — reused across calls to take advantage of prompt caching
_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst assistant.
You are given structured data from ZScaler Web Proxy logs and must provide clear,
concise, actionable security analysis. Always respond with valid JSON as instructed.
Focus on threats, anomalies, and patterns that matter most to a security analyst."""


def _system_with_cache():
    return [{"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]


# ---------------------------------------------------------------------------
# Enrichment — three phases so ORM access stays in the calling thread
# ---------------------------------------------------------------------------

def build_enrich_context(anomalies: list) -> tuple[list, list]:
    """Phase 1 (main thread): read ORM data, return (to_enrich, serialized context).
    Must be called within a Flask app context."""
    to_enrich = sorted(anomalies, key=lambda a: a.confidence, reverse=True)[:MAX_ENRICH]
    entries_context = [
        {
            "anomaly_id": a.id,
            "anomaly_type": a.anomaly_type,
            "preliminary_explanation": a.explanation,
            "preliminary_confidence": a.confidence,
            "log_entries": [e.to_dict() for e in a.log_entries[:MAX_ENTRIES_PER_ANOMALY]],
            "total_linked_events": len(a.log_entries),
        }
        for a in to_enrich
    ]
    return to_enrich, entries_context


def call_enrich_api(entries_context: list) -> list:
    """Phase 2 (threadable): pure Claude I/O, no ORM access."""
    if not entries_context:
        return []

    prompt = f"""You are analyzing flagged anomalies from ZScaler Web Proxy logs.
For each anomaly below, provide:
1. A clear, specific explanation of why this is suspicious (1-2 sentences, written for a SOC analyst)
2. A confidence score (0.0 to 1.0)

Anomalies to analyze:
{json.dumps(entries_context, indent=2, default=str)}

Respond with a JSON array, one object per anomaly, in the same order:
[
  {{
    "anomaly_id": "<id>",
    "explanation": "<improved explanation>",
    "confidence": <0.0-1.0>
  }},
  ...
]"""

    response = _client.messages.create(
        model=ENRICH_MODEL,
        max_tokens=1024,
        system=_system_with_cache(),
        messages=[{"role": "user", "content": prompt}],
    )
    try:
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)
    except Exception:
        return []


def apply_enrich_results(to_enrich: list, enriched_items: list) -> None:
    """Phase 3 (main thread): mutate ORM objects with Claude's results."""
    enriched_by_id = {item["anomaly_id"]: item for item in enriched_items}
    for a in to_enrich:
        if a.id in enriched_by_id:
            item = enriched_by_id[a.id]
            a.explanation = item.get("explanation", a.explanation)
            a.confidence = float(item.get("confidence", a.confidence))


# ---------------------------------------------------------------------------
# Summary — same three-phase pattern
# ---------------------------------------------------------------------------

def build_summary_context(entries: list, raw_anomalies: list) -> dict:
    """Phase 1 (main thread): read ORM entry data and raw anomaly dicts, return serialized
    context. Accepts raw_anomalies (plain dicts from screen_anomalies) so this can be called
    before anomalies are inserted into the DB."""
    timestamps = [e.timestamp for e in entries if e.timestamp]
    time_range = f"{min(timestamps)} to {max(timestamps)}" if timestamps else ""
    blocked = sum(1 for e in entries if (e.action or "").lower() == "blocked")

    return {
        "time_range": time_range,
        "total_events": len(entries),
        "blocked_count": blocked,
        "blocked_pct": round(blocked / len(entries) * 100, 1) if entries else 0,
        "anomaly_count": len(raw_anomalies),
        "top_categories": Counter(e.category for e in entries if e.category).most_common(5),
        "top_source_ips": Counter(e.src_ip for e in entries if e.src_ip).most_common(5),
        "top_destinations": Counter(e.dst_hostname for e in entries if e.dst_hostname).most_common(5),
        "anomaly_types": [a["anomaly_type"] for a in raw_anomalies],
    }


def call_summary_api(context: dict) -> str:
    """Phase 2 (threadable): pure Claude I/O, no ORM access."""
    if not context.get("total_events"):
        return "No log entries were found in the uploaded file."

    prompt = f"""Given the following ZScaler Web Proxy log summary, write a 3-5 sentence
executive summary for a SOC analyst. Focus on the most important security findings,
notable patterns, and recommended follow-up actions. Be specific and actionable.

Log data summary:
{json.dumps(context, indent=2, default=str)}

Respond with a JSON object: {{"summary": "<your summary text>"}}"""

    response = _client.messages.create(
        model=MODEL,
        max_tokens=512,
        system=_system_with_cache(),
        messages=[{"role": "user", "content": prompt}],
    )
    try:
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)["summary"]
    except Exception:
        return response.content[0].text.strip()


# ---------------------------------------------------------------------------
# AI second-pass detection — same three-phase pattern
# ---------------------------------------------------------------------------

_PROGRAMMATIC_UA = ["python", "curl", "wget", "go-http", "java/", "okhttp", "libwww", "httpie"]
MAX_AI_DETECT_CANDIDATES = 15


def build_ai_detect_context(entries: list, flagged_entry_ids: set) -> dict | None:
    """Phase 1 (main thread): compute behavioral anomaly candidates for AI validation.

    Runs statistical tests (beaconing regularity, cumulative bytes, auth failure rate,
    programmatic user-agents) in Python, then packages the candidates for Claude to
    validate and explain. Entry IDs come from our code, not from Claude, so hallucination
    of non-existent IDs is structurally prevented.
    """
    if not entries:
        return None

    ip_requests: dict = defaultdict(list)
    ip_host_times: dict = defaultdict(list)   # (ip, hostname) -> [(timestamp, entry_id)]
    ip_resp_codes: dict = defaultdict(lambda: defaultdict(int))
    ip_user_agents: dict = defaultdict(set)

    for e in entries:
        if not e.src_ip:
            continue
        ip = e.src_ip
        ip_requests[ip].append(e)
        if e.dst_hostname and e.timestamp:
            ip_host_times[(ip, e.dst_hostname)].append((e.timestamp, e.id))
        if e.response_code:
            ip_resp_codes[ip][e.response_code] += 1
        if e.user_agent:
            ip_user_agents[ip].add(e.user_agent)

    candidates = []

    # Beaconing: requests to the same host at suspiciously regular intervals
    for (ip, hostname), time_entries in ip_host_times.items():
        if len(time_entries) < 5:
            continue
        sorted_te = sorted(time_entries, key=lambda x: x[0])
        timestamps = [t for t, _ in sorted_te]
        entry_ids = [eid for _, eid in sorted_te if eid not in flagged_entry_ids]
        intervals = [(timestamps[i + 1] - timestamps[i]).total_seconds()
                     for i in range(len(timestamps) - 1)]
        avg = statistics.mean(intervals)
        if avg < 60:   # sub-minute bursts are browsing, not beaconing
            continue
        std = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = std / avg if avg > 0 else 1.0
        if cv < 0.30 and entry_ids:
            candidates.append({
                "candidate_type": "beaconing",
                "src_ip": ip,
                "dst_hostname": hostname,
                "request_count": len(time_entries),
                "avg_interval_seconds": round(avg),
                "interval_regularity_pct": round((1 - cv) * 100),
                "entry_ids": entry_ids[:20],
            })

    # Slow exfil: high cumulative bytes_sent but no single event over the rule threshold
    SLOW_EXFIL_TOTAL = 50 * 1024 * 1024   # 50 MB cumulative
    SINGLE_THRESHOLD = 10 * 1024 * 1024   # 10 MB (already caught by data_exfil rule)
    for ip, reqs in ip_requests.items():
        total_bytes = sum(e.bytes_sent or 0 for e in reqs)
        if total_bytes < SLOW_EXFIL_TOTAL:
            continue
        if max(e.bytes_sent or 0 for e in reqs) >= SINGLE_THRESHOLD:
            continue   # already flagged by data_exfil rule
        top_reqs = sorted(reqs, key=lambda e: e.bytes_sent or 0, reverse=True)
        entry_ids = [e.id for e in top_reqs if e.id not in flagged_entry_ids][:20]
        if entry_ids:
            candidates.append({
                "candidate_type": "slow_exfil",
                "src_ip": ip,
                "total_bytes_sent_mb": round(total_bytes / (1024 * 1024), 1),
                "request_count": len(reqs),
                "entry_ids": entry_ids,
            })

    # Programmatic user-agents: curl, python-requests, etc.
    for ip, uas in ip_user_agents.items():
        prog_uas = [ua for ua in uas if any(p in ua.lower() for p in _PROGRAMMATIC_UA)]
        if not prog_uas:
            continue
        prog_entries = [e for e in ip_requests[ip]
                        if any(p in (e.user_agent or "").lower() for p in _PROGRAMMATIC_UA)]
        entry_ids = [e.id for e in prog_entries if e.id not in flagged_entry_ids][:20]
        if entry_ids:
            candidates.append({
                "candidate_type": "ua_anomaly",
                "src_ip": ip,
                "programmatic_user_agents": prog_uas[:5],
                "request_count_with_prog_ua": len(prog_entries),
                "entry_ids": entry_ids,
            })

    # Auth abuse: ≥30 % of requests return 401/403 across ≥5 requests
    for ip, codes in ip_resp_codes.items():
        total = len(ip_requests[ip])
        auth_fails = codes.get(401, 0) + codes.get(403, 0)
        if total < 5 or auth_fails / total < 0.30:
            continue
        fail_entries = [e for e in ip_requests[ip] if e.response_code in (401, 403)]
        entry_ids = [e.id for e in fail_entries if e.id not in flagged_entry_ids][:20]
        if not entry_ids:
            continue
        unique_dests = len({e.dst_hostname for e in fail_entries if e.dst_hostname})
        candidates.append({
            "candidate_type": "auth_abuse",
            "src_ip": ip,
            "total_requests": total,
            "auth_failures": auth_fails,
            "failure_rate_pct": round(auth_fails / total * 100),
            "unique_destinations_targeted": unique_dests,
            "entry_ids": entry_ids,
        })

    if not candidates:
        return None

    candidates.sort(key=lambda c: len(c.get("entry_ids", [])), reverse=True)
    top = candidates[:MAX_AI_DETECT_CANDIDATES]
    for i, c in enumerate(top):
        c["index"] = i
    return {"candidates": top}


def call_ai_detect_api(context: dict | None) -> list:
    """Phase 2 (threadable): validate behavioral candidates with Claude. No ORM access.

    Claude only returns {index, confirmed, explanation, confidence} — never entry IDs.
    Python maps back to the original candidate's entry_ids to prevent hallucination and
    keep the response token count small enough to not be truncated.
    """
    if not context or not context.get("candidates"):
        return []

    # Strip entry_ids from what we send — Claude doesn't need them to evaluate
    candidates_for_prompt = [
        {k: v for k, v in c.items() if k != "entry_ids"}
        for c in context["candidates"]
    ]
    candidates_by_index = {c["index"]: c for c in context["candidates"]}

    prompt = f"""The following behavioral patterns were identified by statistical analysis of ZScaler proxy logs.
These have already passed initial screening — your job is to write a clear SOC-analyst explanation
and assign a confidence score for each one.

Candidate types:
- beaconing: regular-interval requests suggesting C2 command-and-control communication
- slow_exfil: sustained low-volume data exfiltration spread across many requests
- ua_anomaly: programmatic/non-browser clients that may indicate malware or automation
- auth_abuse: high auth failure rate suggesting credential stuffing or brute force

Candidates:
{json.dumps(candidates_for_prompt, indent=2, default=str)}

Respond with a JSON array — one object for EVERY candidate (do not skip any):
[
  {{
    "index": <same index as the candidate>,
    "anomaly_type": "<candidate_type>",
    "explanation": "<1-2 sentence SOC-analyst explanation, specific and actionable>",
    "confidence": <0.0-1.0>
  }}
]
Do NOT include entry_ids — Python handles ID assignment."""

    response = _client.messages.create(
        model=ENRICH_MODEL,
        max_tokens=1024,
        system=_system_with_cache(),
        messages=[{"role": "user", "content": prompt}],
    )
    try:
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        items = json.loads(raw)
        if not isinstance(items, list):
            return []
        validated = []
        for item in items:
            if not isinstance(item, dict):
                continue
            conf = float(item.get("confidence", 0))
            if conf < 0.35:
                continue
            candidate = candidates_by_index.get(item.get("index"))
            if candidate is None:
                continue
            validated.append({
                "anomaly_type": item.get("anomaly_type") or candidate["candidate_type"],
                "explanation": item.get("explanation", ""),
                "confidence": conf,
                "log_entry_ids": candidate["entry_ids"],
            })
        return validated
    except Exception as exc:
        import sys
        print(f"[ai_detect] failed: {exc}", file=sys.stderr)
        return []
