import json
from collections import Counter
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
