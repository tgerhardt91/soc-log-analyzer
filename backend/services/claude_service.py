import json
from collections import Counter
import anthropic
import config

_client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
MODEL = "claude-sonnet-4-6"

# Cached system prompt — reused across calls to take advantage of prompt caching
_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst assistant.
You are given structured data from ZScaler Web Proxy logs and must provide clear,
concise, actionable security analysis. Always respond with valid JSON as instructed.
Focus on threats, anomalies, and patterns that matter most to a security analyst."""


def _system_with_cache():
    return [{"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]


def generate_summary(analysis, entries: list, anomalies: list) -> str:
    """Ask Claude to write a 3-5 sentence SOC executive summary."""
    if not entries:
        return "No log entries were found in the uploaded file."

    timestamps = [e.timestamp for e in entries if e.timestamp]
    time_range = ""
    if timestamps:
        time_range = f"{min(timestamps)} to {max(timestamps)}"

    top_categories = Counter(e.category for e in entries if e.category).most_common(5)
    top_ips = Counter(e.src_ip for e in entries if e.src_ip).most_common(5)
    top_domains = Counter(e.dst_hostname for e in entries if e.dst_hostname).most_common(5)
    blocked = sum(1 for e in entries if (e.action or "").lower() == "blocked")

    context = {
        "time_range": time_range,
        "total_events": len(entries),
        "blocked_count": blocked,
        "blocked_pct": round(blocked / len(entries) * 100, 1) if entries else 0,
        "anomaly_count": len(anomalies),
        "top_categories": top_categories,
        "top_source_ips": top_ips,
        "top_destinations": top_domains,
        "anomaly_types": [a.anomaly_type for a in anomalies],
    }

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


def enrich_anomalies(anomalies: list) -> None:
    """Ask Claude to enrich each anomaly with a better explanation and confidence score.
    Mutates the Anomaly objects in place."""
    if not anomalies:
        return

    entries_context = []
    for a in anomalies:
        entry_dict = a.log_entry.to_dict() if a.log_entry else {}
        entries_context.append({
            "anomaly_id": a.id,
            "anomaly_type": a.anomaly_type,
            "preliminary_explanation": a.explanation,
            "preliminary_confidence": a.confidence,
            "log_entry": entry_dict,
        })

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
        model=MODEL,
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
        enriched = json.loads(raw)
        enriched_by_id = {item["anomaly_id"]: item for item in enriched}
        for a in anomalies:
            if a.id in enriched_by_id:
                item = enriched_by_id[a.id]
                a.explanation = item.get("explanation", a.explanation)
                a.confidence = float(item.get("confidence", a.confidence))
    except Exception:
        pass  # Keep preliminary values if Claude response can't be parsed
