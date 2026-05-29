from flask import Blueprint, jsonify, request
from sqlalchemy.orm import joinedload
from models import Analysis, LogEntry, Anomaly
from routes.auth import require_jwt

analyses_bp = Blueprint("analyses", __name__)


@analyses_bp.route("/analyses", methods=["GET"])
@require_jwt
def list_analyses():
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).all()
    return jsonify([a.to_dict() for a in analyses])


@analyses_bp.route("/analyses/<analysis_id>", methods=["GET"])
@require_jwt
def get_analysis(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)

    query = LogEntry.query.filter_by(analysis_id=analysis_id)

    for param, column in [
        ("username",      LogEntry.username),
        ("src_ip",        LogEntry.src_ip),
        ("dst_hostname",  LogEntry.dst_hostname),
        ("category",      LogEntry.category),
        ("threat_name",   LogEntry.threat_name),
    ]:
        val = request.args.get(param)
        if val:
            query = query.filter(column.ilike(f"%{val}%"))

    action_val = request.args.get("action")
    if action_val:
        query = query.filter(LogEntry.action.ilike(action_val))

    code_val = request.args.get("response_code")
    if code_val and code_val.isdigit():
        query = query.filter(LogEntry.response_code == int(code_val))

    paginated = query.order_by(LogEntry.timestamp).paginate(
        page=page, per_page=per_page, error_out=False
    )

    anomalies = (
        Anomaly.query.filter_by(analysis_id=analysis_id)
        .options(joinedload(Anomaly.log_entries))
        .all()
    )
    anomalous_entry_ids = {e.id for a in anomalies for e in a.log_entries}

    entries_data = []
    for e in paginated.items:
        d = e.to_dict()
        d["is_anomalous"] = e.id in anomalous_entry_ids
        entries_data.append(d)

    # Timeline: count requests per hour bucket
    from collections import defaultdict
    hourly = defaultdict(int)
    blocked_hourly = defaultdict(int)
    for e in LogEntry.query.filter_by(analysis_id=analysis_id).all():
        if e.timestamp:
            bucket = e.timestamp.strftime("%Y-%m-%dT%H:00")
            hourly[bucket] += 1
            if (e.action or "").lower() == "blocked":
                blocked_hourly[bucket] += 1

    timeline = [
        {"hour": k, "total": hourly[k], "blocked": blocked_hourly[k]}
        for k in sorted(hourly)
    ]

    return jsonify({
        **analysis.to_dict(),
        "entries": entries_data,
        "total_pages": paginated.pages,
        "current_page": page,
        "total_entries": paginated.total,
        "anomalies": [a.to_dict() for a in anomalies],
        "timeline": timeline,
    })
