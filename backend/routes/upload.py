import os
import threading
import uuid
from flask import Blueprint, request, jsonify
from models import db, Analysis, LogEntry
from routes.auth import require_jwt
from services.parser import parse_log_file
from services.anomaly import screen_anomalies
from services.claude_service import enrich_anomalies, generate_summary
import config

upload_bp = Blueprint("upload", __name__)

ALLOWED_EXTENSIONS = {"log", "txt", "csv"}


def _ext_ok(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _process(app, analysis_id: str, filepath: str):
    with app.app_context():
        analysis = Analysis.query.get(analysis_id)
        try:
            analysis.status = "processing"
            db.session.commit()

            entries = parse_log_file(filepath, analysis_id)
            if entries:
                db.session.bulk_insert_mappings(LogEntry, entries)
                db.session.commit()

            analysis.total_events = len(entries)
            analysis.blocked_count = sum(1 for e in entries if (e.get("action") or "").lower() == "blocked")
            db.session.commit()

            # Load persisted entries for anomaly screening
            db_entries = LogEntry.query.filter_by(analysis_id=analysis_id).all()
            raw_anomalies = screen_anomalies(db_entries)

            from models import Anomaly
            for a in raw_anomalies:
                db.session.add(Anomaly(
                    analysis_id=analysis_id,
                    log_entry_id=a.get("log_entry_id"),
                    anomaly_type=a["anomaly_type"],
                    explanation=a["explanation"],
                    confidence=a["confidence"],
                ))
            db.session.commit()

            db_anomalies = list(Anomaly.query.filter_by(analysis_id=analysis_id).all())
            enrich_anomalies(db_anomalies)
            db.session.commit()

            analysis.summary = generate_summary(analysis, db_entries, db_anomalies)
            analysis.status = "done"
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            analysis.status = "error"
            analysis.summary = str(exc)
            db.session.commit()
            raise


@upload_bp.route("/upload", methods=["POST"])
@require_jwt
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if not file.filename or not _ext_ok(file.filename):
        return jsonify({"error": "Invalid file type. Accepted: .log, .txt, .csv"}), 400

    analysis_id = str(uuid.uuid4())
    safe_name = f"{analysis_id}_{file.filename}"
    filepath = os.path.join(config.UPLOAD_DIR, safe_name)
    file.save(filepath)

    analysis = Analysis(id=analysis_id, filename=file.filename, status="pending")
    db.session.add(analysis)
    db.session.commit()

    from flask import current_app
    app = current_app._get_current_object()
    thread = threading.Thread(target=_process, args=(app, analysis_id, filepath), daemon=True)
    thread.start()

    return jsonify({"analysis_id": analysis_id}), 202
