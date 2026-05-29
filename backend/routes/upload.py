import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, request, jsonify
from sqlalchemy.orm import joinedload
from models import db, Analysis, LogEntry
from routes.auth import require_jwt
from services.parser import parse_log_file
from services.anomaly import screen_anomalies
from services.claude_service import (
    build_enrich_context, call_enrich_api, apply_enrich_results,
    build_summary_context, call_summary_api,
)
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
            entries_by_id = {e.id: e for e in db_entries}
            raw_anomalies = screen_anomalies(db_entries)

            # Build summary context now — raw_anomalies are plain dicts, no DB insert needed.
            # Fire the Sonnet call immediately so it runs while the main thread handles
            # anomaly insertion and enrichment context building.
            summary_ctx = build_summary_context(db_entries, raw_anomalies)

            from models import Anomaly
            with ThreadPoolExecutor(max_workers=2) as pool:
                summary_future = pool.submit(call_summary_api, summary_ctx)

                # Main thread: insert and load anomalies while Sonnet is running
                for a in raw_anomalies:
                    anomaly = Anomaly(
                        analysis_id=analysis_id,
                        anomaly_type=a["anomaly_type"],
                        explanation=a["explanation"],
                        confidence=a["confidence"],
                    )
                    anomaly.log_entries = [
                        entries_by_id[eid]
                        for eid in a.get("log_entry_ids", [])
                        if eid in entries_by_id
                    ]
                    db.session.add(anomaly)
                db.session.commit()

                db_anomalies = list(
                    Anomaly.query.filter_by(analysis_id=analysis_id)
                    .options(joinedload(Anomaly.log_entries))
                    .all()
                )

                # Build enrich context then fire Haiku — Sonnet is already in flight
                to_enrich, enrich_ctx = build_enrich_context(db_anomalies)
                enrich_future = pool.submit(call_enrich_api, enrich_ctx)

                enriched_items = enrich_future.result()
                analysis.summary = summary_future.result()

            # Apply enrichment results back to ORM objects (main thread)
            apply_enrich_results(to_enrich, enriched_items)

            db.session.commit()
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
