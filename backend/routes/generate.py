import os
import uuid
import threading
from flask import Blueprint, request, jsonify, current_app
from models import db, Analysis
from routes.auth import require_jwt
from routes.upload import _process
from services.log_generator import generate_log, generate_preview, _SEEDERS
import config

generate_bp = Blueprint("generate", __name__)


@generate_bp.route("/preview-sample", methods=["POST"])
@require_jwt
def preview_sample():
    body = request.get_json(silent=True) or {}
    requested = body.get("anomaly_types", [])
    anomaly_types = [t for t in requested if t in _SEEDERS] or list(_SEEDERS.keys())
    return jsonify(generate_preview(anomaly_types))


@generate_bp.route("/generate-sample", methods=["POST"])
@require_jwt
def generate_sample():
    body = request.get_json(silent=True) or {}
    requested = body.get("anomaly_types", [])
    anomaly_types = [t for t in requested if t in _SEEDERS]
    if not anomaly_types:
        anomaly_types = list(_SEEDERS.keys())

    analysis_id = str(uuid.uuid4())
    short_label = "_".join(sorted(anomaly_types)[:3])
    filename = f"generated_{short_label}.log"
    filepath = os.path.join(config.UPLOAD_DIR, f"{analysis_id}_{filename}")

    content = generate_log(anomaly_types)
    with open(filepath, "w") as f:
        f.write(content)

    analysis = Analysis(id=analysis_id, filename=filename, status="pending")
    db.session.add(analysis)
    db.session.commit()

    app = current_app._get_current_object()
    threading.Thread(target=_process, args=(app, analysis_id, filepath), daemon=True).start()

    return jsonify({"analysis_id": analysis_id}), 202
