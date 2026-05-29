import uuid
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

anomaly_log_entries = db.Table(
    "anomaly_log_entries",
    db.Column("anomaly_id", db.String(36), db.ForeignKey("anomalies.id"), primary_key=True),
    db.Column("log_entry_id", db.String(36), db.ForeignKey("log_entries.id"), primary_key=True),
)


def _uuid():
    return str(uuid.uuid4())


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    filename = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    summary = db.Column(db.Text)
    total_events = db.Column(db.Integer)
    blocked_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    entries = db.relationship("LogEntry", back_populates="analysis", cascade="all, delete-orphan")
    anomalies = db.relationship("Anomaly", back_populates="analysis", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "status": self.status,
            "summary": self.summary,
            "total_events": self.total_events,
            "blocked_count": self.blocked_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LogEntry(db.Model):
    __tablename__ = "log_entries"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False)
    timestamp = db.Column(db.DateTime)
    username = db.Column(db.Text)
    src_ip = db.Column(db.Text)
    dst_url = db.Column(db.Text)
    dst_hostname = db.Column(db.Text)
    category = db.Column(db.Text)
    action = db.Column(db.Text)
    bytes_sent = db.Column(db.Integer, default=0)
    bytes_received = db.Column(db.Integer, default=0)
    http_method = db.Column(db.Text)
    response_code = db.Column(db.Integer)
    user_agent = db.Column(db.Text)
    threat_name = db.Column(db.Text)

    analysis = db.relationship("Analysis", back_populates="entries")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "username": self.username,
            "src_ip": self.src_ip,
            "dst_url": self.dst_url,
            "dst_hostname": self.dst_hostname,
            "category": self.category,
            "action": self.action,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "http_method": self.http_method,
            "response_code": self.response_code,
            "user_agent": self.user_agent,
            "threat_name": self.threat_name,
        }


class Anomaly(db.Model):
    __tablename__ = "anomalies"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False)
    anomaly_type = db.Column(db.Text)
    explanation = db.Column(db.Text)
    confidence = db.Column(db.Float)

    analysis = db.relationship("Analysis", back_populates="anomalies")
    log_entries = db.relationship("LogEntry", secondary=anomaly_log_entries)

    def to_dict(self):
        return {
            "id": self.id,
            "anomaly_type": self.anomaly_type,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "log_entries": [e.to_dict() for e in self.log_entries],
        }
