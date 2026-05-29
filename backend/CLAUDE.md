# Backend — Python/Flask

## Dev setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in values

mkdir -p uploads
python app.py          # runs on :5000
```

Postgres must be running. Easiest way: `docker compose up db` from the repo root (starts only the DB).

## Key files
| File | Purpose |
|------|---------|
| `app.py` | Flask factory — registers blueprints, calls `db.create_all()` on startup |
| `config.py` | Loads all env vars; import this instead of `os.environ` directly |
| `models.py` | SQLAlchemy models: `Analysis`, `LogEntry`, `Anomaly` |
| `routes/auth.py` | `POST /api/auth/login` + `@require_jwt` decorator |
| `routes/upload.py` | `POST /api/upload` — saves file, spawns background thread |
| `routes/analyses.py` | `GET /api/analyses` (list) and `GET /api/analyses/<id>` (full detail + pagination + filtering) |
| `services/parser.py` | Parses pipe-delimited and CSV log files into dicts for bulk insert |
| `services/anomaly.py` | Rule-based pre-screening (ip_spike, data_exfil, off_hours, blocked_threat, rare_destination) |
| `services/claude_service.py` | Calls Claude API: `generate_summary()` and `enrich_anomalies()` |

## Processing pipeline (background thread in `routes/upload.py`)
```
save file → parse_log_file() → bulk insert LogEntry rows
         → screen_anomalies() → insert Anomaly rows
         → enrich_anomalies() → Claude enriches explanations + confidence
         → generate_summary() → Claude writes SOC summary
         → analysis.status = "done"
```

## API routes
| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/api/auth/login` | None | Returns JWT |
| POST | `/api/upload` | JWT | Multipart file; returns `analysis_id` immediately |
| GET | `/api/analyses` | JWT | List, ordered by `created_at` desc |
| GET | `/api/analyses/<id>` | JWT | Paginated entries (`?page=&per_page=`), filters (`?action=&category=&username=`), timeline, anomalies |

## Environment variables
See `.env.example`. Key ones:
- `ANTHROPIC_API_KEY` — required for Claude calls
- `JWT_SECRET` — any long random string
- `DATABASE_URL` — postgres connection string
- `UPLOAD_DIR` — where uploaded files are saved (default `./uploads`)
- `CORS_ALLOWED_ORIGINS` — comma-separated list of allowed frontend origins
