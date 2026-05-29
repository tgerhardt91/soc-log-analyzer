# SOC Log Analyzer

Full-stack web app for uploading, parsing, and AI-analyzing ZScaler Web Proxy logs. Built as a take-home interview project.

## Stack
- **Frontend**: React 18 + Vite + TypeScript (in `frontend/`)
- **Backend**: Python 3.12 + Flask (in `backend/`)
- **Database**: PostgreSQL 16
- **AI**: Anthropic Claude API (`claude-sonnet-4-6`)

## Running the app

### Docker (recommended)
```bash
cp backend/.env.example backend/.env  # fill in ANTHROPIC_API_KEY and JWT_SECRET
docker compose up --build
# App at http://localhost  |  Backend exposed on host at :5001
```

### Local dev (no Docker)
Start backend and frontend separately — see `backend/CLAUDE.md` and `frontend/CLAUDE.md`.

## Project structure
```
soc-log-analyzer/
├── backend/          # Flask API
├── frontend/         # React + Vite SPA
├── sample_logs/      # sample_zscaler.log (534 entries, 5 seeded anomalies)
├── docker-compose.yml
└── README.md
```

## How a log upload flows end-to-end
1. User POSTs a `.log`, `.txt`, or `.csv` file → `POST /api/upload`
2. Flask saves the file and spawns a background thread
3. Thread: parse log → bulk insert `log_entries` → rule-based anomaly screening → Claude enrichment → update analysis status to `done`
4. Frontend polls `GET /api/analyses/<id>` every 2 seconds until status is `done`

## Sample log
`sample_logs/sample_zscaler.log` — pipe-delimited ZScaler NSS format, 534 entries across one business day. Contains 5 seeded anomalies: IP spike, large upload (data exfil), blocked malware, off-hours access, rare unknown domain. Regenerate with `python3 sample_logs/generate_sample.py`.

## Auth
Single hardcoded user via `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars. Login returns a 24-hour JWT stored in `localStorage`. All `/api/*` routes except `/api/auth/login` require a `Bearer` token.
