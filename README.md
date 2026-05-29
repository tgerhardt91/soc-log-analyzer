# SOC Log Analyzer

A full-stack web application that allows SOC analysts to upload ZScaler Web Proxy log files, parses them, and displays the results in a human-consumable format with AI-powered anomaly detection.

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite + TypeScript |
| Backend | Python 3.12 + Flask |
| Database | PostgreSQL 16 |
| AI | Anthropic Claude (`claude-sonnet-4-6`) |

## Features

- **Secure login** — JWT-based authentication with credentials stored in environment variables
- **Log upload** — drag-and-drop or file picker; accepts `.log`, `.txt` (pipe-delimited), and `.csv` formats
- **SOC dashboard** — summary cards, hourly request timeline chart, filterable/sortable events table
- **AI summary** — Claude generates a 3–5 sentence executive summary for the SOC analyst
- **Anomaly detection** — rule-based pre-screening + Claude enrichment with explanations and confidence scores

---

## Running locally with Docker

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- An [Anthropic API key](https://console.anthropic.com/)

### 1. Clone and configure

```bash
git clone <repo-url>
cd soc-log-analyzer

cp backend/.env.example backend/.env
```

Edit `backend/.env`:

```
ADMIN_USERNAME=admin
ADMIN_PASSWORD=yourpassword
JWT_SECRET=any-long-random-string
DATABASE_URL=postgresql://soc:soc@db:5432/socdb   # keep this for Docker
ANTHROPIC_API_KEY=sk-ant-...
UPLOAD_DIR=./uploads
CORS_ALLOWED_ORIGINS=http://localhost
```

### 2. Start the application

```bash
docker compose up --build
```

The app will be available at **http://localhost**.

### 3. Log in

Use the credentials you set in `.env`. The default in `.env.example` is `admin` / `changeme`.

### 4. Upload a sample log

Upload `sample_logs/sample_zscaler.log`. The file contains 534 entries spanning one business day with five seeded anomalies. Processing takes 10–30 seconds depending on Claude API latency.

---

## Running locally without Docker

### Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env  # edit as above; set DATABASE_URL to your local Postgres

mkdir -p uploads
python app.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend dev server runs at http://localhost:5173 and proxies `/api` to Flask on port 5000.

---

## AI approach

### Where AI is used

#### 1. SOC Executive Summary (`services/claude_service.py → generate_summary`)

After all log entries are parsed, aggregate statistics are sent to Claude:
- Time range, total events, blocked %, top source IPs, top destinations, top categories
- A sample of the 20 highest-risk entries

Claude returns a 3–5 sentence summary written for a SOC analyst, highlighting the most important findings and recommending follow-up actions.

#### 2. Anomaly Enrichment (`services/claude_service.py → enrich_anomalies`)

Before calling Claude, a rule-based engine (`services/anomaly.py`) flags candidate anomalies using deterministic rules:

| Rule | Trigger |
|------|---------|
| `ip_spike` | Same source IP makes >50 requests in any 5-minute window |
| `data_exfil` | Single request with >10 MB bytes sent |
| `off_hours` | Request timestamp between 11 PM and 5 AM |
| `blocked_threat` | ZScaler action = Blocked AND threat name is populated |
| `rare_destination` | Domain appears only once in the entire log AND category is Unknown |

Each flagged anomaly (with the original log entry context) is then sent to Claude, which:
- Rewrites the explanation in clear analyst-friendly language
- Assigns a confidence score (0.0–1.0)

### Model

`claude-sonnet-4-6` — strong reasoning quality with fast output, well-suited for structured JSON responses.

### Prompt caching

The analyst system prompt is marked with `cache_control: ephemeral` so it is cached between the summary and enrichment API calls, reducing token cost and latency.

---

## Log format

The application targets **ZScaler NSS (Nano Streaming Service)** pipe-delimited export format:

```
timestamp|username|src_ip|dst_url|category|action|bytes_sent|bytes_received|method|response_code|user_agent|threat_name|duration_ms
```

CSV files with the same column names are also accepted.

---

## Cloud deployment (bonus)

| Layer | Service |
|-------|---------|
| Frontend | Vercel (set `VITE_API_URL` env var) |
| Backend | Google Cloud Run |
| Database | Cloud SQL or Supabase |
| File storage | Google Cloud Storage (set `UPLOAD_BACKEND=gcs` and `GCS_BUCKET_NAME`) |

The backend is fully stateless and container-ready. No code changes are needed — only environment variable updates.

---

## Project structure

```
soc-log-analyzer/
├── backend/
│   ├── app.py                  # Flask factory + startup
│   ├── config.py               # Env var loading
│   ├── models.py               # SQLAlchemy models (analyses, log_entries, anomalies)
│   ├── routes/
│   │   ├── auth.py             # POST /api/auth/login + @require_jwt decorator
│   │   ├── upload.py           # POST /api/upload + background processing thread
│   │   └── analyses.py         # GET /api/analyses, GET /api/analyses/<id>
│   └── services/
│       ├── parser.py           # ZScaler log parser (pipe-delimited + CSV)
│       ├── anomaly.py          # Rule-based anomaly pre-screening
│       └── claude_service.py   # Anthropic Claude API integration
├── frontend/
│   └── src/
│       ├── api/client.ts       # Axios instance with JWT injection + 401 redirect
│       ├── pages/
│       │   ├── LoginPage.tsx
│       │   ├── UploadPage.tsx
│       │   └── AnalysisPage.tsx
│       └── components/
│           ├── SummaryCards.tsx   # Metric cards + AI summary
│           ├── Timeline.tsx       # Recharts hourly bar chart
│           ├── AnomalyPanel.tsx   # Collapsible anomaly list with confidence badges
│           └── LogTable.tsx       # Filterable/paginated events table
├── sample_logs/
│   ├── generate_sample.py      # Script to regenerate the sample log
│   └── sample_zscaler.log      # 534-entry sample with 5 seeded anomalies
└── docker-compose.yml
```
