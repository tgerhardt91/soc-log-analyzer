# Frontend — React + Vite + TypeScript

## Dev setup
```bash
npm install
npm run dev     # dev server at http://localhost:5173
```

Vite proxies `/api/*` to `http://localhost:5000` (see `vite.config.ts`), so the backend must be running. Easiest: `docker compose up db backend` from the repo root, then `npm run dev` here.

```bash
npm run build   # production build → dist/
```

## Key files
| File | Purpose |
|------|---------|
| `src/api/client.ts` | Axios instance — injects `Authorization: Bearer <token>` on every request; redirects to `/login` on 401 |
| `src/App.tsx` | Router setup; `RequireAuth` wrapper redirects unauthenticated users to `/login` |
| `src/pages/LoginPage.tsx` | POSTs credentials, stores JWT in `localStorage` |
| `src/pages/UploadPage.tsx` | Drag-and-drop file upload; shows past analyses list |
| `src/pages/AnalysisPage.tsx` | Polls `GET /api/analyses/<id>` every 2s until `status === "done"`, then renders the dashboard |
| `src/components/SummaryCards.tsx` | Metric cards (total events, blocked %, anomaly count, time range) + Claude summary paragraph |
| `src/components/Timeline.tsx` | Recharts `BarChart` of request volume by hour (total + blocked) |
| `src/components/AnomalyPanel.tsx` | Collapsible list of anomalies with confidence badge and log entry detail |
| `src/components/LogTable.tsx` | Paginated, filterable events table; anomalous rows highlighted with dark red background |

## Routing
- `/login` — public
- `/` — upload page (requires auth)
- `/analysis/:id` — analysis dashboard (requires auth)

## Styling
Plain inline styles (`React.CSSProperties`) throughout — no CSS files or CSS-in-JS library. Dark theme: background `#0f172a`, surface `#1e293b`, text `#f1f5f9` / `#cbd5e1` / `#94a3b8`.

## Environment variables
Set `VITE_API_URL` to point at a non-local backend (e.g. for cloud deployment). When unset, all `/api` requests go to the same origin (which Vite proxies in dev, and Nginx proxies in the Docker build).
