import { useState, useRef, DragEvent, ChangeEvent, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";

type Analysis = { id: string; filename: string; status: string; created_at: string };

export default function UploadPage() {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<Analysis[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.get("/api/analyses").then((r) => setHistory(r.data)).catch(() => {});
  }, []);

  async function upload(file: File) {
    setError("");
    setUploading(true);
    try {
      const form = new FormData();
      form.append("file", file);
      const { data } = await api.post("/api/upload", form);
      navigate(`/analysis/${data.analysis_id}`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg ?? "Upload failed.");
    } finally {
      setUploading(false);
    }
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) upload(file);
  }

  function onChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) upload(file);
  }

  function logout() {
    localStorage.removeItem("token");
    navigate("/login");
  }

  return (
    <div style={styles.page}>
      <nav style={styles.nav}>
        <span style={styles.brand}>SOC Log Analyzer</span>
        <button style={styles.logoutBtn} onClick={logout}>Sign out</button>
      </nav>
      <div style={styles.content}>
        <h2 style={styles.heading}>Upload Log File</h2>
        <p style={styles.hint}>Accepted formats: .log, .txt, .csv (ZScaler Web Proxy)</p>

        <div
          style={{
            ...styles.dropzone,
            borderColor: dragging ? "#3b82f6" : "#334155",
            background: dragging ? "#1e3a5f" : "#1e293b",
          }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input ref={inputRef} type="file" accept=".log,.txt,.csv" style={{ display: "none" }} onChange={onChange} />
          {uploading
            ? <p style={styles.dropText}>Uploading and processing…</p>
            : <>
                <p style={styles.dropText}>Drop your log file here</p>
                <p style={styles.dropSub}>or click to browse</p>
              </>
          }
        </div>

        {error && <p style={styles.error}>{error}</p>}

        {history.length > 0 && (
          <div style={styles.historyBox}>
            <h3 style={styles.historyTitle}>Previous Uploads</h3>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>File</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Uploaded</th>
                  <th style={styles.th}></th>
                </tr>
              </thead>
              <tbody>
                {history.map((a) => (
                  <tr key={a.id}>
                    <td style={styles.td}>{a.filename}</td>
                    <td style={styles.td}>
                      <span style={{ ...styles.badge, ...statusColor(a.status) }}>{a.status}</span>
                    </td>
                    <td style={styles.td}>{new Date(a.created_at).toLocaleString()}</td>
                    <td style={styles.td}>
                      {a.status === "done" && (
                        <button style={styles.viewBtn} onClick={() => navigate(`/analysis/${a.id}`)}>
                          View
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function statusColor(status: string): React.CSSProperties {
  if (status === "done") return { background: "#166534", color: "#86efac" };
  if (status === "error") return { background: "#7f1d1d", color: "#fca5a5" };
  return { background: "#1e3a5f", color: "#93c5fd" };
}

const styles: Record<string, React.CSSProperties> = {
  page: { minHeight: "100vh", background: "#0f172a", fontFamily: "system-ui, sans-serif" },
  nav: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "1rem 2rem", background: "#1e293b", borderBottom: "1px solid #334155" },
  brand: { color: "#f1f5f9", fontWeight: 700, fontSize: 18 },
  logoutBtn: { background: "transparent", border: "1px solid #475569", color: "#94a3b8", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  content: { maxWidth: 720, margin: "2rem auto", padding: "0 1rem" },
  heading: { color: "#f1f5f9", marginBottom: 4 },
  hint: { color: "#64748b", fontSize: 13, marginBottom: 24 },
  dropzone: { border: "2px dashed", borderRadius: 12, padding: "3rem 2rem", textAlign: "center", cursor: "pointer", transition: "all 0.2s" },
  dropText: { color: "#cbd5e1", fontSize: 16, margin: "0 0 4px" },
  dropSub: { color: "#64748b", fontSize: 13, margin: 0 },
  error: { color: "#f87171", fontSize: 13, marginTop: 12 },
  historyBox: { marginTop: 40 },
  historyTitle: { color: "#94a3b8", fontSize: 15, marginBottom: 12, fontWeight: 600 },
  table: { width: "100%", borderCollapse: "collapse" },
  th: { color: "#64748b", fontSize: 12, textAlign: "left", padding: "8px 12px", borderBottom: "1px solid #1e293b", textTransform: "uppercase", letterSpacing: "0.05em" },
  td: { color: "#cbd5e1", fontSize: 14, padding: "10px 12px", borderBottom: "1px solid #1e293b" },
  badge: { padding: "2px 8px", borderRadius: 4, fontSize: 12, fontWeight: 600 },
  viewBtn: { background: "#1d4ed8", color: "#fff", border: "none", padding: "5px 12px", borderRadius: 6, cursor: "pointer", fontSize: 12 },
};
