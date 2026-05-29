import { useState, useRef, DragEvent, ChangeEvent, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import { colors } from "../theme";

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
        <div style={styles.navBrand}>
          <div style={styles.logoMark}>⬡</div>
          <span style={styles.logoText}>SOC Log Analyzer</span>
        </div>
        <button style={styles.logoutBtn} onClick={logout}>Sign out</button>
      </nav>
      <div style={styles.content}>
        <h2 style={styles.heading}>Upload Log File</h2>
        <p style={styles.hint}>Accepted formats: .log, .txt, .csv &mdash; ZScaler Web Proxy</p>

        <div
          style={{
            ...styles.dropzone,
            borderColor: dragging ? colors.accent : colors.border,
            background: dragging ? colors.accentBg : colors.bgSurface,
            boxShadow: dragging ? `0 0 24px ${colors.accent}33` : "none",
          }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input ref={inputRef} type="file" accept=".log,.txt,.csv" style={{ display: "none" }} onChange={onChange} />
          <div style={styles.uploadIcon}>↑</div>
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
                  <tr key={a.id} style={styles.tr}>
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
  if (status === "done") return { background: colors.successMid, color: colors.success };
  if (status === "error") return { background: colors.dangerMid, color: colors.danger };
  return { background: colors.accentBg, color: colors.accent };
}

const styles: Record<string, React.CSSProperties> = {
  page: { minHeight: "100vh", background: colors.bgPage, fontFamily: "system-ui, sans-serif" },
  nav: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "0 2rem", height: 56,
    background: colors.bgSurface,
    borderBottom: `1px solid ${colors.border}`,
    boxShadow: `0 1px 0 ${colors.border}`,
  },
  navBrand: { display: "flex", alignItems: "center", gap: 10 },
  logoMark: {
    width: 24, height: 24, borderRadius: 5,
    background: `linear-gradient(135deg, ${colors.accent}, ${colors.accentDim})`,
    boxShadow: `0 0 10px ${colors.accent}55`,
    display: "flex", alignItems: "center", justifyContent: "center",
    fontSize: 12, color: colors.bgPage, fontWeight: 900,
  },
  logoText: { color: colors.textPrimary, fontWeight: 700, fontSize: 14 },
  logoutBtn: {
    background: "transparent", border: `1px solid ${colors.border}`,
    color: colors.textMuted, padding: "5px 14px", borderRadius: 6, cursor: "pointer", fontSize: 13,
  },
  content: { maxWidth: 720, margin: "2.5rem auto", padding: "0 1rem" },
  heading: { color: colors.textPrimary, marginBottom: 4, fontSize: 22 },
  hint: { color: colors.textMuted, fontSize: 13, marginBottom: 24 },
  dropzone: {
    border: `2px dashed`, borderRadius: 12, padding: "3rem 2rem",
    textAlign: "center", cursor: "pointer", transition: "all 0.2s",
  },
  uploadIcon: {
    fontSize: 28, color: colors.accent, marginBottom: 12,
    textShadow: `0 0 12px ${colors.accent}88`,
  },
  dropText: { color: colors.textSecondary, fontSize: 16, margin: "0 0 4px" },
  dropSub: { color: colors.textMuted, fontSize: 13, margin: 0 },
  error: { color: colors.danger, fontSize: 13, marginTop: 12 },
  historyBox: { marginTop: 40 },
  historyTitle: { color: colors.textSecondary, fontSize: 13, marginBottom: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: {
    color: colors.textMuted, fontSize: 11, textAlign: "left",
    padding: "8px 12px", borderBottom: `1px solid ${colors.border}`,
    textTransform: "uppercase", letterSpacing: "0.05em",
  },
  tr: { borderBottom: `1px solid ${colors.border}` },
  td: { color: colors.textSecondary, fontSize: 14, padding: "10px 12px" },
  badge: { padding: "2px 8px", borderRadius: 4, fontSize: 12, fontWeight: 600 },
  viewBtn: {
    background: colors.accentBg, color: colors.accent,
    border: `1px solid ${colors.accent}55`,
    padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 12, fontWeight: 600,
  },
};
