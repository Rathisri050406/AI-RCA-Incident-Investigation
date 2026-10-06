const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
export const apiBase = BASE;
let token = sessionStorage.getItem("token") || "";
export const setToken = (t) => { token = t; t ? sessionStorage.setItem("token", t) : sessionStorage.removeItem("token"); };
export const hasToken = () => !!token;

async function call(path, opts = {}) {
  const res = await fetch(BASE + path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(opts.headers || {}) },
  });
  if (res.status === 401 && path !== "/api/auth/login") { setToken(""); window.location.reload(); }
  if (!res.ok) { let d = ""; try { d = (await res.json()).detail; } catch {} throw new Error(d || res.statusText); }
  return res;
}
const json = async (p, o) => (await call(p, o)).json();
const post = (p, b) => json(p, { method: "POST", body: JSON.stringify(b || {}) });

export const api = {
  login: (username, password) => post("/api/auth/login", { username, password }),
  stats: () => json("/api/dashboard/statistics"),
  incidents: () => json("/api/incidents"),
  incident: (id) => json(`/api/incidents/${id}`),
  investigate: (id) => post(`/api/incidents/${id}/investigate`),
  investigation: (id) => json(`/api/incidents/${id}/investigation`),
  evidence: (id) => json(`/api/incidents/${id}/evidence`),
  report: (id) => json(`/api/incidents/${id}/report`),
  approve: (id, comment) => post(`/api/incidents/${id}/approve`, { comment }),
  reject: (id, comment) => post(`/api/incidents/${id}/reject`, { comment }),
  ragSearch: (query) => post("/api/rag/search", { query, k: 4 }),
  scenarios: () => json("/api/demo/scenarios"),
  runDemo: (scenario, seed) => post("/api/demo/run", { scenario, seed }),
  mlMetrics: () => json("/api/ml/metrics"),
  evalResults: () => json("/api/evaluation/results"),
  upload: async (file) => { const f = new FormData(); f.append("file", file);
    const r = await fetch(BASE + "/api/incidents/upload", { method: "POST", body: f, headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) throw new Error((await r.json()).detail || "Upload failed"); return r.json(); },
  pdf: async (id) => { const r = await call(`/api/incidents/${id}/report?format=pdf`); const b = await r.blob();
    const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = `INC-${String(id).padStart(3, "0")}.pdf`; a.click(); },
};
