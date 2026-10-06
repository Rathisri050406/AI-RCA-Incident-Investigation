import { useState } from "react";
import { api, setToken } from "../services/api";
export default function Login({ onDone }) {
  const [u, setU] = useState("admin"); const [p, setP] = useState(""); const [err, setErr] = useState("");
  const go = async (e) => { e.preventDefault(); try { const r = await api.login(u, p); setToken(r.access_token); onDone(); } catch (x) { setErr(x.message); } };
  return (<div className="login card"><h2>Analyst Login</h2><p className="mut">AI-Based Autonomous Root-Cause Analysis and Cybersecurity Incident Investigation</p>
    <form onSubmit={go}><p><input value={u} onChange={(e) => setU(e.target.value)} placeholder="Username" /></p>
      <p><input type="password" value={p} onChange={(e) => setP(e.target.value)} placeholder="Password" /></p>
      <button>Sign in</button><p className="err">{err}</p></form></div>);
}
