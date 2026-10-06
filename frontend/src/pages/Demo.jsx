import { useEffect, useState } from "react";
import { api } from "../services/api";
export default function Demo({ open }) {
  const [sc, setSc] = useState({}); const [busy, setBusy] = useState(""); const [err, setErr] = useState("");
  useEffect(() => { api.scenarios().then(setSc); }, []);
  const run = async (k) => { setBusy(k); setErr(""); try { const r = await api.runDemo(k, Math.floor(Math.random() * 1000)); open(r.id); } catch (e) { setErr(e.message); } setBusy(""); };
  return (<><h2>Demo Mode</h2><p className="mut">Generates safe SYNTHETIC events, then runs detection → investigation → correlation → RCA → risk → RAG → GenAI → report.</p>
    <div className="row">{Object.entries(sc).map(([k, v]) => (<div className="card stat" key={k}><b style={{ fontSize: 16 }}>{v}</b><p><button disabled={!!busy} onClick={() => run(k)}>{busy === k ? "Running..." : "Run scenario"}</button></p></div>))}</div><p className="err">{err}</p></>);
}
