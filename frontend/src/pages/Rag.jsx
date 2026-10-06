import { useState } from "react";
import { api } from "../services/api";
export default function Rag() {
  const [q, setQ] = useState(""); const [r, setR] = useState(null); const [err, setErr] = useState("");
  const go = async (e) => { e.preventDefault(); try { setR(await api.ragSearch(q)); setErr(""); } catch (x) { setErr(x.message); } };
  return (<><h2>RAG Knowledge</h2><form className="card" onSubmit={go}><input placeholder="e.g. how to respond to repeated failed logins" value={q} onChange={(e) => setQ(e.target.value)} /><p><button>Search</button></p></form>
    <p className="err">{err}</p>{r && <p className="mut">Embedding backend: {r.backend}</p>}
    {r?.results.map((x, i) => <div className="card" key={i}><b>{x.source}</b> <span className="mut">score {x.score}</span><p>{x.text}</p></div>)}</>);
}
