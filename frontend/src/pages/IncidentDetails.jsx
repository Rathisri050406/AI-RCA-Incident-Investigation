import { useEffect, useState } from "react";
import { api } from "../services/api";
import { Badge, Bar, Card, Pct } from "../components/ui";
const TABS = ["Overview", "Investigation Timeline", "Evidence", "Root Cause", "Risk Assessment", "RAG Knowledge", "AI Report", "Response Approval"];

export default function IncidentDetails({ id }) {
  const [inc, setInc] = useState(null); const [tab, setTab] = useState(TABS[0]); const [ev, setEv] = useState(null);
  const [tr, setTr] = useState(null); const [rep, setRep] = useState(null); const [cm, setCm] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const load = async () => {
    const i = await api.incident(id); setInc(i);
    if (i.investigated) { api.evidence(id).then(setEv); api.investigation(id).then(setTr); api.report(id).then(setRep); }
  };
  useEffect(() => { load().catch((e) => setErr(e.message)); }, [id]);
  if (err) return <p className="err">{err}</p>; if (!inc) return <p>Loading...</p>;
  const run = async () => { setBusy(true); try { await api.investigate(id); await load(); } catch (e) { setErr(e.message); } setBusy(false); };
  const decide = async (a) => { await (a ? api.approve : api.reject)(id, cm); await load(); };
  const need = !inc.investigated;
  const ai = inc.ai || {};
  return (<><h2>{inc.code}: {inc.title}</h2>
    <div className="tabs">{TABS.map((t) => <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>{t}</button>)}</div>
    {need && tab !== "Overview" && <div className="warn">Not investigated yet. Open Overview and click "Run investigation".</div>}
    {tab === "Overview" && (<><Card><div className="row"><div>Type<br /><b>{inc.incident_type}</b></div><div>Severity<br /><Badge v={inc.severity} /></div>
      <div>Status<br /><Badge v={inc.status} /></div><div>Detection confidence<br /><b><Pct v={inc.confidence} /></b></div><div>Class<br /><Badge v={inc.classification} /></div>
      <div>Detected at<br />{inc.detected_at}</div><div>Events analysed<br />{inc.event_count}</div></div>
      {need && <p><button disabled={busy} onClick={run}>{busy ? "Investigating..." : "Run investigation"}</button></p>}</Card>
      {inc.rca && (<><Card title="Evidence">{ev?.evidence.map((e) => <div key={e.id}>✓ {e.description}</div>)}</Card>
        <Card title="Root cause"><b>{inc.rca.root_cause}</b> - confidence <Pct v={inc.rca.confidence} /><Bar v={inc.rca.confidence} /></Card>
        <Card title="Risk"><Badge v={inc.risk.level} /> score {inc.risk.score}/100</Card>
        <Card title="AI explanation"><p>{ai.summary}</p><p>{ai.technical_explanation}</p><p className="mut">Provider: {ai.provider}</p></Card></>)}</>)}
    {tab === "Investigation Timeline" && tr && <Card><div className="tl">{tr.trace.map((t, i) => (<div key={i}><b>{t.module}</b> <Badge v={t.status === "completed" ? "low" : "medium"} /> <span className="mut">{t.timestamp}</span>
      <div className="mut">in: {JSON.stringify(t.input)}<br />out: {JSON.stringify(t.output)}</div></div>))}</div><p className="mut">Total time {tr.duration_s}s</p></Card>}
    {tab === "Evidence" && ev && (<><Card>{ev.summary} Evidence strength: <b><Pct v={ev.strength} /></b></Card>
      {ev.evidence.map((e) => (<div className="ev" key={e.id}><b>{e.id}</b> [{e.source}] <Badge v={e.severity} /> conf <Pct v={e.confidence} /><br />{e.description}<br /><span className="mut">{e.timestamp}</span></div>))}</>)}
    {tab === "Root Cause" && inc.rca && (<><Card title={inc.rca.root_cause}>Confidence <Pct v={inc.rca.confidence} /><Bar v={inc.rca.confidence} /><p>{inc.rca.explanation}</p>
      <p className="mut">Supporting evidence: {inc.rca.supporting_evidence.join(", ") || "none"}</p></Card>
      <Card title="Alternative explanations">{inc.rca.alternative_causes.map((a, i) => <p key={i}>• {a.cause}{a.score != null && ` (score ${a.score})`} {a.note && <span className="mut">- {a.note}</span>}</p>)}</Card></>)}
    {tab === "Risk Assessment" && inc.risk && (<Card title={`${inc.risk.level} - ${inc.risk.score}/100`}><p className="mut">{inc.risk.logic}</p>
      <table><tbody>{Object.entries(inc.risk.components).map(([k, v]) => <tr key={k}><td>{k}</td><td style={{ width: "50%" }}><Bar v={v} /></td><td>{v} × weight {inc.risk.weights[k === "strength" ? "strength" : k]}</td></tr>)}</tbody></table></Card>)}
    {tab === "RAG Knowledge" && inc.rag && inc.rag.map((r, i) => <Card key={i} title={r.source}><span className="mut">similarity {r.score}</span><p>{r.text}</p></Card>)}
    {tab === "AI Report" && rep && (<><p><button onClick={() => api.pdf(id)}>Download PDF</button></p>
      <Card title="Incident summary"><p>{ai.summary}</p></Card><Card title="Technical explanation"><p>{ai.technical_explanation}</p><p>{ai.root_cause}</p></Card>
      <Card title="Evidence (facts)">{ai.supporting_evidence?.map((x, i) => <p key={i}>{x}</p>)}</Card><Card title="Risk"><p>{ai.risk_explanation}</p></Card>
      <Card title="Recommended response">{ai.recommended_response?.map((x, i) => <p key={i}>{x}</p>)}</Card>
      <Card title="Limitations">{ai.limitations?.map((x, i) => <p key={i}>• {x}</p>)}</Card>
      <Card title="RAG references">{rep["12_rag_references"].join(", ")}</Card></>)}
    {tab === "Response Approval" && inc.approval && (<Card title="Recommended actions - require human approval"><p>Status: <Badge v={inc.approval.status} /></p>
      {inc.approval.actions?.map((a, i) => <p key={i}>• {a.action}<br /><span className="mut">{a.rationale}</span></p>)}
      {inc.approval.status === "PENDING" ? (<><textarea rows="2" placeholder="Analyst comment (optional)" value={cm} onChange={(e) => setCm(e.target.value)} />
        <p><button className="grn" onClick={() => decide(true)}>APPROVE</button> <button className="red" onClick={() => decide(false)}>REJECT</button></p>
        <p className="mut">Nothing is executed automatically; approval only records the decision.</p></>) : <p className="mut">Decided by {inc.approval.decided_by} at {inc.approval.decided_at}. {inc.approval.comment}</p>}</Card>)}
  </>);
}
