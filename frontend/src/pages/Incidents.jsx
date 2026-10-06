import { useEffect, useState } from "react";
import { api } from "../services/api";
import { Badge, Pct } from "../components/ui";
export default function Incidents({ open }) {
  const [rows, setRows] = useState([]); const [err, setErr] = useState("");
  const load = () => api.incidents().then(setRows);
  useEffect(() => { load(); }, []);
  const up = async (e) => { try { const i = await api.upload(e.target.files[0]); open(i.id); } catch (x) { setErr(x.message); } };
  return (<><h2>Incidents</h2><div className="card"><b>Upload custom CSV</b> <span className="mut">(flow features or log events)</span>
    <p><input type="file" accept=".csv" onChange={up} /></p><span className="err">{err}</span></div>
    <div className="card"><table><thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Severity</th><th>Class</th><th>Conf.</th><th>Status</th></tr></thead><tbody>
      {rows.map((r) => (<tr key={r.id} className="click" onClick={() => open(r.id)}><td>{r.code}</td><td>{r.title}</td><td>{r.incident_type}</td>
        <td><Badge v={r.severity} /></td><td><Badge v={r.classification} /></td><td><Pct v={r.confidence} /></td><td><Badge v={r.status} /></td></tr>))}
      {!rows.length && <tr><td colSpan="7" className="mut">No incidents yet. Run a scenario from Demo Mode.</td></tr>}</tbody></table></div></>);
}
