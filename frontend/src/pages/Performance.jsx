import { useEffect, useState } from "react";
import { api, apiBase } from "../services/api";
import { Card } from "../components/ui";
const f = (v) => (typeof v === "number" ? v.toFixed(4) : v ?? "-");
export default function Performance() {
  const [m, setM] = useState(null); const [e, setE] = useState(null); const [err, setErr] = useState("");
  useEffect(() => { api.mlMetrics().then(setM).catch((x) => setErr(x.message)); api.evalResults().then(setE).catch(() => {}); }, []);
  if (!m) return <p>{err || "Loading..."}</p>;
  const cols = ["accuracy", "precision", "recall", "f1", "roc_auc", "false_positive_rate"];
  return (<><h2>Model Performance</h2>
    {m.warning && <div className="warn">{m.warning} Train on CIC-IDS2017 with scripts/train_detector.py for meaningful numbers.</div>}
    <Card title={`Test-set metrics (data: ${m.data_source}; train ${m.n_train}, test ${m.n_test})`}>
      <table><thead><tr><th>Model</th>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead><tbody>
        {Object.entries(m.results).map(([n, r]) => <tr key={n}><td>{n}</td>{cols.map((c) => <td key={c}>{f(r[c])}</td>)}</tr>)}</tbody></table></Card>
    <div className="row">{["confusion_matrix", "class_distribution", "feature_importance", "metrics"].map((p) => <img key={p} className="plot" style={{ width: 340 }} src={`${apiBase}/static/plots/${p}.png`} alt={p} />)}</div>
    <h2 style={{ marginTop: 20 }}>System comparison</h2>
    {e ? (<Card title={`A: ML-only · B: detection + rule-based · C: proposed (${e.seeds_per_scenario} seeds × 5 synthetic scenarios)`}><table><thead><tr><th>System</th><th>Detection acc.</th><th>False-pos. rate</th><th>RCA acc.</th><th>Evidence coverage</th><th>Report completeness</th><th>Avg time (s)</th></tr></thead><tbody>
      {Object.entries(e.systems).map(([k, s]) => <tr key={k}><td>{k}</td><td>{f(s.detection_accuracy)}</td><td>{f(s.false_positive_rate)}</td><td>{f(s.rca_accuracy)}</td><td>{f(s.evidence_coverage)}</td><td>{f(s.report_completeness)}</td><td>{f(s.avg_time_s)}</td></tr>)}</tbody></table>
      <p className="mut">{e.note}</p></Card>) : <p className="mut">Run <code>python scripts/evaluate_investigation.py</code> to generate comparison results.</p>}</>);
}
