import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { Card } from "../components/ui";
const COLORS = ["#2b5fd9", "#e0662b", "#2e9e5b", "#c9302c", "#d79a1c", "#7a5af8"];
const Pie1 = ({ data }) => (<ResponsiveContainer width="100%" height={220}><PieChart><Pie data={data} dataKey="value" nameKey="name" outerRadius={75} label>
  {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}</Pie><Tooltip /><Legend /></PieChart></ResponsiveContainer>);
export default function Dashboard() {
  const [s, setS] = useState(null); const [m, setM] = useState(null);
  useEffect(() => { api.stats().then(setS); api.mlMetrics().then(setM).catch(() => {}); }, []);
  if (!s) return <p>Loading...</p>;
  const cards = [["Total Incidents", s.total], ["Active Incidents", s.active], ["High Risk", s.high_risk], ["Critical", s.critical], ["Resolved", s.resolved]];
  const det = m ? Object.entries(m.results).map(([k, r]) => ({ name: k.split(" ")[0], F1: +r.f1.toFixed(3), Recall: +r.recall.toFixed(3), Precision: +r.precision.toFixed(3) })) : [];
  return (<><h2>Dashboard</h2>
    <div className="row">{cards.map(([n, v]) => <div key={n} className="card stat"><b>{v}</b><span>{n}</span></div>)}</div>
    <div className="row">
      <div className="card" style={{ flex: 2, minWidth: 300 }}><h3>Incidents over time</h3><ResponsiveContainer width="100%" height={220}>
        <LineChart data={s.over_time}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="date" /><YAxis allowDecimals={false} /><Tooltip /><Line dataKey="count" stroke="#2b5fd9" /></LineChart></ResponsiveContainer></div>
      <div className="card" style={{ flex: 1, minWidth: 260 }}><h3>Severity distribution</h3><Pie1 data={s.severity} /></div></div>
    <div className="row">
      <div className="card" style={{ flex: 1, minWidth: 260 }}><h3>Incident types</h3><Pie1 data={s.types} /></div>
      <div className="card" style={{ flex: 1, minWidth: 260 }}><h3>Investigation status</h3><Pie1 data={s.status} /></div>
      <div className="card" style={{ flex: 2, minWidth: 300 }}><h3>Detection performance (test set){m?.warning && <span className="mut"> - synthetic data</span>}</h3>
        <ResponsiveContainer width="100%" height={220}><BarChart data={det}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="name" /><YAxis domain={[0, 1]} /><Tooltip /><Legend />
          <Bar dataKey="Precision" fill="#2b5fd9" /><Bar dataKey="Recall" fill="#2e9e5b" /><Bar dataKey="F1" fill="#e0662b" /></BarChart></ResponsiveContainer></div></div></>);
}
