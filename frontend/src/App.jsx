import { useState } from "react";
import { hasToken, setToken } from "./services/api";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Incidents from "./pages/Incidents";
import IncidentDetails from "./pages/IncidentDetails";
import Demo from "./pages/Demo";
import Rag from "./pages/Rag";
import Performance from "./pages/Performance";

const NAV = [["dashboard", "Dashboard"], ["demo", "Demo Mode"], ["incidents", "Incidents"], ["rag", "RAG Knowledge"], ["perf", "Model Performance"]];

export default function App() {
  const [auth, setAuth] = useState(hasToken());
  const [page, setPage] = useState("dashboard");
  const [sel, setSel] = useState(null);
  if (!auth) return <Login onDone={() => setAuth(true)} />;
  const open = (id) => { setSel(id); setPage("detail"); };
  return (<div className="app"><nav className="side"><h3>AI-Based Autonomous RCA & Cybersecurity Incident Investigation</h3>
    {NAV.map(([k, l]) => <a key={k} className={page === k || (k === "incidents" && page === "detail") ? "on" : ""} onClick={() => setPage(k)}>{l}</a>)}
    <a onClick={() => { setToken(""); setAuth(false); }}>Logout</a></nav>
    <main className="main">{page === "dashboard" && <Dashboard />}{page === "demo" && <Demo open={open} />}{page === "incidents" && <Incidents open={open} />}
      {page === "detail" && <IncidentDetails id={sel} />}{page === "rag" && <Rag />}{page === "perf" && <Performance />}</main></div>);
}
