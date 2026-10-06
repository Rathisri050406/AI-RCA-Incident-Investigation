export const Badge = ({ v }) => <span className={`badge ${String(v || "").toLowerCase()}`}>{String(v ?? "-").toUpperCase()}</span>;
export const Pct = ({ v }) => <>{v == null ? "-" : `${Math.round(v * 100)}%`}</>;
export const Bar = ({ v }) => <div className="bar"><i style={{ width: `${Math.round((v || 0) * 100)}%` }} /></div>;
export const Card = ({ title, children }) => <div className="card">{title && <h3 style={{ marginTop: 0 }}>{title}</h3>}{children}</div>;
