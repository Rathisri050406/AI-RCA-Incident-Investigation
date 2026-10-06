"""Safe SYNTHETIC scenario generator (no real attacks, no real systems)."""
from datetime import datetime, timedelta
import numpy as np
from backend.ml.data_loader import make_benign_flows, make_attack_flows

SCENARIOS = {
    "normal": "Normal activity",
    "failed_logins": "Repeated failed logins",
    "suspicious_network": "Suspicious network activity",
    "db_failure": "Application/database failure",
    "multi_stage": "Multiple correlated security events",
}
EXPECTED_ROOT_CAUSE = {  # ground truth for evaluation
    "normal": "none", "failed_logins": "brute_force", "suspicious_network": "port_scan",
    "db_failure": "database_failure", "multi_stage": "compromised_account",
}
EXPECTED_EVIDENCE = {
    "normal": [], "failed_logins": ["auth_failures", "high_rate"],
    "suspicious_network": ["port_scan", "ml_malicious_flows"],
    "db_failure": ["db_timeouts", "app_errors"],
    "multi_stage": ["auth_failures", "success_after_failures", "port_scan", "ml_malicious_flows"],
}
USERS = ["alice", "bob", "carol", "dave", "erin", "admin", "svc_backup", "guest"]


class _B:
    def __init__(self, start):
        self.events, self.t = [], start

    def add(self, offset_s, **kw):
        e = {"id": f"E{len(self.events) + 1:04d}",
             "timestamp": (self.t + timedelta(seconds=float(offset_s))).isoformat(timespec="seconds")}
        e.update(kw)
        self.events.append(e)


def _flows(b, rng, kind, n, src, t0, spread):
    df = make_benign_flows(n, rng) if kind == "benign" else make_attack_flows(kind, n, rng)
    for i, row in enumerate(df.drop(columns=["label"]).to_dict("records")):
        row = {k: float(v) for k, v in row.items()}
        b.add(t0 + i * spread, src_ip=src, dst_ip="10.0.0.5", dst_port=int(row["dst_port"]),
              event_type="flow", flow=row, message=f"{kind} flow")


def _auth_fail(b, rng, src, n, t0, window, users):
    for _ in range(n):
        u = users[int(rng.integers(len(users)))]
        b.add(t0 + float(rng.uniform(0, window)), src_ip=src, dst_ip="10.0.0.10", dst_port=22,
              event_type="auth_failure", user=u, message=f"Failed password for {u}")


def _normal_background(b, rng, n=40):
    for _ in range(n):
        u = USERS[int(rng.integers(5))]
        b.add(float(rng.uniform(0, 3500)), src_ip=f"192.168.1.{int(rng.integers(10, 50))}", dst_ip="10.0.0.10",
              dst_port=443, event_type="auth_success", user=u, message=f"Accepted password for {u}")
    for _ in range(int(rng.integers(1, 3))):
        b.add(float(rng.uniform(0, 3500)), src_ip="192.168.1.20", dst_ip="10.0.0.10", dst_port=22,
              event_type="auth_failure", user="bob", message="Failed password for bob")
    _flows(b, rng, "benign", 15, "192.168.1.30", 0, 200)


def generate_scenario(name, seed=0):
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario {name}")
    rng = np.random.default_rng(seed)
    b = _B(datetime(2026, 3, 14, 2, 0, 0))
    _normal_background(b, rng)
    atk = f"203.0.113.{int(rng.integers(10, 250))}"   # TEST-NET-3 documentation range
    if name == "failed_logins":
        n = int(rng.integers(300, 600))
        _auth_fail(b, rng, atk, n, 600, 240, ["admin"] if False else ["admin", "alice"])
        for i in range(int(rng.integers(60, 120))):
            b.add(600 + i * 2.5, src_ip=atk, dst_ip="10.0.0.10", dst_port=22, event_type="http_request",
                  message="POST /login")
    elif name == "suspicious_network":
        _flows(b, rng, "portscan", int(rng.integers(40, 80)), atk, 900, 1.0)
        for p in rng.choice(np.arange(1, 10000), 40, replace=False):
            b.add(900 + float(rng.uniform(0, 60)), src_ip=atk, dst_ip="10.0.0.5", dst_port=int(p),
                  event_type="connection", message="SYN probe")
    elif name == "db_failure":
        for i in range(int(rng.integers(25, 50))):
            b.add(1200 + i * 6, src_ip="10.0.0.20", dst_ip="10.0.0.30", dst_port=5432, event_type="db_timeout",
                  message="Database query timeout after 30000 ms", latency_ms=int(rng.integers(20000, 45000)))
        for i in range(int(rng.integers(15, 30))):
            b.add(1210 + i * 9, src_ip="10.0.0.20", dst_ip="10.0.0.20", dst_port=8000, event_type="app_error",
                  message="Application error: connection pool exhausted")
    elif name == "multi_stage":
        _flows(b, rng, "portscan", int(rng.integers(40, 70)), atk, 600, 1.0)
        for p in rng.choice(np.arange(1, 10000), 30, replace=False):
            b.add(600 + float(rng.uniform(0, 60)), src_ip=atk, dst_ip="10.0.0.5", dst_port=int(p),
                  event_type="connection", message="SYN probe")
        _auth_fail(b, rng, atk, int(rng.integers(150, 300)), 900, 280, ["admin"])
        b.add(1300, src_ip=atk, dst_ip="10.0.0.10", dst_port=22, event_type="auth_success", user="admin",
              message="Accepted password for admin")
    b.events.sort(key=lambda e: e["timestamp"])
    for i, e in enumerate(b.events):
        e["id"] = f"E{i + 1:04d}"
    return b.events
