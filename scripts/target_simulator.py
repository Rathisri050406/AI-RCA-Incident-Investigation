"""Computer 1 (simulated target) for DISTRIBUTED mode: sends synthetic events to the investigation server.
  python scripts/target_simulator.py --server http://<server-ip>:8000 --scenario failed_logins --password '...'
"""
import argparse, json, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.utils.demo import SCENARIOS, generate_scenario

p = argparse.ArgumentParser()
p.add_argument("--server", default="http://127.0.0.1:8000"); p.add_argument("--user", default="admin")
p.add_argument("--password", required=True); p.add_argument("--scenario", default="failed_logins", choices=list(SCENARIOS))
a = p.parse_args()

def post(path, body, token=None):
    req = urllib.request.Request(a.server + path, json.dumps(body).encode(), {"Content-Type": "application/json",
                                 **({"Authorization": f"Bearer {token}"} if token else {})})
    return json.load(urllib.request.urlopen(req))

tok = post("/api/auth/login", {"username": a.user, "password": a.password})["access_token"]
ev = [{k: v for k, v in e.items() if k != "id"} for e in generate_scenario(a.scenario, 7)]
inc = post("/api/incidents", {"title": f"Simulated target: {SCENARIOS[a.scenario]}", "events": ev}, tok)
print("Incident created:", inc["code"], inc["classification"])
if inc["classification"] != "NORMAL":
    print("Investigation:", post(f"/api/incidents/{inc['id']}/investigate", {}, tok)["rca"]["root_cause"])
