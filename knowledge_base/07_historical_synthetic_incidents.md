# Historical Synthetic Incident Descriptions (synthetic examples, not real events)
Example A: 420 failed SSH logins from one external address within four minutes against the admin account; no success; resolved by rate limiting and credential review. Root cause: brute-force activity.
Example B: Port scan of 60 ports followed twelve minutes later by failed logins and one success for a privileged account from the same address. Root cause: compromised account after reconnaissance; account reset and sessions reviewed.
Example C: Database timeouts every few seconds with connection pool exhausted errors after a deployment; root cause was a missing index causing long-running queries.
