# Brute-Force Authentication Attacks (project knowledge note)
Brute-force authentication activity shows as a large number of failed logins from one source within a short window, often against one or a few accounts. Password spraying differs: few attempts per account across many accounts. MITRE ATT&CK describes this behaviour as technique T1110 (Brute Force).
Indicators: failed-login bursts, one source address, repeated POST requests to login endpoints, abnormal frequency compared with the baseline.
Alternative explanations to rule out: a misconfigured service retrying stale credentials, a user who forgot a password, a compromised legitimate client.
Recommended handling: review the targeted accounts, check whether any login from the source succeeded, enable additional authentication controls such as multi-factor authentication or rate limiting, and review authentication logs. Blocking should be approved by a human analyst first.
