# Denial of Service and Request Flooding (project knowledge note)
Flooding shows very high request or packet rates toward one service, many flows with heavy forward traffic and little reply, and degraded availability. MITRE ATT&CK refers to Endpoint Denial of Service (T1499).
Distinguish from legitimate traffic spikes such as a marketing event or batch job.
Handling: confirm business context, apply rate limiting, work with the network provider on upstream filtering, and scale capacity if the load is legitimate.
