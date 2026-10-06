# Network Reconnaissance and Port Scanning (project knowledge note)
A port scan appears as many short connections from one source to many different destination ports, with small packets, high SYN counts and little returned data. MITRE ATT&CK lists this under Network Service Discovery (T1046).
Scanning alone does not prove compromise; it often precedes credential attacks or exploitation, so look for follow-up authentication activity from the same source.
Handling: confirm whether the source is an authorised vulnerability scanner, review exposed services, close unused ports, and monitor the source for later activity. Response actions need analyst approval.
