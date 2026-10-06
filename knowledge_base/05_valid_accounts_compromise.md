# Compromised Accounts After Credential Attacks (project knowledge note)
A successful login from a source that previously produced many failures suggests the credential attack may have worked. Adversary use of legitimate credentials is described in MITRE ATT&CK as Valid Accounts (T1078).
Multi-stage patterns, for example scanning then a login attack then a successful login, raise severity because they suggest an adversary progressing through stages.
Handling: treat the account as potentially compromised, review what the session did, force a credential reset after approval, check for lateral movement, and preserve logs as evidence.
