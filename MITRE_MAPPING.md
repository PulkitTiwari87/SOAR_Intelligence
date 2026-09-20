# MITRE ATT&CK mapping

Every mapping stored on an incident carries `tactic`, `technique`, `subtechnique`, `source`, `confidence` and
`evidence`. The UI shows the source and marks inferred mappings. **An empty mapping is a valid answer**: nothing is
guessed when no rule matches.

| `source` | Meaning | Confidence |
|---|---|---|
| `wazuh_rule` | Technique ids carried by the Wazuh rule that fired (authored by the rule writer). | 0.9 |
| `rule_engine` | Deterministic heuristics in `soar/pipeline/mitre.py`, each with an evidence string. | 0.4 – 0.8 |
| `llm_inferred` | Suggested by the LLM commander; accepted **only if the id is in the catalog**, capped at 0.7, shown as *inferred*. | ≤ 0.7 |

## Heuristics (`from_rules`)

| Observation | Mapping |
|---|---|
| ≥ 5 failed logins | T1110 Brute Force (0.75); one account → T1110.001 Password Guessing; ≥ 3 accounts with few attempts each → T1110.003 Password Spraying |
| Successful login from an IP that had failures | T1078 Valid Accounts (0.5) |
| `suspicious_process` with reverse-shell-style command | T1059 (0.7), T1059.004 Unix Shell when a shell is invoked |
| Email classified as phishing | T1566 (0.8); with links T1566.002 (0.7); with attachments T1566.001 |
| `network_scan` | T1046 Network Service Discovery (0.8) |
| `web_attack` | T1190 Exploit Public-Facing Application (0.7) |
| `privilege_escalation` | T1548 Abuse Elevation Control Mechanism (0.5) |
| `data_exfiltration` | T1041 (0.4, "channel unknown") |
| Integrity change to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | T1098 Account Manipulation (0.4, labelled heuristic) |

The catalog is a **curated subset** of enterprise ATT&CK (about three dozen techniques and sub-techniques), not the
full matrix; extend `CATALOG` in `soar/pipeline/mitre.py` to map more. Tactic impact feeds the risk score (`risk.TACTIC_IMPACT`).
