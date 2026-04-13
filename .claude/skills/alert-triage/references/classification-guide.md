# Alert Classification Guide

## Fundamental principle

Most alerts are false positives. Your job is to find EVIDENCE, not to confirm suspicions. When in doubt, classify as
"suspicious" — this is better than a wrong malicious classification that wastes IR resources, or a wrong benign
classification that misses a threat.

## Pre-classification checklist

Before making ANY classification, confirm you have:

- [ ] Searched for related alerts on the same agent/host
- [ ] Checked rule frequency across the environment
- [ ] Investigated process tree and parent-child relationships
- [ ] Reviewed network activity (DNS, connections, lateral movement)
- [ ] Checked for persistence mechanisms (registry, scheduled tasks, services)
- [ ] Looked for defense evasion behaviors
- [ ] Verified code signing status of executables involved
- [ ] Identified environment context (production vs sandbox/test)

## Classification: Benign (score 0-19)

Confirmed false positive or legitimate activity. Use when you have positive evidence of legitimacy:
- Recognized enterprise software performing expected functions
- Known IT management activity (SCCM, Group Policy, Intune)
- Security testing with clear test environment indicators
- Rule known to have high FP rate for this specific scenario

## Classification: Suspicious (score 20-60)

Insufficient information to determine. Use when:
- Suspicious indicators BUT lack corroborating evidence of malicious INTENT
- Activity COULD be malicious OR legitimate
- First time seeing this pattern with no baseline

## Classification: Malicious (score 61-100)

Requires at least ONE high-confidence indicator:
- Confirmed C2 communication (beaconing to known bad IP/domain)
- Persistence mechanisms established (registry Run keys, scheduled tasks)
- Credential theft (LSASS access, credential file access)
- Lateral movement (RDP/SMB/WinRM to other internal hosts)
- Active defense evasion (disabling AV, clearing logs)
- Known malware hash match

NOT sufficient alone (require corroboration):
- Unsigned binary, large file size, running from Temp folder
- WriteProcessMemory API, VirtualAlloc RWX
- Alert severity "critical" or rule name containing "Malicious"

## Behavioral Weight Table

| Behavior | Score | Classification |
|----------|-------|---------------|
| Persistence + C2 together | 75+ | Malicious |
| Credential access (LSASS read) | 80+ | Malicious |
| Confirmed C2 beaconing | 75+ | Malicious |
| Lateral movement | 75+ | Malicious |
| AV/EDR disabling | 80+ | Malicious |
| Known malware hash | 90+ | Malicious |
| Process injection without confirmed target | 35-50 | Suspicious |
| Unsigned executable | 25-40 | Suspicious |
| Running from Temp/AppData | 25-40 | Suspicious |
| PowerShell execution alone | 20-35 | Suspicious |

## Common False Positive Sources

- **Enterprise management**: SCCM, Group Policy, Intune, Ansible, Puppet
- **Security software**: DLP agents, EDR agents, vulnerability scanners
- **Software protection**: Denuvo, VMProtect, game anti-cheat
- **Large frameworks**: Electron apps (Slack, Discord, VS Code), Node.js, game launchers
- **Security testing**: Atomic Red Team, Caldera, penetration testing
