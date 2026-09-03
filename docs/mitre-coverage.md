# MITRE ATT&CK Coverage Matrix

## Overview
This document maps all detection rules in the SOC Home Lab to MITRE ATT&CK techniques, identifies coverage gaps, and outlines a remediation plan.

## Coverage by Tactic

| Tactic | Techniques Covered | Total Techniques | Coverage |
|--------|-------------------|-----------------|----------|
| Reconnaissance | 1 | 10 | 10% |
| Initial Access | 1 | 9 | 11% |
| Execution | 2 | 12 | 17% |
| Persistence | 4 | 19 | 21% |
| Privilege Escalation | 2 | 13 | 15% |
| Defense Evasion | 2 | 42 | 5% |
| Credential Access | 2 | 17 | 12% |
| Discovery | 1 | 31 | 3% |
| Lateral Movement | 5 | 9 | 56% |
| Collection | 0 | 17 | 0% |
| Command and Control | 3 | 16 | 19% |
| Exfiltration | 2 | 9 | 22% |
| Impact | 2 | 13 | 15% |

## Detection Rule Mapping

### Wazuh Custom Rules

| Rule ID | Description | MITRE Technique | Tactic |
|---------|-------------|-----------------|--------|
| 100100-102 | SSH Brute Force (escalating severity) | T1110.001 | Credential Access |
| 100103-104 | RDP Brute Force | T1110.001 | Credential Access |
| 100105 | Web Login Brute Force | T1110.001 | Credential Access |
| 100106-107 | Account Lockout / Distributed Attack | T1110.003 | Credential Access |
| 100108 | Successful Login After Brute Force | T1078 | Defense Evasion |
| 100120 | Suspicious PowerShell | T1059.001 | Execution |
| 100121 | Offensive Tool Execution | T1059.001 | Execution |
| 100122 | Credential Dumping Tool | T1003.001 | Credential Access |
| 100124 | Suspicious File in Temp | T1204.002 | Execution |
| 100125 | Mass File Encryption | T1486 | Impact |
| 100126 | Shadow Copy Deletion | T1490 | Impact |
| 100127 | LOLBin Abuse | T1218 | Defense Evasion |
| 100150 | PsExec Detection | T1021.002 | Lateral Movement |
| 100151 | Suspicious Service Install | T1543.003 | Persistence |
| 100152 | WMI Remote Execution | T1047 | Lateral Movement |
| 100153 | Off-Hours RDP | T1021.001 | Lateral Movement |
| 100154 | Pass-the-Hash | T1550.002 | Lateral Movement |
| 100155 | PowerShell Remoting | T1021.006 | Lateral Movement |
| 100156 | Admin Share Access | T1021.002 | Lateral Movement |
| 100157 | Remote Scheduled Task | T1053.005 | Persistence |

### Sigma Rules

| Rule | MITRE Technique | Tactic |
|------|-----------------|--------|
| Scheduled Task Creation | T1053.005 | Persistence |
| Credential Dump Detection | T1003.001 | Credential Access |
| Windows Defender Tampering | T1562.001 | Defense Evasion |
| Sudo Abuse (Linux) | T1548.003 | Privilege Escalation |
| DNS Tunneling | T1071.004 | C2 / Exfiltration |

### Suricata IDS Rules

| SID | MITRE Technique | Tactic |
|-----|-----------------|--------|
| 1000001 | T1071.001 | C2 (HTTP Beaconing) |
| 1000002-3 | T1071.004 | C2 (DNS Tunneling) |
| 1000007-8 | T1496 | Impact (Cryptomining) |
| 1000009 | T1048.003 | Exfiltration (DNS) |
| 1000010-11 | T1046 | Discovery (Port Scan) |
| 1000012 | T1190 | Initial Access (SQLi) |
| 1000020-21 | T1095 | C2 (ICMP Tunneling) |
| 1000025-26 | T1021.002 | Lateral Movement (SMB) |
| 1000027 | T1090.003 | C2 (Tor) |

## Priority Gap Remediation Plan

| Priority | Gap | Planned Detection | Status |
|----------|-----|-------------------|--------|
| P1 | Collection tactics (0% coverage) | File access monitoring via Sysmon + FIM | Planned |
| P2 | Discovery techniques (3%) | Process enumeration, network scan detection | Planned |
| P3 | Initial Access (11%) | Phishing email analysis, exploit detection | Planned |
| P4 | Defense Evasion (5%) | Process hollowing, DLL side-loading detection | Planned |
| P5 | Privilege Escalation (15%) | Token manipulation, UAC bypass detection | Planned |
