# Threat Hunting: Lateral Movement

ES|QL hunts over `logs-soc.windows-*`. ES|QL has no event-sequence joins, so several hunts correlate
by bucketing events per host and hour with `DATE_TRUNC` and keeping buckets where the steps of a
technique co-occur. Verified in CI against seeded events (`tests/elastic`).

---

## 1. RDP fan-out and fan-in (T1021.001)

**Hypothesis:** a compromised account is used to RDP to hosts its owner never touches, or from more
sources than usual.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "4624" AND winlog.event_data.LogonType == "10"
| STATS logons = COUNT(*), sources = COUNT_DISTINCT(source.ip), targets = COUNT_DISTINCT(host.name)
    BY winlog.event_data.TargetUserName
| WHERE sources > 1 OR targets > 1
| SORT targets DESC, sources DESC
| LIMIT 50
```

**Triage:** compare against the user's normal workstation; logons from the attacker VLAN
(10.0.2.0/24) are never legitimate in this lab.

---

## 2. Admin share access followed by a service install (T1021.002, T1569.002)

**Hypothesis:** PsExec-style tools copy a binary over `ADMIN$` and start it as a service, so both
events land on the target within minutes.

```esql
FROM logs-soc.windows-*
| WHERE (event.code == "5140" AND winlog.event_data.ShareName LIKE "*ADMIN$") OR event.code == "7045"
| EVAL hour = DATE_TRUNC(1 hour, @timestamp),
    share_access = CASE(event.code == "5140", 1, 0),
    service_install = CASE(event.code == "7045", 1, 0)
| STATS share_accesses = SUM(share_access), services = SUM(service_install),
    sources = VALUES(source.ip), service_names = VALUES(winlog.event_data.ServiceName)
    BY host.name, hour
| WHERE share_accesses > 0 AND services > 0
| SORT hour DESC
| LIMIT 50
```

**Triage:** the `sources` column is the pivot to the attacking host. Related: Wazuh 100152, 100159;
Suricata 1000025 / 1000026 on the wire.

---

## 3. Processes spawned by the WMI provider host (T1047)

**Hypothesis:** remote WMI execution (`wmic /node`, Impacket `wmiexec`) runs commands as children of
`WmiPrvSE.exe` on the target.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "1" AND TO_LOWER(process.parent.executable) LIKE "*\\\\wmiprvse.exe"
| STATS runs = COUNT(*), first_seen = MIN(@timestamp) BY host.name, process.executable, process.command_line
| SORT runs ASC
| LIMIT 100
```

**Triage:** `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<timestamp>` is Impacket's output-redirection
signature. Related: Wazuh 100154, Sigma `wmiprvse_spawns_shell`.

---

## 4. Commands run inside WinRM sessions (T1021.006)

**Hypothesis:** PowerShell Remoting sessions execute as `wsmprovhost.exe`; interactive recon
commands under it indicate hands-on-keyboard activity.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "1" AND TO_LOWER(process.parent.executable) LIKE "*\\\\wsmprovhost.exe"
| STATS runs = COUNT(*) BY host.name, user.name, process.executable, process.command_line
| SORT runs ASC
| LIMIT 100
```

---

## 5. NewCredentials logons via seclogo (T1550.002)

**Hypothesis:** pass-the-hash with `sekurlsa::pth` produces type 9 logons through the `seclogo`
process; `runas /netonly` does too, so every hit needs explaining.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "4624" AND winlog.event_data.LogonType == "9"
    AND winlog.event_data.LogonProcessName LIKE "seclogo*"
| KEEP @timestamp, host.name, winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName,
    winlog.event_data.TargetOutboundUserName, winlog.event_data.AuthenticationPackageName
| SORT @timestamp DESC
| LIMIT 100
```

**Triage:** `TargetOutboundUserName` is the account whose credentials were injected. Related: Wazuh
100157.
