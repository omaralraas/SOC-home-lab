# Threat Hunting: Persistence

Hypothesis-driven hunts written in [ES|QL](https://www.elastic.co/docs/reference/query-languages/esql)
against the `logs-soc.windows-*` data stream (Winlogbeat: Security, System and Sysmon channels).
Paste a query into **Kibana > Discover > ES|QL**. Every query in this folder runs in CI against
Elasticsearch with seeded events (`tests/elastic`), so syntax and field names are verified.

Most hunts here use **stacking**: persistence is rare, so group by the artefact and read the long
tail (lowest counts, fewest hosts) first.

---

## 1. Scheduled tasks created on few hosts (T1053.005)

**Hypothesis:** an attacker who gained execution registered a scheduled task for persistence; it will
exist on one or two hosts, unlike software-deployed tasks that appear fleet-wide.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "4698"
| STATS created = COUNT(*), hosts = COUNT_DISTINCT(host.name), first_seen = MIN(@timestamp)
    BY winlog.event_data.TaskName, winlog.event_data.SubjectUserName
| WHERE hosts <= 2
| SORT created ASC, first_seen DESC
| LIMIT 100
```

**Triage:** read the task XML (`winlog.event_data.TaskContent`) for the action; script hosts or
binaries under `Users\Public`, `AppData` or `Temp` are what Wazuh rule 100131 / Sigma
`schtask_creation` alert on. Check whether the creating account normally administers that host.

---

## 2. Run-key values pointing at unusual binaries (T1547.001)

**Hypothesis:** malware set a `Run`/`RunOnce` value; the value data will be rare across the fleet.

```esql
FROM logs-soc.windows-*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND event.code == "13"
    AND registry.path LIKE "*CurrentVersion*Run*"
| STATS writes = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY registry.data.strings, process.executable
| WHERE hosts <= 2
| SORT writes ASC
| LIMIT 100
```

**Triage:** hash the referenced binary and check signer/reputation; `reg.exe` or a script host as
`process.executable` means the key was set from a command line. Related: Wazuh 100130, Sigma
`registry_run_key_suspicious_path`.

---

## 3. New services, suspicious image paths first (T1543.003)

**Hypothesis:** remote execution tools (PsExec, Impacket, Cobalt Strike) install short-lived services
whose image path runs a shell or a binary from a writable share.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "7045"
| EVAL image = TO_LOWER(winlog.event_data.ImagePath)
| EVAL suspicious = image LIKE "*%comspec%*" OR image LIKE "*cmd.exe /c*" OR image LIKE "*powershell*"
    OR image LIKE "*users*public*" OR image LIKE "*\\\\127.0.0.1*"
| STATS installs = COUNT(*), hosts = COUNT_DISTINCT(host.name)
    BY winlog.event_data.ServiceName, image, suspicious
| SORT suspicious DESC, hosts ASC
| LIMIT 100
```

**Triage:** a service created and deleted within minutes on a workstation is lateral movement until
proven otherwise; pivot to `event.code == "5140"` (admin share access) on the same host just before.
Related: Wazuh 100152.

---

## 4. WMI event subscriptions (T1546.003)

**Hypothesis:** fileless persistence through a WMI filter/consumer binding. Legitimate subscriptions
are rare enough on workstations to review every one.

```esql
FROM logs-soc.windows-*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND event.code IN ("19", "20", "21")
| KEEP @timestamp, host.name, event.code, winlog.event_data.Name, winlog.event_data.Destination,
    winlog.event_data.Query, winlog.event_data.User
| SORT @timestamp DESC
| LIMIT 100
```

**Triage:** event 20 `Destination` is the payload (a command line or script); event 21 binds it to the
event 19 filter. A `CommandLineEventConsumer` running PowerShell is the classic malicious pattern.

---

## 5. Files dropped into Startup folders (T1547.001)

**Hypothesis:** an implant copied itself into a Startup folder to run at logon.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "11" AND file.path LIKE "*Start Menu*Programs*Startup*"
| STATS files = COUNT(*) BY host.name, process.executable, file.name
| SORT files ASC
| LIMIT 100
```

**Triage:** `.lnk` files written by installers are normal; scripts (`.vbs`, `.js`, `.bat`) or
executables written by Office, a browser or a script host are not.
