# Threat Hunting: Persistence Mechanisms

## Overview
KQL queries for hunting persistence techniques in the SOC Home Lab environment.
All queries target the `soc-windows-*` index pattern in Kibana.

---

## 1. Scheduled Task Creation (T1053.005)

**Description:** Hunt for newly created scheduled tasks that may indicate persistence.

```kql
event.action:"scheduled-task-created" AND winlog.event_id:4698
| stats count by winlog.event_data.SubjectUserName, winlog.event_data.TaskName
| sort count desc
```

**Investigation Steps:**
1. Review the task name and creation context
2. Check if the creating user account is expected to create tasks
3. Examine the task's executable path and arguments
4. Cross-reference with known legitimate scheduled tasks

---

## 2. Registry Run Key Modifications (T1547.001)

**Description:** Detect modifications to registry run keys used for persistence.

```kql
winlog.event_id:13 AND winlog.event_data.TargetObject:*CurrentVersion\\Run*
| stats count by winlog.event_data.TargetObject, winlog.event_data.Details, host.name
```

**Investigation Steps:**
1. Verify the registry value is from a known application
2. Check the executable path referenced in the value
3. Investigate the process that made the modification
4. Compare against baseline registry values

---

## 3. New Service Installations (T1543.003)

**Description:** Hunt for newly installed services which may indicate persistence or lateral movement.

```kql
(winlog.event_id:7045 OR winlog.event_id:4697)
| stats count by winlog.event_data.ServiceName, winlog.event_data.ImagePath, host.name
| sort count asc
```

**Investigation Steps:**
1. Check if service name matches known legitimate software
2. Verify the service binary path
3. Check the digital signature of the service binary
4. Review the account context under which the service was installed

---

## 4. WMI Event Subscriptions (T1546.003)

**Description:** Detect WMI event subscriptions used for fileless persistence.

```kql
winlog.event_id:(19 OR 20 OR 21) AND winlog.channel:"Microsoft-Windows-Sysmon/Operational"
| stats count by winlog.event_id, winlog.event_data.Name, winlog.event_data.Consumer
```

**Investigation Steps:**
1. Review the WMI consumer name and query
2. Check for encoded or obfuscated commands
3. Determine when the subscription was created
4. Assess if this matches any known legitimate WMI subscriptions

---

## 5. Startup Folder Additions (T1547.001)

**Description:** Detect files added to startup folders.

```kql
winlog.event_id:11 AND winlog.event_data.TargetFilename:(*Startup* OR *Start Menu*)
| stats count by winlog.event_data.TargetFilename, winlog.event_data.Image, host.name
```

**Investigation Steps:**
1. Examine the file placed in the startup folder
2. Check the creating process
3. Verify file hash against threat intelligence
4. Review the file's digital signature
