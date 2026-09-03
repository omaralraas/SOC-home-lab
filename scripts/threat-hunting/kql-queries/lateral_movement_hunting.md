# Threat Hunting: Lateral Movement

## Overview
KQL queries for detecting lateral movement techniques across the SOC Home Lab network.
Target index: `soc-windows-*` and `soc-syslog-*`

---

## 1. RDP Session Tracking (T1021.001)

**Description:** Track RDP sessions across the network to identify unusual remote access patterns.

```kql
winlog.event_id:4624 AND winlog.event_data.LogonType:10
| stats count, values(source.ip) as source_ips, dc(source.ip) as unique_sources
  by winlog.event_data.TargetUserName, host.name
| where unique_sources > 1
| sort count desc
```

**Investigation Steps:**
1. Identify if the user typically uses RDP
2. Check if source IPs are from expected subnets
3. Correlate with VPN logs if applicable
4. Look for off-hours RDP sessions

---

## 2. PsExec / SMB Lateral Movement (T1021.002)

**Description:** Detect PsExec-style lateral movement via SMB administrative shares.

```kql
(winlog.event_id:5140 AND winlog.event_data.ShareName:("\\\\*\\ADMIN$" OR "\\\\*\\C$" OR "\\\\*\\IPC$"))
OR (winlog.event_id:7045 AND winlog.event_data.ServiceName:PSEXESVC)
| stats count by source.ip, host.name, winlog.event_data.ShareName
| sort count desc
```

**Investigation Steps:**
1. Verify if admin share access is from authorized IT personnel
2. Check if PSEXESVC service creation corresponds to known admin activity
3. Investigate the source host for compromise indicators
4. Review what files were accessed through the share

---

## 3. WMI Remote Execution (T1047)

**Description:** Detect WMI-based remote process execution.

```kql
winlog.event_id:4688 AND process.name:"WmiPrvSE.exe"
AND process.command_line:*create*
| stats count by host.name, winlog.event_data.ParentProcessName, process.command_line
```

**Investigation Steps:**
1. Review the command executed via WMI
2. Identify the remote source of the WMI call
3. Check for corresponding authentication events
4. Determine if WMI is typically used in this environment

---

## 4. PowerShell Remoting (T1021.006)

**Description:** Detect PowerShell remoting sessions indicating lateral movement.

```kql
winlog.event_id:4688 AND process.command_line:(*Enter-PSSession* OR *Invoke-Command*-ComputerName* OR *New-PSSession*)
| stats count by winlog.event_data.SubjectUserName, host.name, process.command_line
```

---

## 5. Pass-the-Hash Indicators (T1550.002)

**Description:** Detect logon events consistent with pass-the-hash attacks.

```kql
winlog.event_id:4624 AND winlog.event_data.LogonType:9
AND winlog.event_data.LogonProcessName:"seclogo"
AND winlog.event_data.AuthenticationPackageName:"Negotiate"
| stats count by winlog.event_data.TargetUserName, source.ip, host.name
```

**Investigation Steps:**
1. Type 9 logons with seclogo are strong PtH indicators
2. Check if the user typically logs on this way
3. Investigate the source host for compromise
4. Review for preceding credential access activity
