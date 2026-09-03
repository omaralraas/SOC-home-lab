# Threat Hunting: Data Exfiltration

## Overview
KQL queries for detecting data exfiltration attempts through various channels.
Target indices: `soc-suricata-*`, `soc-syslog-*`, `soc-windows-*`

---

## 1. Large Outbound Data Transfers (T1048)

**Description:** Detect unusually large outbound data transfers that may indicate exfiltration.

```kql
event.module:"suricata" AND event_type:"flow"
AND destination.ip NOT (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
| stats sum(flow.bytes_toserver) as bytes_out by source.ip, destination.ip
| where bytes_out > 104857600
| sort bytes_out desc
```

**Investigation Steps:**
1. Identify what application generated the traffic
2. Check if destination is a known cloud service
3. Review the time of day (off-hours exfiltration is suspicious)
4. Examine file access logs for sensitive file access before transfer

---

## 2. DNS Tunneling Detection (T1071.004)

**Description:** Detect DNS tunneling through query pattern analysis.

```kql
event.module:"suricata" AND event_type:"dns"
| stats avg(dns.query.length) as avg_len, max(dns.query.length) as max_len, count as query_count
  by source.ip, dns.query.rrname
| where avg_len > 50 OR query_count > 500
| sort query_count desc
```

---

## 3. Encrypted Channel Anomalies (T1573)

**Description:** Detect suspicious encrypted connections that may hide exfiltration.

```kql
event.module:"suricata" AND event_type:"tls"
AND NOT tls.sni:(*microsoft.com OR *google.com OR *amazonaws.com OR *cloudflare.com)
| stats count, sum(flow.bytes_toserver) as bytes_out by source.ip, tls.sni, destination.ip
| where bytes_out > 10485760
| sort bytes_out desc
```

---

## 4. Unusual Cloud Storage Uploads (T1567.002)

**Description:** Detect uploads to cloud storage services.

```kql
event.module:"suricata" AND event_type:"http"
AND (http.hostname:(*dropbox.com OR *drive.google.com OR *onedrive.live.com OR *mega.nz OR *wetransfer.com))
AND http.http_method:"POST"
| stats count, sum(http.length) as total_bytes by source.ip, http.hostname
| sort total_bytes desc
```

---

## 5. Staged Data for Exfiltration (T1074)

**Description:** Detect creation of archive files that may be staged for exfiltration.

```kql
winlog.event_id:11 AND winlog.event_data.TargetFilename:(*.zip OR *.rar OR *.7z OR *.tar.gz)
AND winlog.event_data.TargetFilename:(*Users* OR *Temp* OR *Public*)
| stats count by winlog.event_data.TargetFilename, winlog.event_data.Image, host.name
| sort count desc
```
