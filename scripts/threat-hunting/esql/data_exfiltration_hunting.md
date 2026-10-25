# Threat Hunting: Command and Control and Exfiltration

ES|QL hunts over `logs-soc.suricata-*` (Suricata EVE via Logstash; the original record is kept
under `suricata.eve.*`) and `logs-soc.windows-*`. Verified in CI against seeded events
(`tests/elastic`).

---

## 1. Hosts sending far more than they receive (T1048)

**Hypothesis:** bulk exfiltration shows up as an internal host uploading much more to an external
address than it downloads, unlike browsing and updates.

```esql
FROM logs-soc.suricata-*
| WHERE suricata.eve.event_type == "flow"
    AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS sent_mb = SUM(suricata.eve.flow.bytes_toserver) / 1048576.0,
    received_mb = SUM(suricata.eve.flow.bytes_toclient) / 1048576.0,
    flows = COUNT(*)
    BY source.ip, destination.ip, destination.port
| EVAL upload_ratio = ROUND(sent_mb / (received_mb + 0.001), 1)
| WHERE sent_mb > 50 OR upload_ratio > 10
| SORT sent_mb DESC
| LIMIT 50
```

**Triage:** check the destination's ASN and TLS SNI; backups and cloud sync clients upload
legitimately, but on a schedule and to known providers.

---

## 2. DNS tunnelling: many unique, long subdomains under one parent (T1071.004)

**Hypothesis:** DNS tunnels encode data into subdomains, producing a high count of unique, long
labels beneath a single parent domain from one client.

```esql
FROM logs-soc.suricata-*
| WHERE suricata.eve.event_type == "dns" AND suricata.eve.dns.type == "request"
| EVAL query = TO_LOWER(MV_FIRST(suricata.eve.dns.queries.rrname))
| EVAL labels = SPLIT(query, ".")
| EVAL first_label_length = LENGTH(MV_FIRST(labels)),
    parent = MV_CONCAT(MV_SLICE(labels, -2, -1), ".")
| STATS queries = COUNT(*), unique_names = COUNT_DISTINCT(query), longest_label = MAX(first_label_length)
    BY source.ip, parent
| WHERE unique_names > 50 OR longest_label > 40
| SORT unique_names DESC
| LIMIT 50
```

**Triage:** CDNs and anti-virus reputation lookups also produce long labels, but from many clients;
a single client generating hundreds of unique names under one parent is the tunnel signature.
Related: Sigma `dns_tunneling`, Suricata 1000002 / 1000009.

---

## 3. Persistent periodic connections (T1071.001)

**Hypothesis:** an implant checks in on a timer, so the same source/destination pair is active in
almost every hour of the day. This query finds candidates; `beacon_hunter.py` then scores interval
jitter and size consistency on the raw flows.

```esql
FROM logs-soc.suricata-*
| WHERE suricata.eve.event_type == "flow"
    AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| EVAL hour = DATE_TRUNC(1 hour, @timestamp)
| STATS flows = COUNT(*) BY source.ip, destination.ip, destination.port, hour
| STATS active_hours = COUNT(*), median_flows_per_hour = MEDIAN(flows), spread = MEDIAN_ABSOLUTE_DEVIATION(flows)
    BY source.ip, destination.ip, destination.port
| WHERE active_hours >= 6
| SORT active_hours DESC, spread ASC
| LIMIT 50
```

**Next step:** export the pair's flows and run
`python scripts/threat-hunting/beacon_hunter.py --eve eve.json --min-score 0.7`.

---

## 4. Self-signed or default TLS certificates (T1573.002)

**Hypothesis:** quick C2 infrastructure uses self-signed certificates, where subject equals issuer.

```esql
FROM logs-soc.suricata-*
| WHERE suricata.eve.event_type == "tls" AND suricata.eve.tls.subject == suricata.eve.tls.issuerdn
| STATS sessions = COUNT(*), clients = COUNT_DISTINCT(source.ip)
    BY destination.ip, suricata.eve.tls.sni, suricata.eve.tls.subject
| SORT clients ASC, sessions DESC
| LIMIT 50
```

**Triage:** internal appliances and lab tools are often self-signed; external destinations reached by
a single client are the ones to explain. Related: Suricata 1000004.

---

## 5. Archives staged in temporary folders (T1074.001)

**Hypothesis:** before exfiltration, data is compressed into an archive in a staging folder.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "11"
    AND (file.extension IN ("zip", "7z", "rar") OR file.name LIKE "*.zip" OR file.name LIKE "*.7z" OR file.name LIKE "*.rar")
    AND (file.path LIKE "*Temp*" OR file.path LIKE "*Users*Public*" OR file.path LIKE "*ProgramData*")
| STATS archives = COUNT(*) BY host.name, process.executable, file.path
| SORT archives DESC
| LIMIT 50
```

**Triage:** PowerShell `Compress-Archive` or `7z.exe` writing to `Users\Public` shortly before a
large outbound flow (hunt 1) is a strong sequence.
