# Threat Hunting: Credential Access

ES|QL hunts over `logs-soc.syslog-*` (Linux auth via Logstash) and `logs-soc.windows-*`. Verified in
CI against seeded events (`tests/elastic`).

---

## 1. SSH sources that failed and then succeeded (T1110.001, T1078)

**Hypothesis:** a brute-force source that eventually logs in has guessed a password. Unlike the
real-time Wazuh correlation (rule 40112, 4-minute window), this looks across the whole search range,
so slow, low-and-slow guessing is caught too.

```esql
FROM logs-soc.syslog-*
| WHERE process.name == "sshd" AND event.category == "authentication"
| EVAL failed = CASE(event.outcome == "failure", 1, 0), succeeded = CASE(event.outcome == "success", 1, 0)
| STATS failures = SUM(failed), successes = SUM(succeeded), accounts = VALUES(user.name),
    first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip
| WHERE failures >= 5 AND successes > 0
| SORT failures DESC
| LIMIT 50
```

**Triage:** confirm which account succeeded (`accounts`), then follow IR-002. Rotate that
credential even if the session looks benign.

---

## 2. Password spraying against Windows accounts (T1110.003)

**Hypothesis:** spraying tries one password against many accounts, so a source fails for many
distinct users with few attempts each, under per-account lockout thresholds.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "4625"
| STATS failures = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName),
    first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip
| EVAL attempts_per_account = ROUND(failures / accounts, 1)
| WHERE accounts >= 5 AND attempts_per_account <= 3
| SORT accounts DESC
| LIMIT 50
```

**Triage:** a source with many accounts and about one attempt each is spraying; a source with one
account and many attempts is guessing (Wazuh 60204). Related: Wazuh 100100 / 100101.

---

## 3. Processes opening LSASS (T1003.001)

**Hypothesis:** credential dumpers open `lsass.exe` with read access; the set of processes that do
so legitimately is small and stable, so anything new stands out.

```esql
FROM logs-soc.windows-*
| WHERE event.code == "10" AND TO_LOWER(winlog.event_data.TargetImage) LIKE "*\\\\lsass.exe"
| STATS opens = COUNT(*), hosts = COUNT_DISTINCT(host.name), access_masks = VALUES(winlog.event_data.GrantedAccess)
    BY winlog.event_data.SourceImage
| SORT hosts ASC, opens ASC
| LIMIT 100
```

**Triage:** `0x1010` / `0x1410` / `0x1fffff` from anything outside the OS, Defender and your EDR is
dumping. Related: Sigma `lsass_access_sysmon`, Wazuh stock rule 92900.
