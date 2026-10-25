"""Seed events for the ES|QL hunting tests, shaped like the Logstash pipelines' output
(Winlogbeat ECS + winlog.event_data, Suricata EVE under suricata.eve.*, parsed sshd lines).
Each hunt gets at least one planted malicious event plus benign background."""

from datetime import UTC, datetime, timedelta

T0 = datetime(2026, 10, 25, 8, 0, tzinfo=UTC)
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def ts(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).isoformat()


def win(minutes, code, channel="Security", host="WIN10-LAB", **fields):
    doc = {
        "@timestamp": ts(minutes),
        "event": {"code": str(code)},
        "host": {"name": host},
        "winlog": {"channel": channel},
    }
    event_data = fields.pop("event_data", {})
    doc["winlog"]["event_data"] = event_data
    doc.update(fields)
    return doc


def windows_events():
    docs = [
        # persistence
        win(
            1,
            4698,
            event_data={
                "TaskName": "\\OneDriveSync",
                "SubjectUserName": "jdoe",
                "TaskContent": "<Command>powershell.exe</Command>",
            },
        ),
        win(
            2,
            13,
            SYSMON,
            registry={
                "path": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd",
                "data": {"strings": ["C:\\Users\\Public\\upd.exe"]},
            },
            process={"executable": "C:\\Windows\\System32\\reg.exe"},
        ),
        win(
            3,
            7045,
            "System",
            event_data={"ServiceName": "BTOBTO", "ImagePath": "%COMSPEC% /Q /c echo cd > \\\\127.0.0.1\\C$\\__output"},
        ),
        win(
            3.5,
            7045,
            "System",
            event_data={
                "ServiceName": "MozillaMaintenance",
                "ImagePath": "C:\\Program Files (x86)\\Mozilla\\maintenanceservice.exe",
            },
        ),
        win(
            4,
            20,
            SYSMON,
            event_data={"Name": "Updater", "Destination": "powershell -enc SQBFAFgA", "Query": "", "User": "SYSTEM"},
        ),
        win(
            5,
            11,
            SYSMON,
            file={
                "path": "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.vbs",
                "name": "run.vbs",
                "extension": "vbs",
            },
            process={"executable": "C:\\Windows\\System32\\wscript.exe"},
        ),
        # lateral movement
        win(10, 4624, event_data={"LogonType": "10", "TargetUserName": "admin"}, source={"ip": "10.0.2.100"}),
        win(
            11,
            4624,
            host="WIN10-B",
            event_data={"LogonType": "10", "TargetUserName": "admin"},
            source={"ip": "10.0.0.50"},
        ),
        win(12, 5140, event_data={"ShareName": "\\\\*\\ADMIN$"}, source={"ip": "10.0.2.100"}),
        win(13, 7045, "System", event_data={"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe"}),
        win(
            14,
            1,
            SYSMON,
            process={
                "executable": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1698765 2>&1",
                "parent": {"executable": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
            },
        ),
        win(
            15,
            1,
            SYSMON,
            user={"name": "admin"},
            process={
                "executable": "C:\\Windows\\System32\\whoami.exe",
                "command_line": "whoami /all",
                "parent": {"executable": "C:\\Windows\\System32\\wsmprovhost.exe"},
            },
        ),
        win(
            16,
            4624,
            event_data={
                "LogonType": "9",
                "LogonProcessName": "seclogo",
                "SubjectUserName": "jdoe",
                "TargetUserName": "jdoe",
                "TargetOutboundUserName": "administrator",
                "AuthenticationPackageName": "Negotiate",
            },
        ),
        # exfil staging
        win(
            20,
            11,
            SYSMON,
            file={"path": "C:\\Users\\Public\\q3.zip", "name": "q3.zip", "extension": "zip"},
            process={"executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        ),
        # credential access
        win(
            30,
            10,
            SYSMON,
            event_data={
                "SourceImage": "C:\\Users\\Public\\m.exe",
                "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                "GrantedAccess": "0x1010",
            },
        ),
    ]
    docs += [
        win(40 + i, 4625, event_data={"TargetUserName": user}, source={"ip": "10.0.2.100"})
        for i, user in enumerate(["alice", "bob", "carol", "dave", "erin", "frank"])
    ]
    return docs


def suricata(minutes, event_type, src="10.0.0.50", dest="203.0.113.50", dport=443, **eve):
    return {
        "@timestamp": ts(minutes),
        "host": {"name": "suricata-sensor"},
        "source": {"ip": src},
        "destination": {"ip": dest, "port": dport},
        "suricata": {"eve": {"event_type": event_type, **eve}},
    }


def suricata_events():
    docs = [
        # 8 hours of hourly-ish check-ins to one C2 host, plus a big upload
        suricata(h * 60 + 7, "flow", flow={"bytes_toserver": 512, "bytes_toclient": 300})
        for h in range(8)
    ]
    docs.append(
        suricata(30, "flow", dest="198.51.100.9", flow={"bytes_toserver": 80 * 1048576, "bytes_toclient": 4096})
    )
    docs.append(suricata(31, "flow", dest="10.0.0.51", dport=80, flow={"bytes_toserver": 900, "bytes_toclient": 50000}))
    docs += [
        suricata(
            50 + i / 10,
            "dns",
            dest="10.0.0.1",
            dport=53,
            dns={
                "type": "request",
                "queries": [
                    {
                        "rrname": f"{i:04d}aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRlZA{i:04d}.t.attacker.example",
                        "rrtype": "TXT",
                    }
                ],
            },
        )
        for i in range(60)
    ]
    docs.append(
        suricata(
            55, "dns", dest="10.0.0.1", dport=53, dns={"type": "request", "queries": [{"rrname": "www.wikipedia.org"}]}
        )
    )
    docs.append(
        suricata(
            56,
            "tls",
            tls={
                "subject": "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
                "issuerdn": "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
                "sni": "update-cdn.example",
            },
        )
    )
    return docs


def syslog_events():
    docs = []
    for i in range(8):
        docs.append(
            {
                "@timestamp": ts(60 + i / 6),
                "host": {"name": "ubuntu-srv"},
                "process": {"name": "sshd"},
                "event": {"category": "authentication", "outcome": "failure"},
                "user": {"name": "jdoe"},
                "source": {"ip": "10.0.2.100"},
            }
        )
    docs.append(
        {
            "@timestamp": ts(62),
            "host": {"name": "ubuntu-srv"},
            "process": {"name": "sshd"},
            "event": {"category": "authentication", "outcome": "success"},
            "user": {"name": "jdoe"},
            "source": {"ip": "10.0.2.100"},
        }
    )
    return docs


STREAMS = {
    "logs-soc.windows-lab": windows_events,
    "logs-soc.suricata-lab": suricata_events,
    "logs-soc.syslog-lab": syslog_events,
}
