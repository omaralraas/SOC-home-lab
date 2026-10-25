from windows_event_parser import parse_xml, triage

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def event(event_id, time, ns=True, **data):
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f"<Event {NS if ns else ''}><System><EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{time}"/><Computer>WIN10-LAB</Computer></System>'
        f"<EventData>{items}</EventData></Event>"
    )


def test_parses_namespaced_export_with_root():
    events = parse_xml(f"<Events>{event(4624, '2026-10-25T09:00:00Z', TargetUserName='jdoe', LogonType='2')}</Events>")
    assert len(events) == 1 and events[0].get("TargetUserName") == "jdoe"


def test_parses_rootless_wevtutil_output():
    xml = event(4625, "2026-10-25T09:00:00Z") + event(4625, "2026-10-25T09:00:01Z")
    assert len(parse_xml(xml)) == 2


def test_parses_export_without_namespace():
    # The previous parser used `find(a) or find(b)`; leaf Elements are falsy,
    # so every event in a namespace-less export was silently dropped.
    events = parse_xml(f"<Events>{event(4720, '2026-10-25T09:00:00Z', ns=False, TargetUserName='svc_backup')}</Events>")
    assert [e.event_id for e in events] == [4720]


def test_detects_password_spraying_but_not_single_account_bursts():
    spray = [
        event(4625, f"2026-10-25T09:00:0{i}Z", TargetUserName=u, IpAddress="10.0.2.100")
        for i, u in enumerate(["alice", "bob", "carol", "dave", "erin"])
    ]
    titles = {f.title for f in triage(parse_xml("<Events>" + "".join(spray) + "</Events>"))}
    assert "Password spraying" in titles

    burst = [
        event(4625, f"2026-10-25T09:00:{i:02d}Z", TargetUserName="admin", IpAddress="10.0.2.100") for i in range(12)
    ]
    titles = {f.title for f in triage(parse_xml("<Events>" + "".join(burst) + "</Events>"))}
    assert titles == {"Failed logon burst"}


def test_off_hours_respects_utc_offset():
    # 03:30 UTC is 07:30 at UTC+4 (outside 08-18) but 23:30 the previous day at UTC-4
    xml = "<Events>" + event(4624, "2026-10-25T03:30:00Z", TargetUserName="jdoe", LogonType="10") + "</Events>"
    events = parse_xml(xml)
    assert [f.title for f in triage(events, (8, 18), utc_offset=4)] == ["Off-hours interactive logon"]
    assert triage(events, (0, 24), utc_offset=4) == []


def test_flags_persistence_and_anti_forensics():
    xml = (
        "<Events>"
        + "".join(
            [
                event(7045, "2026-10-25T09:00:00Z", ServiceName="BTOBTO", ImagePath="%COMSPEC% /Q /c echo"),
                event(
                    4732,
                    "2026-10-25T09:01:00Z",
                    TargetSid="S-1-5-32-544",
                    MemberSid="S-1-5-21-1-1001",
                    SubjectUserName="jdoe",
                ),
                event(1102, "2026-10-25T09:02:00Z", SubjectUserName="jdoe"),
            ]
        )
        + "</Events>"
    )
    findings = triage(parse_xml(xml))
    assert [f.title for f in findings][0] == "Security log cleared"  # sorted by severity
    assert {"Service installed", "Added to local Administrators"} <= {f.title for f in findings}
