"""Build deterministic test PCAPs for the Suricata rules with scapy.

TCP traffic is generated as complete sessions (handshake, data, teardown)
with consistent sequence numbers, so Suricata's stream engine and app-layer
parsers (HTTP, DNS, TLS, SMB, FTP) treat it exactly like captured traffic.
"""

from __future__ import annotations

import datetime as dt
import itertools
import struct

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

# Lab addressing (docs/architecture.md)
WORKSTATION = "10.0.0.50"
WEB_SERVER = "10.0.0.51"
RESOLVER = "10.0.0.1"
SOC_HOST = "10.0.1.20"
KALI = "10.0.2.100"
INTERNET = "203.0.113.50"

QTYPES = {"A": 1, "TXT": 16, "AXFR": 252}


class Pcap:
    def __init__(self) -> None:
        self.packets: list = []
        self.clock = 1_761_390_000.0  # fixed epoch keeps output deterministic
        self._ports = itertools.count(49152)

    # ------------------------------------------------------------- primitives
    def _emit(self, pkt, gap: float = 0.001) -> None:
        self.clock += gap
        frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / pkt
        frame.time = self.clock
        self.packets.append(frame)

    def tcp_session(
        self, src: str, dst: str, dport: int, client: list[bytes] = (), server: list[bytes] = (), gap: float = 0.001
    ) -> None:
        """Full TCP conversation; client and server payloads alternate."""
        sport = next(self._ports)
        cseq, sseq = 1000, 5000
        self._emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=cseq), gap)
        self._emit(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        cseq += 1
        sseq += 1
        self._emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        for i in range(max(len(client), len(server))):
            if i < len(client):
                data = client[i]
                self._emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / data)
                cseq += len(data)
                self._emit(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq))
            if i < len(server):
                data = server[i]
                self._emit(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / data)
                sseq += len(data)
                self._emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        self._emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
        self._emit(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
        self._emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))

    def raw_tcp(self, src: str, dst: str, dport: int, flags: str, gap: float = 0.001) -> None:
        self._emit(IP(src=src, dst=dst) / TCP(sport=next(self._ports), dport=dport, flags=flags, seq=1000), gap)

    def http(
        self,
        src: str,
        dst: str,
        method: str,
        uri: str,
        headers: dict | None = None,
        body: bytes = b"",
        dport: int = 80,
        gap: float = 0.001,
    ) -> None:
        hdrs = {"Host": dst, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", **(headers or {})}
        if body:
            hdrs["Content-Length"] = str(len(body))
        request = f"{method} {uri} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
        self.tcp_session(src, dst, dport, [request.encode() + body], [response], gap)

    def dns(self, src: str, qname: str, qtype: str = "A", dst: str = RESOLVER, gap: float = 0.001) -> None:
        sport = next(self._ports)
        qid = sport & 0xFFFF
        query = DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=QTYPES[qtype]))
        self._emit(IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / query, gap)
        answer = DNS(
            id=qid,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=qname, qtype=QTYPES[qtype]),
            an=DNSRR(
                rrname=qname,
                type=QTYPES[qtype] if qtype != "AXFR" else 1,
                rdata="198.51.100.7" if qtype != "TXT" else "ok",
            ),
        )
        self._emit(IP(src=dst, dst=src) / UDP(sport=53, dport=sport) / answer)

    def dns_tcp(self, src: str, qname: str, qtype: str, dst: str) -> None:
        query = bytes(DNS(id=0x1337, rd=0, qd=DNSQR(qname=qname, qtype=QTYPES[qtype])))
        self.tcp_session(src, dst, 53, [struct.pack(">H", len(query)) + query], [])

    def icmp_echo(self, src: str, dst: str, size: int, gap: float = 0.001) -> None:
        self._emit(IP(src=src, dst=dst) / ICMP(type=8, id=1, seq=len(self.packets)) / Raw(b"A" * size), gap)

    def write(self, path) -> None:
        wrpcap(str(path), self.packets)


# --------------------------------------------------------------------- SMB2


def _smb2_header(command: int, msg_id: int, tree_id: int = 0, response: bool = False) -> bytes:
    flags = 0x1 if response else 0x0
    return (
        b"\xfeSMB"
        + struct.pack("<HHIHHIIQIIQ", 64, 1, 0, command, 1, flags, 0, msg_id, 0, tree_id, 0x4000000000001)
        + b"\x00" * 16
    )


def _nbss(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def smb2_tree_connect(path: str, msg_id: int) -> bytes:
    name = path.encode("utf-16le")
    body = struct.pack("<HHHH", 9, 0, 64 + 8, len(name)) + name
    return _nbss(_smb2_header(0x0003, msg_id) + body)


def smb2_tree_connect_response(msg_id: int, tree_id: int, pipe: bool) -> bytes:
    body = struct.pack("<HBBIII", 16, 0x02 if pipe else 0x01, 0, 0, 0, 0x001F01FF)
    return _nbss(_smb2_header(0x0003, msg_id, tree_id, response=True) + body)


def smb2_create(name: str, msg_id: int, tree_id: int) -> bytes:
    fname = name.encode("utf-16le")
    body = (
        struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x0012019F, 0, 0x7, 1, 0x40, 64 + 56, len(fname), 0, 0)
        + fname
    )
    return _nbss(_smb2_header(0x0005, msg_id, tree_id) + body)


def smb2_create_response(msg_id: int, tree_id: int) -> bytes:
    body = (
        struct.pack("<HBBIQQQQQQII", 89, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x80, 0) + b"\x11" * 16 + struct.pack("<II", 0, 0)
    )
    return _nbss(_smb2_header(0x0005, msg_id, tree_id, response=True) + body)


# --------------------------------------------------------------------- TLS


def self_signed_cert_der(organisation: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some-State"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
        ]
    )
    start = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _tls_record(handshakes: bytes) -> bytes:
    return b"\x16\x03\x03" + struct.pack(">H", len(handshakes)) + handshakes


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + struct.pack(">I", len(body))[1:] + body


def tls_client_hello(sni: str) -> bytes:
    host = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(host)) + host
    sni_ext = struct.pack(">HH", 0, len(server_name) + 2) + struct.pack(">H", len(server_name)) + server_name
    body = (
        b"\x03\x03"
        + b"\x01" * 32
        + b"\x00"  # version, random, empty session id
        + struct.pack(">H", 2)
        + b"\xc0\x2f"  # one cipher suite
        + b"\x01\x00"  # null compression
        + struct.pack(">H", len(sni_ext))
        + sni_ext
    )
    return _tls_record(_handshake(1, body))


def tls_server_hello_with_cert(cert_der: bytes) -> bytes:
    server_hello = _handshake(2, b"\x03\x03" + b"\x02" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00")
    chain = struct.pack(">I", len(cert_der))[1:] + cert_der
    certificate = _handshake(11, struct.pack(">I", len(chain))[1:] + chain)
    done = _handshake(14, b"")
    return _tls_record(server_hello + certificate + done)
