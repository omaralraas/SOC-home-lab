"""Wazuh -> SOAR webhook integration.

integratord runs this once per alert at or above the <level> configured in
ossec.conf, as:  custom-soar <alert_file> <api_key> <hook_url> [options_file]

The alert is POSTed as JSON with an HMAC-SHA256 signature over
"<timestamp>.<body>" using api_key as the shared secret, so the SOAR webhook
can reject forged or replayed requests. Standard library only: it runs on the
Python bundled with the manager.
"""

import hashlib
import hmac
import json
import sys
import time
import urllib.request

TIMEOUT_SECONDS = 10


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def build_request(alert: dict, secret: str, url: str) -> urllib.request.Request:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"hook_url must be http(s), got {url!r}")
    body = json.dumps(alert, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    return urllib.request.Request(  # noqa: S310 - scheme validated above
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-SOAR-Timestamp": timestamp,
            "X-SOAR-Signature": sign(secret, timestamp, body),
        },
    )


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: custom-soar <alert_file> <api_key> <hook_url>", file=sys.stderr)
        return 2
    alert_file, secret, url = argv[1], argv[2], argv[3]
    with open(alert_file, encoding="utf-8") as fh:
        alert = json.load(fh)
    with urllib.request.urlopen(build_request(alert, secret, url), timeout=TIMEOUT_SECONDS) as resp:  # noqa: S310
        return 0 if 200 <= resp.status < 300 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
