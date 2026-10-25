import time
import uuid

import pytest

from tests.wazuh.harness import IMAGE, MOUNTS, docker


@pytest.fixture(scope="session")
def wazuh_manager():
    """A wazuh-manager container running the repo's config and ruleset."""
    name = f"soclab-wazuh-test-{uuid.uuid4().hex[:8]}"
    volume_args = [arg for src, dst in MOUNTS.items() for arg in ("-v", f"{src}:{dst}:ro")]
    # Same nofile limit as wazuh/docker-compose.yml: analysisd raises its limit at
    # start and logs an ERROR on hosts whose default is lower (e.g. CI runners).
    limits = ["--ulimit", "nofile=655360:655360"]
    started = docker("run", "-d", "--rm", "--name", name, *limits, *volume_args, IMAGE)
    assert started.returncode == 0, started.stderr

    try:
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if docker("exec", name, "test", "-S", "/var/ossec/queue/sockets/logtest").returncode == 0:
                break
            time.sleep(3)
        else:
            log = docker("exec", name, "cat", "/var/ossec/logs/ossec.log").stdout
            pytest.fail(f"wazuh-analysisd never opened the logtest socket.\n{log[-4000:]}")
        yield name
    finally:
        docker("rm", "-f", name)


@pytest.fixture(scope="session")
def stock_rules_dir(wazuh_manager, tmp_path_factory):
    """The stock ruleset shipped in the image, copied out for static analysis."""
    dest = tmp_path_factory.mktemp("stock")
    copied = docker("cp", f"{wazuh_manager}:/var/ossec/ruleset/rules", str(dest))
    assert copied.returncode == 0, copied.stderr
    return dest / "rules"
