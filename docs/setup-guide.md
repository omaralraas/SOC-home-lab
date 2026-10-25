# Setup Guide

Deploys the lab described in [architecture.md](architecture.md). Every config referenced here is
the same file CI tests, so what you deploy is what was validated.

## Prerequisites

### Hardware (minimum)
- **CPU:** 8 cores · **RAM:** 16 GB (32 GB recommended) · **Disk:** 100 GB SSD

### Software
- VirtualBox 7 or VMware Workstation
- Docker Engine 27+ with the Compose v2 plugin on the SOC VMs
- ISOs: Ubuntu Server 24.04, Windows 10/11, Kali Linux, pfSense CE

---

## Step 1: Hypervisor networks

Create three host-only networks (no DHCP):

```bash
VBoxManage hostonlyif create   # repeat three times
VBoxManage hostonlyif ipconfig vboxnet0 --ip 10.0.0.254 --netmask 255.255.255.0   # CORP
VBoxManage hostonlyif ipconfig vboxnet1 --ip 10.0.1.254 --netmask 255.255.255.0   # SOC_MGMT
VBoxManage hostonlyif ipconfig vboxnet2 --ip 10.0.2.254 --netmask 255.255.255.0   # ATTACKER
```

Set the Suricata VM's CORP adapter to **promiscuous mode: allow all** so it sees the segment.

---

## Step 2: pfSense

1. VM with four adapters: NAT (WAN), vboxnet0 (CORP), vboxnet1 (SOC_MGMT), vboxnet2 (ATTACKER).
2. Assign interface addresses from the architecture IP table.
3. Recreate the policy in [`network/firewall-rules/pfsense-rules.conf`](../network/firewall-rules/pfsense-rules.conf)
   under **Firewall > Rules**. The file is the reviewed policy in pf syntax; pfSense itself is
   configured through the GUI.
4. **Status > System Logs > Settings > Remote logging:** send firewall logs to `10.0.1.10:514`
   (Wazuh) and `10.0.1.11:5514` (Logstash).
5. **SOAR containment:** **Firewall > Aliases > URLs**, add `SOAR_BLOCKLIST` of type
   *URL Table (IPs)* pointing at `http://10.0.1.10:5000/blocklist.txt` with a 1-minute refresh,
   then add the block rules from the policy file that reference it.

---

## Step 3: Wazuh (SOC_MGMT, 10.0.1.10)

```bash
git clone https://github.com/omaralraas/SOC-home-lab.git /opt/soc-home-lab
cd /opt/soc-home-lab/wazuh

docker compose -f generate-indexer-certs.yml run --rm generator   # one-time TLS material
cp .env.example .env
sed -i "s/CHANGE_ME_SOAR_SHARED_SECRET/$(openssl rand -hex 32)/" .env
# use the same secret as <api_key> of the custom-soar integration
sed -i "s/CHANGE_ME_SOAR_SHARED_SECRET/$(grep SOAR_SHARED_SECRET .env | cut -d= -f2)/" ossec.conf

docker compose up -d
docker compose exec wazuh.manager sh -c 'openssl rand -hex 16 > /var/ossec/etc/authd.pass && cat /var/ossec/etc/authd.pass'
```

The dashboard is at `https://10.0.1.10` (user `admin`). The manager requires the enrollment
password printed by the last command (`<use_password>yes</use_password>` in `ossec.conf`).

Rules, `ossec.conf` and `shared/agent.conf` are mounted into the container, so after editing them:
`docker compose restart wazuh.manager`.

### Enroll agents (same version as the manager, 4.14.8)

```powershell
# Windows endpoint (10.0.0.50), elevated PowerShell
msiexec /i wazuh-agent-4.14.8-1.msi /q WAZUH_MANAGER=10.0.1.10 WAZUH_REGISTRATION_PASSWORD=<authd.pass>
NET START WazuhSvc
```

```bash
# Ubuntu endpoint (10.0.0.51)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER=10.0.1.10 WAZUH_REGISTRATION_PASSWORD=<authd.pass> apt-get install -y wazuh-agent=4.14.8-1
systemctl enable --now wazuh-agent
```

Agents receive Sysmon/PowerShell/Defender collection and FIM settings from the centralized
`shared/agent.conf`; no per-host editing is needed.

### Rotating Wazuh credentials

The `.env.example` values are the wazuh-docker defaults and only suitable for an isolated lab.
To change them, follow Wazuh's
[password change procedure for Docker](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#change-the-password-of-wazuh-users):
generate bcrypt hashes with the indexer's `hash.sh`, update
`config/wazuh_indexer/internal_users.yml` and `.env`, update the API password in
`config/wazuh_dashboard/wazuh.yml`, then `docker compose down && docker compose up -d` and apply
the security config with `securityadmin.sh` inside the indexer container.

---

## Step 4: Elastic tier (SOC_MGMT, 10.0.1.11)

```bash
cd /opt/soc-home-lab/elastic
cp .env.example .env            # change every password and the Kibana key
docker compose up -d --wait     # setup job, Elasticsearch, Logstash, Kibana
```

Kibana: `http://10.0.1.11:5601` (user `elastic`). Data lands in the `logs-soc.syslog-lab`,
`logs-soc.windows-lab` and `logs-soc.suricata-lab` data streams; open **Discover > ES|QL** and use
the hunts in [`scripts/threat-hunting/esql`](../scripts/threat-hunting/esql).

---

## Step 5: Suricata sensor (SOC_MGMT, 10.0.1.12)

```bash
cd /opt/soc-home-lab/suricata
docker compose run --rm suricata suricata-update     # ET Open rules into the suricata-lib volume
SPAN_INTERFACE=eth1 docker compose up -d
tail -f /var/log/suricata/eve.json
```

Ship EVE to Logstash with Filebeat using
[`elastic/beats/filebeat-suricata.yml`](../elastic/beats/filebeat-suricata.yml), and install a
Wazuh agent on the sensor so the stock Suricata rules alert in Wazuh too.

---

## Step 6: Windows endpoint (10.0.0.50)

### Sysmon

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip C:\Sysmon
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
  -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Audit policy (the Security events the rules and hunts use)

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable                  # 4624/4625
auditpol /set /subcategory:"Account Lockout" /success:enable                        # 4740
auditpol /set /subcategory:"User Account Management" /success:enable                # 4720
auditpol /set /subcategory:"Security Group Management" /success:enable              # 4732
auditpol /set /subcategory:"Other Object Access Events" /success:enable             # 4698
auditpol /set /subcategory:"File Share" /success:enable                             # 5140
auditpol /set /subcategory:"Process Creation" /success:enable                       # 4688
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Winlogbeat

Install Winlogbeat 9.5.3, copy [`elastic/beats/winlogbeat.yml`](../elastic/beats/winlogbeat.yml),
then load its ECS ingest pipelines once (command in the file header) and start the service.

---

## Step 7: Linux endpoint (10.0.0.51)

```bash
apt-get install -y auditd audispd-plugins apache2
cat > /etc/audit/rules.d/soc-homelab.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/crontab -p wa -k cron
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S execve -k exec
EOF
augenrules --load
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload ssh
```

Install Filebeat 9.5.3 with [`elastic/beats/filebeat-linux.yml`](../elastic/beats/filebeat-linux.yml).

---

## Step 8: Verify the pipeline

```bash
# Wazuh: all agents active, and a rule fires for a test line
docker compose -f /opt/soc-home-lab/wazuh/docker-compose.yml exec wazuh.manager /var/ossec/bin/agent_control -l
docker compose -f /opt/soc-home-lab/wazuh/docker-compose.yml exec wazuh.manager /var/ossec/bin/wazuh-logtest

# Elastic: each data stream is receiving documents
curl -s -u elastic:$ELASTIC_PASSWORD "http://10.0.1.11:9201/_cat/indices/.ds-logs-soc*?v"

# SOAR: health and current blocklist
curl -s http://10.0.1.10:5000/health
curl -s http://10.0.1.10:5000/blocklist.txt

# The repo's own test suite (needs Docker; add -m e2e for the full Elastic stack)
pip install -r requirements-dev.txt && pytest
```

---

## Troubleshooting

| Issue | Check |
|---|---|
| Agent will not enroll | Port 1515/TCP open CORP -> 10.0.1.10, enrollment password matches `authd.pass` |
| No Sysmon alerts in Wazuh | The agent received `shared/agent.conf` (`agent_control -i <id>`); Sysmon service running |
| A custom rule never fires | `docker compose logs wazuh.manager \| grep -i analysisd` for rule warnings; run `pytest tests/wazuh` |
| Logstash not healthy | `docker compose logs logstash`; the `setup` job must have completed |
| No data in a `logs-soc.*` stream | Beats output host/port (5044 Linux, 5045 Windows, 5046 Suricata) and pfSense rules for those ports |
| Suricata sees no traffic | SPAN/promiscuous mode on the sensor adapter; `SPAN_INTERFACE` matches it |
| SOAR rejects alerts (401) | `SOAR_SHARED_SECRET` in `.env` equals `<api_key>` in `ossec.conf`; host clocks within 5 minutes |
