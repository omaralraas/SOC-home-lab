# Setup Guide

Complete step-by-step guide to deploy the SOC Home Lab from scratch.

## Prerequisites

### Hardware (Minimum)
- **CPU:** 8 cores (Intel i7 / AMD Ryzen 7)
- **RAM:** 16 GB DDR4 (32 GB recommended)
- **Storage:** 100 GB SSD (256 GB NVMe recommended)
- **Network:** 1 Gigabit Ethernet adapter

### Software
- [VirtualBox 7.0+](https://www.virtualbox.org/) or [VMware Workstation Pro](https://www.vmware.com/)
- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/)
- ISOs: Ubuntu 22.04 Server, Windows 10, Kali Linux, pfSense

---

## Step 1: Hypervisor Setup

### VirtualBox Configuration
1. Download and install VirtualBox 7.0+
2. Install VirtualBox Extension Pack for USB 3.0 and PXE boot support
3. Create three Host-Only networks:
   - `vboxnet0` → 10.0.0.0/24 (CORP VLAN)
   - `vboxnet1` → 10.0.1.0/24 (SOC_MGMT VLAN)
   - `vboxnet2` → 10.0.2.0/24 (ATTACKER VLAN)

```bash
# Create host-only networks
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 10.0.0.254 --netmask 255.255.255.0
VBoxManage hostonlyif ipconfig vboxnet1 --ip 10.0.1.254 --netmask 255.255.255.0
VBoxManage hostonlyif ipconfig vboxnet2 --ip 10.0.2.254 --netmask 255.255.255.0
```

---

## Step 2: pfSense Firewall Setup

1. Create VM: 1 vCPU, 1 GB RAM, 10 GB disk
2. Attach 4 network adapters:
   - Adapter 1: NAT (WAN)
   - Adapter 2: Host-Only vboxnet0 (CORP)
   - Adapter 3: Host-Only vboxnet1 (SOC_MGMT)
   - Adapter 4: Host-Only vboxnet2 (ATTACKER)
3. Install pfSense from ISO
4. Configure interfaces and assign IPs per [architecture.md](architecture.md)
5. Import firewall rules from `network/firewall-rules/pfsense-rules.conf`

---

## Step 3: Wazuh SIEM Deployment

### Deploy with Docker Compose
```bash
# On the SOC_MGMT VM (10.0.1.10)
cd /opt/soc-homelab/wazuh

# Set environment variables
export INDEXER_PASSWORD=SecurePassword123!
export API_PASSWORD=WazuhAPI456!
export DASHBOARD_PASSWORD=Dashboard789!

# Deploy
docker-compose up -d

# Verify all containers are running
docker-compose ps

# Check Wazuh Manager health
curl -s -k -u wazuh-wui:$API_PASSWORD https://localhost:55000/security/user/authenticate
```

### Enroll Agents
```bash
# On Windows endpoint (10.0.0.50)
# Download Wazuh agent MSI from dashboard
# Install with:
wazuh-agent-4.7.2-1.msi /q WAZUH_MANAGER=10.0.1.10

# On Ubuntu endpoint (10.0.0.51)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install wazuh-agent
sed -i 's/MANAGER_IP/10.0.1.10/' /var/ossec/etc/ossec.conf
systemctl enable --now wazuh-agent
```

---

## Step 4: ELK Stack Deployment

```bash
# On the SOC_MGMT VM (10.0.1.11)
cd /opt/soc-homelab/elastic

# Configure environment
cp .env.example .env
# Edit .env with secure passwords

# Deploy ELK Stack
docker-compose up -d

# Wait for Elasticsearch to be ready
until curl -s -u elastic:$ELASTIC_PASSWORD http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"'; do
    echo "Waiting for Elasticsearch..."
    sleep 10
done

# Create index patterns in Kibana
curl -X POST "http://localhost:5601/api/saved_objects/index-pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -u elastic:$ELASTIC_PASSWORD \
  -d '{"attributes":{"title":"soc-*","timeFieldName":"@timestamp"}}'
```

---

## Step 5: Suricata IDS Installation

```bash
# On SOC_MGMT VM (10.0.1.12)
apt-get update && apt-get install -y suricata

# Copy custom configuration
cp suricata/suricata.yaml /etc/suricata/suricata.yaml
cp suricata/rules/*.rules /etc/suricata/rules/

# Update Suricata rules
suricata-update

# Enable and start Suricata
systemctl enable --now suricata

# Verify Suricata is running
suricata --build-info
tail -f /var/log/suricata/eve.json
```

---

## Step 6: Windows Endpoint Setup (10.0.0.50)

### Install Sysmon
```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon

# Install with SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Configure Audit Policies
```powershell
# Enable advanced audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Object Access" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable

# Enable command line in process creation events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## Step 7: Linux Endpoint Setup (10.0.0.51)

```bash
# Install auditd for enhanced logging
apt-get install -y auditd audispd-plugins

# Configure audit rules
cat >> /etc/audit/rules.d/soc-homelab.rules << 'EOF'
# Monitor file access to sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitor cron modifications
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Process execution monitoring
-a always,exit -F arch=b64 -S execve -k exec
EOF

systemctl restart auditd
```

---

## Step 8: Verification

### Test Alert Generation
```bash
# From Kali Linux (10.0.2.100), generate test alerts:

# 1. SSH brute force (should trigger Wazuh rules 100100-100102)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.51 -t 4

# 2. Port scan (should trigger Suricata rule 1000010)
nmap -sS -T4 10.0.0.0/24

# 3. Web directory scan (should trigger web attack rules)
dirb http://10.0.0.51/

# Verify alerts appear in:
# - Wazuh Dashboard: https://10.0.1.10:443
# - Kibana: http://10.0.1.11:5601
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Wazuh agent not connecting | Check firewall rules for port 1514/TCP between CORP and SOC_MGMT |
| Elasticsearch out of memory | Increase `ES_MEM_LIMIT` in `.env` and restart containers |
| Suricata not capturing traffic | Verify promiscuous mode is enabled on the network adapter |
| No logs in Kibana | Check Logstash is running and index pattern is configured |
| Docker containers restarting | Check `docker logs <container>` for error details |
