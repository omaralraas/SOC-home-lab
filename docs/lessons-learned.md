# Lessons Learned

## Project Journey

This SOC Home Lab was built as a hands-on learning project to develop practical blue team security skills. The goal was to simulate a realistic Security Operations Center environment using open-source tools and apply detection engineering, threat hunting, and incident response skills.

### Timeline
- **Week 1-2:** Network design, pfSense setup, VLAN segmentation
- **Week 3-4:** Wazuh SIEM deployment and agent enrollment
- **Week 5-6:** ELK Stack integration and log pipeline configuration
- **Week 7-8:** Suricata IDS deployment and custom rule development
- **Week 9-10:** Detection rule engineering (Sigma, YARA, Wazuh custom rules)
- **Week 11-12:** Attack simulation, threat hunting, and SOAR automation

---

## Technical Challenges & Solutions

### Challenge 1: Log Volume Management
**Problem:** Elasticsearch disk usage grew rapidly with full syslog ingestion (~2GB/day), threatening to fill the disk within weeks.

**Solution:**
- Moved to data streams (`logs-soc.*`) with a `soc-logs` lifecycle policy: roll over weekly or at
  10 GB per shard, delete after 30 days (`elastic/setup/setup.sh`, verified by the e2e test)
- Reduced Sysmon event collection to security-relevant events with a curated Sysmon config

### Challenge 2: False Positive Tuning
**Problem:** Initial Wazuh rules generated 100+ alerts/day, most were false positives from legitimate Windows services and scheduled tasks.

**Solution:** Iterative refinement process:
1. Monitored alert volume for 1 week to establish baseline
2. Identified top false positive sources (Windows Update, AV scans, backup jobs)
3. Added exclusion conditions to custom rules
4. Tuned frequency and timeframe parameters
5. Reduced noise by 85% while maintaining detection coverage

### Challenge 3: Resource Optimization
**Problem:** Running all VMs simultaneously required 24+ GB RAM, exceeding initial hardware capacity.

**Solution:**
- Sized JVM heaps explicitly: Elasticsearch 1 GB (`ES_HEAP`), Wazuh indexer 1 GB, Logstash 512 MB
- Split the stack across VMs so Wazuh and Elastic never compete for the same memory
- Implemented swap space as buffer for peak usage periods
- Used lightweight Linux containers where possible

### Challenge 4: Detection Coverage Gaps
**Problem:** Coverage was tracked in a hand-written table whose percentages could not be
reproduced and had drifted from the rules.

**Solution:** Coverage is now generated from the rule files themselves:
1. `tools/attack_coverage.py` collects technique IDs from Wazuh, Sigma, Suricata and YARA rules
   and validates them against ATT&CK v20 (which also caught T1562.001 being renamed to T1685)
2. Per-tactic coverage uses ATT&CK's own technique counts as denominators
   ([mitre-coverage.md](mitre-coverage.md)), plus a Navigator layer for the heat map
3. Gaps are prioritised by what the lab can actually observe: Collection and Discovery are the
   largest gaps for the current telemetry

---

## Detection-as-code review (v2)

Rebuilding the lab so every rule, config and query is tested against the real engines in CI
turned up defects that reading the configs had not. The details and root causes are in
[detection-engineering.md](detection-engineering.md); the headline lessons:

1. **A rule that loads is not a rule that fires.** Several Wazuh rules hung off the wrong parent
   rule IDs and could never match, and analysisd only logs a warning for a missing `if_sid`.
   Every custom rule now has a positive test case replayed through `wazuh-logtest`.
2. **Custom rules can silently break stock ones.** Wazuh files each event in either sid-based or
   group-based correlation lists, never both, so one `if_matched_sid` disabled the stock Windows
   brute-force rule. A static lint now models the rule tree to catch this.
3. **Test benign look-alikes, not just attacks.** The DNS, scheduled-task and sudo rules matched
   everyday activity; each rule now ships with negative cases sitting right next to its logic.
4. **Configs must be validated by the software that runs them.** The Suricata config failed
   Suricata's own `-T` check, a single `alert arp` rule stopped a whole rule file loading, Kibana
   rejected its config, and a YARA file never compiled.
5. **Network scope is part of the detection.** With the attacker VLAN inside `HOME_NET`, every
   inbound Suricata rule was blind to the lab's own simulations.

---

## Key Takeaways

1. **Defense in Depth works:** Multiple detection layers (NIDS + HIDS + SIEM) caught threats that individual tools missed
2. **Tuning is ongoing:** Detection engineering is an iterative process, not a one-time setup
3. **Automation is essential:** Manual alert triage doesn't scale - even basic SOAR automation saves significant time
4. **Documentation matters:** Well-documented playbooks and procedures are as important as the tools themselves
5. **Attacker perspective helps:** Using Kali to simulate attacks revealed gaps in detection coverage

---

## Future Improvements

- [ ] **Threat Intelligence Feeds:** Integrate MISP or OpenCTI for automated IOC enrichment
- [ ] **ML-Based Anomaly Detection:** Implement Elasticsearch ML jobs for baseline behavior modeling
- [ ] **Cloud SIEM Integration:** Extend monitoring to cloud environments (AWS CloudTrail, Azure AD)
- [ ] **EDR Integration:** Add Velociraptor or Elastic Agent for advanced endpoint detection
- [ ] **Deception Technology:** Deploy honeypots (Cowrie SSH, HoneyD) for early threat detection
- [ ] **Purple Team Automation:** Build automated attack-and-detect validation pipeline
- [ ] **Case Management:** Integrate TheHive for structured incident tracking

---

## Certifications This Lab Prepares For

| Certification | Relevance |
|--------------|-----------|
| CompTIA Security+ | Foundational security concepts, network security |
| CompTIA CySA+ | SOC operations, threat detection, log analysis |
| Blue Team Level 1 (BTL1) | SIEM usage, incident response, threat hunting |
| Elastic Certified Analyst | Kibana, ES\|QL hunting, dashboards |
| Splunk Core User | Log analysis concepts (transferable skills) |
| GIAC GSOC | SOC analyst skills and methodologies |
