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

**Solution:** Implemented Index Lifecycle Management (ILM) policies:
- Hot phase: 7 days (high-performance SSD)
- Delete phase: 30 days (auto-cleanup)
- Reduced Sysmon event collection to security-relevant events only
- Configured Logstash to drop noisy, low-value events before indexing

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
- Set Docker resource limits for all containers (`deploy.resources.limits.memory`)
- Configured Elasticsearch JVM heap to 1GB (sufficient for home lab data volume)
- Reduced Logstash worker threads from default to 2
- Implemented swap space as buffer for peak usage periods
- Used lightweight Linux containers where possible

### Challenge 4: Detection Coverage Gaps
**Problem:** Initial detection rules only covered 30% of relevant MITRE ATT&CK techniques.

**Solution:** Systematic gap analysis:
1. Mapped all existing rules to MITRE ATT&CK techniques
2. Identified uncovered tactics (especially Initial Access and Collection)
3. Prioritized rules based on likelihood and impact
4. Added Sigma rules for broader detection coverage
5. Achieved 60%+ coverage across high-priority techniques

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
| Elastic Certified Analyst | Kibana, KQL queries, dashboard creation |
| Splunk Core User | Log analysis concepts (transferable skills) |
| GIAC GSOC | SOC analyst skills and methodologies |
