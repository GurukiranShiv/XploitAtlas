# Interview Explanation

## 60-second version

I built an Exploit-Aware Vulnerability Prioritization Platform that takes scanner results from tools like OpenVAS and Nuclei and ranks vulnerabilities based on real risk, not just CVSS. The system enriches each CVE with EPSS exploitation probability and CISA KEV known-exploited status, then combines that with exploit maturity, asset exposure, and business criticality. The final output is a prioritized remediation queue with a risk score, severity rating, SLA, and an explanation of why each finding should be fixed first.

## What problem it solves

Normal vulnerability scanners produce too many findings and often sort by CVSS alone. In real SOC operations, a vulnerability with CVSS 9.8 on an internal dev server may be less urgent than a CVSS 8.8 issue on an internet-facing production asset that is in CISA KEV and has public exploit activity. This project solves that gap by adding threat intelligence and asset context.

## STAR answer

**Situation:** Vulnerability scanners generate large volumes of findings, and sorting only by CVSS can create poor prioritization.

**Task:** I wanted to build a realistic SOC-style platform that prioritizes remediation based on exploitability, active exploitation, and asset risk.

**Action:** I developed a FastAPI application with SQLAlchemy models for assets, findings, and threat-intelligence cache. I added import parsers for OpenVAS CSV and Nuclei JSONL, integrated EPSS and CISA KEV enrichment, and created an explainable scoring model using CVSS, EPSS, KEV, exploit maturity, exposure, and business criticality. I also built a dashboard to display ranked findings, SLA, and reasoning.

**Result:** The platform produces a practical remediation queue that helps analysts focus on the vulnerabilities most likely to be exploited against the most important assets. It demonstrates vulnerability management, SOC triage, threat intelligence enrichment, API development, database design, and risk-based prioritization.

## Key technical points to explain

- **Why CVSS alone is not enough:** CVSS measures severity but not the likelihood that attackers are currently exploiting the vulnerability.
- **Why EPSS helps:** EPSS provides a probability-style signal for exploitation likelihood.
- **Why KEV matters:** CISA KEV indicates the vulnerability has confirmed real-world exploitation.
- **Why asset exposure matters:** Internet-facing assets are easier to reach than internal-only systems.
- **Why business criticality matters:** A vulnerability on a crown-jewel system should be prioritized over a similar vulnerability on a low-impact lab host.
- **Why explainability matters:** Analysts and managers need to understand why a finding was prioritized.

## Safe project walkthrough

1. Start the backend.
2. Click `/seed-sample-data` or the dashboard's **Load Sample Scanner Findings** button.
3. Show the ranked findings.
4. Compare Log4Shell/MOVEit-style KEV findings against the sample high-CVSS but low-context dev finding.
5. Explain how the tool helps reduce false urgency and patching noise.

## Possible interviewer questions

### Why did you use EPSS and CISA KEV together?
EPSS estimates exploitation likelihood, while KEV confirms known real-world exploitation. EPSS is predictive, and KEV is evidence-based. Using both gives a better prioritization signal than either one alone.

### Why did you include asset exposure?
A vulnerable internet-facing production asset creates a higher attack opportunity than the same CVE on an isolated internal host. Exposure turns a generic CVE score into organization-specific risk.

### How would you improve this project in production?
I would add authentication, role-based access, scheduled enrichment jobs, scanner connectors, CMDB integration, Jira/ServiceNow ticket creation, SLA tracking, and historical risk trend dashboards.

### Is this a scanner?
No. It is a prioritization and enrichment layer. It consumes scanner output and decides what should be fixed first.
