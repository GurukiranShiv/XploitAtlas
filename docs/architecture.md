# Architecture

## Goal

The platform converts raw vulnerability scanner findings into an exploit-aware remediation queue. Traditional scanner output usually sorts by CVSS severity, but SOC and vulnerability-management teams need to know which issue is most likely to be exploited and which asset matters most.

## Components

1. **FastAPI backend**
   - REST API for assets, findings, imports, statistics, and score previews.
   - Swagger UI at `/docs`.

2. **Database layer**
   - SQLite by default for local testing.
   - PostgreSQL supported through Docker Compose.
   - Tables: `assets`, `threat_intel`, `findings`.

3. **Threat-intelligence enrichment**
   - FIRST EPSS API for exploitation probability.
   - CISA KEV JSON catalog for known real-world exploitation.
   - Local threat-intel cache avoids repeated API calls.

4. **Scanner ingestion**
   - Nuclei JSONL parser.
   - OpenVAS/GVM CSV parser.
   - Import functions normalize host, CVE, scanner plugin ID, severity, CVSS, port, service, and remediation text.

5. **Risk scoring engine**
   - CVSS: technical severity.
   - EPSS: likelihood of exploitation.
   - CISA KEV: confirmed active exploitation.
   - Exploit maturity: none, PoC, public, weaponized.
   - Exposure: internet, DMZ, internal, dev/lab.
   - Business criticality: asset impact from 1 to 5.

6. **Frontend dashboard**
   - Displays score cards and ranked findings.
   - Imports scanner files.
   - Provides score preview for interview walkthroughs.

## Data Flow

```text
OpenVAS/Nuclei finding
        |
        v
Parser normalizes scanner output
        |
        v
CVE enrichment from EPSS + CISA KEV
        |
        v
Risk scoring engine combines technical + threat + business context
        |
        v
Prioritized remediation queue with SLA and reason
```

## Scoring Formula

The score is calculated from weighted normalized components:

| Signal | Weight | Why it matters |
| --- | ---: | --- |
| CVSS | 25% | Technical severity |
| EPSS | 25% | Probability of exploitation |
| CISA KEV | 20% | Real-world exploitation evidence |
| Exposure | 15% | Internet-facing assets are easier to attack |
| Business criticality | 10% | Business impact of compromised asset |
| Exploit maturity | 5% | PoC/public/weaponized exploit availability |

Extra modifiers are applied for known ransomware usage, KEV on exposed assets, and extremely high EPSS + high CVSS combinations.

## Why this is advanced

This project is advanced because it does not stop at vulnerability scanning. It implements the decision logic that a SOC or vulnerability-management team would use to reduce alert fatigue and patch the most dangerous issues first.
