# IOC Enricher

`ioc-enricher` is a production-style Python CLI for SOC automation workflows.  
It ingests raw IOC lists, normalizes and classifies indicators, enriches with threat intelligence, correlates CVEs against CISA KEV, and exports a single analyst-ready CSV.

## Overview

Security teams often receive mixed IOC feeds (CSV/TXT) that are inconsistent and incomplete.  
This project standardizes ingestion and produces a consolidated enrichment output suitable for triage, prioritization, and downstream automation.

## Pipeline Flow

1. Parse input (`.csv` or `.txt`)
2. Detect IOC type and normalize value
3. Enrich supported IOCs with VirusTotal (VT v3)
4. Correlate CVEs with CISA KEV feed
5. Compute `risk_priority`
6. Write a single normalized output CSV

## Supported IOC Types

- `ip`
- `domain`
- `url`
- `hash` (MD5/SHA1/SHA256/SHA512)
- `cve` (for KEV correlation)

## VirusTotal Enrichment

VT is applied only to `ip`, `domain`, `url`, and `hash`.

- `ip` -> `/ip_addresses/{ioc}`
- `domain` -> `/domains/{ioc}`
- `hash` -> `/files/{hash}`
- `url` -> `/urls/{url_id}` (URL-safe base64, no padding)

Key behavior:
- API key is loaded from `.env` (`VT_API_KEY`)
- No hardcoded secrets
- Exponential backoff retries for `429` and timeouts (up to 5 attempts)
- CVEs are intentionally skipped in VT stage (not treated as VT errors)

## CISA KEV Correlation

For `ioc_type == cve`, the tool checks CISA's KEV feed:

- Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Cached locally to avoid repeated downloads during processing
- Fast in-memory lookup by CVE ID

Returned KEV fields:
- `kev_exploited`
- `kev_vendor`
- `kev_product`
- `kev_due_date`

## Risk Priority Logic

| Condition | risk_priority |
|---|---|
| `kev_exploited == True` and `vt_malicious >= 3` | `CRITICAL` |
| `kev_exploited == True` OR `vt_malicious >= 5` | `HIGH` |
| `vt_malicious in [1,2,3,4]` | `MEDIUM` |
| `vt_malicious == 0` or missing | `LOW` |

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

Create `.env`:

```env
VT_API_KEY=your_virustotal_api_key
```

## Usage

```bash
python -m ioc_enricher --input sample.csv --output out.csv
```

Example snippet:

```csv
ioc,ioc_type,timestamp,error,vt_malicious,vt_suspicious,vt_harmless,vt_undetected,vt_error,vt_link,kev_exploited,kev_vendor,kev_product,kev_due_date,risk_priority
8.8.8.8,ip,2026-02-04T00:00:00Z,,0,0,61,32,,https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8,,,,,LOW
CVE-2021-44228,cve,2026-02-04T00:00:00Z,,,,,,,,True,Apache,Log4j2,2021-12-24,HIGH
```

## Output Columns

- `ioc`: normalized indicator value
- `ioc_type`: detected type
- `timestamp`: processing timestamp (UTC)
- `error`: parse/normalization error (if any)
- `vt_malicious`, `vt_suspicious`, `vt_harmless`, `vt_undetected`: VT verdict counters
- `vt_error`: VT request/enrichment error state
- `vt_link`: VT API self link for the IOC
- `kev_exploited`, `kev_vendor`, `kev_product`, `kev_due_date`: KEV correlation fields (CVE rows)
- `risk_priority`: derived triage priority (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`)

## Failure-Tolerance Design

- Invalid IOC rows never stop execution; errors are recorded per row
- VT failures are isolated per IOC (`vt_error`) and do not crash the pipeline
- KEV download/cache errors do not crash processing; CVE KEV state is marked accordingly
- Output CSV is always generated with a stable header order
