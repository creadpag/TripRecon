<div align="center">

![TripRecon Banner](https://github.com/user-attachments/assets/1f080aaf-8735-43c8-b2a9-6da9e60f8798)

# TripRecon v3.0
### Advanced OSINT & Attack Surface Reconnaissance for Bug Bounty

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.0-00d9a3?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](#license)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-f43f5e?style=flat-square)](#)

**TripRecon** is a comprehensive reconnaissance framework that combines 20+ OSINT sources into a single professional HTML + Excel report — built for bug bounty hunters and pentesters.

</div>

---

## Features

| Module | Description | API Required |
|--------|-------------|:---:|
| 🌐 **DNS Records** | Full enumeration — A, MX, TXT, NS, CNAME, SPF/DMARC anchoring | ✗ |
| 🔀 **Subdomains** | crt.sh + HackerTarget + SecurityTrails + AI permutation | Optional |
| 📂 **Sensitive Paths** | `/.env`, `/.git/config`, `/backup.zip`, `/admin`, `/api/v1`, 200+ probes | ✗ |
| 🛡️ **Security Headers** | 10-header audit with risk scoring and remediation per header | ✗ |
| 🌍 **CORS Analysis** | Origin reflection, wildcard + credentials, CORS chain | ✗ |
| 🧱 **WAF Detection** | Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, 20+ signatures | ✗ |
| 🔧 **Tech Stack** | Framework, CMS, CDN, server detection via headers & responses | ✗ |
| 🔌 **Port Scanning** | Top ports with service/banner grab | ✗ |
| 👁️ **Shodan** | CVEs, open ports, org pivot via live Shodan host lookup | ✓ |
| 🕰️ **Wayback Machine** | 47+ URL patterns, GET param mining for SQLi/XSS/SSRF/Redirect | ✗ |
| 🔎 **Google Dorking** | 70+ dorks across Google / Bing / DuckDuckGo / Brave | Optional |
| 💧 **Leak Database** | ProxyNova breach lookup — emails, passwords, sources | ✗ |
| 🦠 **VirusTotal** | Domain reputation, malicious detections, URL scan history | ✓ |
| 🔭 **URLScan.io** | Screenshot + DOM analysis history for the target | ✓ |
| 🗺️ **ASN / BGP** | RIPE Stat full prefix map + organization pivot | ✗ |
| 📋 **WHOIS / RDAP** | Registrar, expiry, registrant, hidden contact detection | ✗ |
| 🖼️ **Favicon Hash** | MMH3 hash for Shodan `http.favicon.hash:` pivot | ✗ |
| ✉️ **Email Security** | SPF, DMARC policy + pct, DKIM selector check | ✗ |
| 📜 **JS Analysis** | Spider JS files → extract API endpoints + 30+ secret patterns | ✗ |
| ⚡ **Subdomain Takeover** | CNAME → unclaimed cloud service detection (Azure, GitHub, Heroku…) | ✗ |
| 🪣 **Bucket Finder** | AWS S3, GCP, Azure Blob public bucket enumeration | ✗ |
| 🐙 **GitHub Dorking** | Secrets, `.env` files, API keys in public repos linked to target | Optional |

---

## Installation

```bash
# Clone
git clone https://github.com/youruser/triprecon.git
cd triprecon

# Install dependencies
pip install -r requirements.txt

# Copy and fill your API keys
cp .env.example .env
```

### Requirements

```
python >= 3.10
requests
rich
jinja2
openpyxl
dnspython
python-dotenv
```

---

## API Keys (`.env`)

```env
# ── Required for full coverage ─────────────────────────────────────
SHODAN_API_KEY=           # https://account.shodan.io
VIRUSTOTAL_API_KEY=       # https://www.virustotal.com/gui/my-apikey
URLSCAN_API_KEY=          # https://urlscan.io/user/signup

# ── Recommended ────────────────────────────────────────────────────
SECURITYTRAILS_API_KEY=   # https://securitytrails.com/app/account/credentials
GITHUB_TOKEN=             # https://github.com/settings/tokens  (no scopes needed)
NETLAS_API_KEY=           # https://app.netlas.io/profile/

# ── Dorking (optional — use --sinapigoogle / --sinapibing for free) ─
GOOGLE_API_KEY=           # console.cloud.google.com → Custom Search API
GOOGLE_CSE_ID=            # programmablesearchengine.google.com
BING_API_KEY=             # portal.azure.com → Bing Search v7
BRAVE_API_KEY=            # api.search.brave.com
HUNTERHOW_API_KEY=        # hunter.how
```

> **Note:** All API keys are optional. TripRecon skips modules gracefully when keys are absent and still runs full passive recon without any key.

---

## Usage

```bash
# Quick scan — one domain
python triprecon.py -d target.com

# Full recon — all modules
python triprecon.py -d target.com --all

# Full scan with custom output folder
python triprecon.py -d target.com --all -o ./reports/target

# Batch scan from file
python triprecon.py -l domains.txt --all -o ./reports

# Targeted attack surface scan
python triprecon.py -d target.com --js --takeover --cors --waf --buckets

# Dorking with custom dork file
python triprecon.py -d target.com --dork dorks.txt --engines google,bing,ddg

# Dorking WITHOUT API keys (free scraping mode)
python triprecon.py -d target.com --dork dorks.txt --engines google --sinapigoogle
python triprecon.py -d target.com --dork dorks.txt --engines bing   --sinapibing
```

### All Flags

```
target:
  -d, --domain      Single target domain
  -l, --list        File with one domain per line

output:
  -o, --output      Output directory (default: current dir)

recon modules:
  --all             Enable all modules below
  --wayback         Wayback Machine URL mining + GET param extraction
  --analyze-headers Security header audit (X-Frame-Options, CSP, HSTS…)
  --check-paths     Sensitive path probing (/.env, /.git, /admin…)
  --cors            CORS misconfiguration detection
  --waf             WAF fingerprinting
  --detect-tech     Technology stack detection
  --scan-ports      Top port scan with service/banner grab
  --js              JavaScript file crawl → secrets + endpoint extraction
  --takeover        Subdomain takeover detection (CNAME to unclaimed services)
  --buckets         Cloud bucket enumeration (S3, GCP, Azure Blob)
  --github          GitHub dorking for secrets linked to target

search engines (require --dork):
  --engines         Comma-separated: google,bing,ddg,brave  (default: google)
  --sinapigoogle    Scrape Google without API key
  --sinapibing      Scrape Bing without API key
```

---

## Output

Every scan produces two files in the output directory:

```
reports/
├── triprecon_target.com.html    ← Interactive HTML report (client-ready)
└── triprecon_target.com.xlsx    ← Excel workbook (all data, filterable)
```

### HTML Report

The HTML report uses a dark-theme professional layout with:

- **Sidebar navigation** — jump to any section instantly
- **Topbar** — domain, scan date, risk grade chip
- **Stats grid** — at-a-glance counts for all modules
- **Executive Summary** — risk score (0–100), grade (A–F), all findings with severity badges
- **Attack Vectors table** — auto-generated recommendations per finding
- **Per-section tables** — DNS / Subdomains / Paths / Headers / CORS / WAF / Ports / Shodan / Wayback / Dorks / Leaks / VirusTotal / URLScan / ASN / WHOIS / Email / JS / Params / Takeover / Buckets / GitHub
- **Charts** — security headers coverage, port distribution, subdomain sources
- **Print / PDF** — browser print produces a clean client-ready PDF

### Risk Scoring

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | 80–100 | Low attack surface, well hardened |
| **B** | 60–79  | Minor issues, generally secure |
| **C** | 40–59  | Moderate exposure, fix required |
| **D** | 20–39  | High exposure, multiple vectors |
| **F** | 0–19   | Critical — immediate action required |

---

## Examples

<details>
<summary>Single domain — full recon</summary>

```bash
python triprecon.py -d hackerone.com --all -o ./out
```

</details>

<details>
<summary>Batch bug bounty program scope</summary>

```bash
cat scope.txt
api.target.com
cdn.target.com
auth.target.com

python triprecon.py -l scope.txt --all --js --takeover -o ./reports
```

</details>

<details>
<summary>Dork campaign — no API keys needed</summary>

```bash
python triprecon.py -d target.com \
  --dork dorks.txt \
  --engines google,bing,ddg \
  --sinapigoogle \
  --sinapibing
```

</details>

---

## Project Structure

```
triprecon/
├── triprecon.py        # Main script
├── .env.example        # API key template
├── requirements.txt    # Python dependencies
├── dorks/
│   └── default.txt     # Default dork list (70+ queries)
└── reports/            # Output directory (auto-created)
```

---

## Disclaimer

> TripRecon is intended **only for authorized security testing** — bug bounty programs, penetration tests with written permission, or your own assets. Running this tool against targets without authorization is illegal. The author assumes no responsibility for misuse.

---

## License

MIT © 2026 — Built for the bug bounty community 🐛

---

<div align="center">

**TripRecon v3.0** · Made with 💀 for bug bounty hunters

</div>
