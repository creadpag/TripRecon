#!/usr/bin/env python3
"""
TripRecon v3.0 — Advanced OSINT & Reconnaissance for Bug Bounty
By CreadPag | For authorized security testing ONLY

v3 additions over v3:
  - ASN enumeration via Team Cymru DNS + RIPE Stat — find all IP ranges owned by target org
  - WHOIS data — pivoting by registrant, email, org
  - Favicon hash (MurmurHash3) — Shodan pivot to find same stack on other IPs
  - JavaScript endpoint extraction — spider JS files, extract API paths & secrets
  - Wayback parameter mining — extract unique GET params for fuzzing
  - Subdomain takeover detection — CNAME to dangling services (S3, GH Pages, etc.)
  - GitHub dorking — secrets, tokens, API keys in public repos
  - Cloud bucket enumeration — S3/GCS/Azure bucket permutations (no download)
  - SPF/DMARC deep analysis — email spoofing surface
  - Improved risk scoring with new finding categories
"""

import os
import re
import sys
import json
import time
import random
import socket
import struct
import base64
import hashlib
import logging
import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
import dns.resolver
import pandas as pd
from bs4 import BeautifulSoup
from jinja2 import Template
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from dotenv import load_dotenv

# ── Optional: pip install duckduckgo-search ──────────────────────────────────
try:
    from duckduckgo_search import DDGS
    DDG_AVAILABLE = True
except ImportError:
    DDG_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "3.0"

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

SECURITY_HEADER_LIST: List[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

# Paths that commonly reveal critical vulnerabilities
SENSITIVE_PATHS: List[str] = [
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/config.php", "/wp-config.php", "/configuration.php",
    "/config.yml", "/config.yaml", "/config.json",
    "/database.sql", "/dump.sql", "/backup.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/.backup",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/administrator/", "/wp-admin/", "/manager/",
    "/api/v1/", "/api/v2/", "/api/", "/swagger/", "/api-docs/",
    "/graphql", "/graphiql", "/graphql/playground",
    "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/server-status", "/server-info", "/.DS_Store",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/web.config", "/app.config",
    "/package.json", "/composer.json", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml",
    "/.travis.yml", "/Jenkinsfile", "/.circleci/config.yml",
    "/proc/self/environ",  # LFI indicator
    "/etc/passwd",         # LFI indicator
]

# WAF signatures
WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":    ["__cfduid", "cf-ray", "cloudflare"],
    "AWS WAF":       ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":        ["akamai-ghost", "x-check-cacheable"],
    "Sucuri":        ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":       ["x-iinfo", "x-cdn=imperva"],
    "F5 BIG-IP":     ["x-wa-info", "x-forwarded-for"],
    "ModSecurity":   ["mod_security", "modsecurity"],
    "Barracuda":     ["barra_counter_session"],
    "Wordfence":     ["wordfence"],
}

DEFAULT_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    445, 587, 993, 995, 3306, 3389, 5432,
    6379, 8080, 8443, 8888, 9200, 27017,
]

# Subdomain takeover: CNAME fingerprints for dangling services
# Source: https://github.com/EdOverflow/can-i-take-over-xyz
TAKEOVER_FINGERPRINTS: Dict[str, Dict] = {
    "Amazon S3":          {"cname": ["s3.amazonaws.com"], "body": ["NoSuchBucket", "The specified bucket does not exist"], "severity": "HIGH"},
    "GitHub Pages":       {"cname": ["github.io", "github.com"], "body": ["There isn't a GitHub Pages site here"], "severity": "HIGH"},
    "Heroku":             {"cname": ["herokudns.com", "herokuapp.com"], "body": ["No such app", "herokucdn.com/error-pages"], "severity": "HIGH"},
    "Fastly":             {"cname": ["fastly.net"], "body": ["Fastly error: unknown domain"], "severity": "HIGH"},
    "Ghost":              {"cname": ["ghost.io"], "body": ["The thing you were looking for is no longer here"], "severity": "MEDIUM"},
    "Shopify":            {"cname": ["myshopify.com", "shopify.com"], "body": ["Sorry, this shop is currently unavailable"], "severity": "MEDIUM"},
    "Tumblr":             {"cname": ["domains.tumblr.com"], "body": ["Whatever you were looking for doesn't currently exist"], "severity": "MEDIUM"},
    "Zendesk":            {"cname": ["zendesk.com"], "body": ["Help Center Closed"], "severity": "MEDIUM"},
    "Unbounce":           {"cname": ["unbouncepages.com"], "body": ["The requested URL was not found on this server"], "severity": "MEDIUM"},
    "HubSpot":            {"cname": ["hubspot.com", "hs-sites.com"], "body": ["does not exist in our system"], "severity": "MEDIUM"},
    "Netlify":            {"cname": ["netlify.com", "netlify.app"], "body": ["Not found - Request ID"], "severity": "HIGH"},
    "Surge.sh":           {"cname": ["surge.sh"], "body": ["project not found"], "severity": "HIGH"},
    "Azure":              {"cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"], "body": ["404 Web Site not found"], "severity": "HIGH"},
    "Fly.io":             {"cname": ["fly.dev"], "body": ["404 Not Found"], "severity": "MEDIUM"},
    "Pantheon":           {"cname": ["pantheonsite.io"], "body": ["The gods are wise"], "severity": "MEDIUM"},
    "Acquia":             {"cname": ["acquia-sites.com"], "body": ["Web Site not found"], "severity": "MEDIUM"},
    "Webflow":            {"cname": ["proxy.webflow.com", "webflow.io"], "body": ["The page you are looking for doesn't exist"], "severity": "MEDIUM"},
    "WP Engine":          {"cname": ["wpengine.com"], "body": ["The site you were looking for couldn't be found"], "severity": "MEDIUM"},
    "Strikingly":         {"cname": ["s.strikinglydns.com"], "body": ["page not found"], "severity": "LOW"},
    "Readme.io":          {"cname": ["readme.io"], "body": ["Project doesnt exist"], "severity": "MEDIUM"},
    "Bitbucket":          {"cname": ["bitbucket.io"], "body": ["Repository not found"], "severity": "HIGH"},
    "Squarespace":        {"cname": ["squarespace.com"], "body": ["No Such Account"], "severity": "LOW"},
}

# Cloud bucket name permutations (replaced {domain} and {tld} at runtime)
BUCKET_PATTERNS: List[str] = [
    "{org}", "{org}-dev", "{org}-prod", "{org}-staging", "{org}-backup",
    "{org}-data", "{org}-assets", "{org}-static", "{org}-media", "{org}-logs",
    "{org}-uploads", "{org}-public", "{org}-private", "{org}-internal",
    "{org}.com", "{org}.net", "{org}-files", "{org}-storage", "{org}-bucket",
    "dev.{org}", "staging.{org}", "prod.{org}", "cdn.{org}", "assets.{org}",
    "backup.{org}", "static.{org}", "media.{org}", "data.{org}",
]

# Regex patterns for secrets in JS files
JS_SECRET_PATTERNS: Dict[str, str] = {
    "AWS Access Key":         r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":         r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":         r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":           r"gh[pousr]_[A-Za-z0-9]{36}",
    "Slack Token":            r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Stripe Key":             r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Twilio Key":             r"SK[0-9a-fA-F]{32}",
    "SendGrid Key":           r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "JWT Token":              r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
    "Private Key Header":     r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "Bearer Token":           r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}",
    "API Key Generic":        r"(?i)api[_\-]?key['\"\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
    "Password in JS":         r"(?i)(?:password|passwd|pwd)['\"\s:=]+['\"]([^'\"]{8,})['\"]",
    "Database URL":           r"(?i)(?:mysql|postgres|mongodb|redis)://[^\s'\"]+",
    "Internal URL":           r"https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s'\"]+",
}

# Extensions whose URLs are collected as-is — never fetched/downloaded
FILE_DORK_EXTENSIONS: Dict[str, str] = {
    # Documents / configs
    ".pdf":    "PDF",
    ".doc":    "DOC",  ".docx": "DOCX",
    ".xls":    "XLS",  ".xlsx": "XLSX",
    ".ppt":    "PPT",  ".pptx": "PPTX",
    ".txt":    "TXT",
    ".csv":    "CSV",
    # Source / config
    ".xml":    "XML",
    ".json":   "JSON",
    ".yml":    "YAML", ".yaml": "YAML",
    ".env":    "ENV",
    ".conf":   "CONF", ".cfg":  "CFG",
    ".ini":    "INI",
    ".log":    "LOG",
    # Archives / backups
    ".zip":    "ZIP",  ".tar":  "TAR",
    ".gz":     "GZ",   ".bz2":  "BZ2",
    ".7z":     "7Z",   ".rar":  "RAR",
    ".bak":    "BAK",  ".old":  "OLD",
    ".backup": "BAK",  ".dump": "DUMP",
    # Database
    ".sql":    "SQL",  ".db":   "DB",
    ".sqlite": "SQLITE",
    # Scripts / code
    ".php":    "PHP",  ".asp":  "ASP",
    ".aspx":   "ASPX", ".jsp":  "JSP",
    ".py":     "PY",   ".rb":   "RB",
    ".sh":     "SH",   ".bash": "SH",
    # Certificates / keys
    ".pem":    "PEM",  ".key":  "KEY",
    ".crt":    "CRT",  ".cer":  "CER",
    ".p12":    "P12",  ".pfx":  "PFX",
}

# Dork categories — used to organise dorks in the HTML report
# Each entry: category_name -> list of dork templates
# Use {domain} placeholder; it is replaced at runtime
DORK_CATEGORIES: Dict[str, List[str]] = {
    "🔑 Login / Auth": [
        'site:{domain} inurl:login',
        'site:{domain} inurl:signin',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:portal',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:account',
        'site:{domain} intitle:"login" OR intitle:"sign in"',
    ],
    "📄 Sensitive Files": [
        'site:{domain} ext:pdf',
        'site:{domain} ext:doc OR ext:docx',
        'site:{domain} ext:xls OR ext:xlsx',
        'site:{domain} ext:ppt OR ext:pptx',
        'site:{domain} ext:txt',
        'site:{domain} ext:csv',
        'site:{domain} ext:log',
        'site:{domain} ext:xml',
    ],
    "🗜️ Backups & Archives": [
        'site:{domain} ext:zip OR ext:tar OR ext:gz',
        'site:{domain} ext:bak OR ext:old OR ext:backup',
        'site:{domain} ext:sql OR ext:dump OR ext:db',
        'site:{domain} ext:7z OR ext:rar',
        'site:{domain} inurl:backup',
        'site:{domain} intitle:"index of" backup',
    ],
    "⚙️ Config & Source": [
        'site:{domain} ext:env',
        'site:{domain} ext:conf OR ext:cfg OR ext:ini',
        'site:{domain} ext:yml OR ext:yaml',
        'site:{domain} ext:json inurl:config',
        'site:{domain} inurl:.git',
        'site:{domain} inurl:wp-config',
        'site:{domain} inurl:phpinfo',
        'site:{domain} ext:php inurl:config',
    ],
    "🔓 Keys & Certificates": [
        'site:{domain} ext:pem OR ext:key',
        'site:{domain} ext:crt OR ext:cer OR ext:pfx',
        'site:{domain} ext:p12',
        'site:{domain} inurl:private',
        'site:{domain} intext:"BEGIN RSA PRIVATE KEY"',
        'site:{domain} intext:"BEGIN CERTIFICATE"',
    ],
    "🌐 API & Endpoints": [
        'site:{domain} inurl:api',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:graphql',
        'site:{domain} inurl:v1 OR inurl:v2 OR inurl:v3',
        'site:{domain} inurl:rest',
        'site:{domain} inurl:endpoint',
        'site:{domain} inurl:json',
        'site:{domain} filetype:wsdl',
    ],
    "☁️ Cloud Storage": [
        'site:s3.amazonaws.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:{domain} inurl:s3',
        'site:{domain} inurl:bucket',
    ],
    "💬 Exposed Info": [
        'site:{domain} intext:"password"',
        'site:{domain} intext:"username"',
        'site:{domain} intext:"api_key" OR intext:"apikey"',
        'site:{domain} intext:"secret"',
        'site:{domain} intext:"token"',
        'site:{domain} intext:"DB_PASS" OR intext:"DB_USER"',
        'site:{domain} intitle:"index of"',
        'site:{domain} intext:"Warning: mysql_"',
        'site:{domain} intext:"ORA-" intext:"error"',
    ],
    "🔍 Subdomains / Infra": [
        'site:{domain} -www',
        'site:{domain} inurl:dev OR inurl:staging OR inurl:test',
        'site:{domain} inurl:internal',
        'site:{domain} inurl:vpn OR inurl:ssh',
        'site:{domain} inurl:jira OR inurl:confluence OR inurl:jenkins',
        'site:{domain} inurl:gitlab OR inurl:bitbucket',
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  (loaded from .env)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Config:
    shodan_key:         str   = field(default_factory=lambda: os.getenv("SHODAN_API_KEY", ""))
    securitytrails_key: str   = field(default_factory=lambda: os.getenv("SECURITYTRAILS_API_KEY", ""))
    google_api_key:     str   = field(default_factory=lambda: os.getenv("GOOGLE_API_KEY", ""))
    google_cse_id:      str   = field(default_factory=lambda: os.getenv("GOOGLE_CSE_ID", ""))
    bing_api_key:       str   = field(default_factory=lambda: os.getenv("BING_API_KEY", ""))
    brave_api_key:      str   = field(default_factory=lambda: os.getenv("BRAVE_API_KEY", ""))
    netlas_key:         str   = field(default_factory=lambda: os.getenv("NETLAS_API_KEY", ""))
    hunterhow_key:      str   = field(default_factory=lambda: os.getenv("HUNTERHOW_API_KEY", ""))
    virustotal_key:     str   = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    urlscan_key:        str   = field(default_factory=lambda: os.getenv("URLSCAN_API_KEY", ""))
    ipinfo_key:         str   = field(default_factory=lambda: os.getenv("IPINFO_API_KEY", ""))
    github_token:       str   = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    proxy:              str   = field(default_factory=lambda: os.getenv("PROXY", ""))
    max_threads:        int   = field(default_factory=lambda: int(os.getenv("MAX_THREADS", "15")))
    request_delay:      float = field(default_factory=lambda: float(os.getenv("REQUEST_DELAY", "1.5")))
    timeout:            int   = field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "15")))
    scrape_delay_min:   float = field(default_factory=lambda: float(os.getenv("SCRAPE_DELAY_MIN", "2.0")))
    scrape_delay_max:   float = field(default_factory=lambda: float(os.getenv("SCRAPE_DELAY_MAX", "5.0")))

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def rand_headers() -> Dict[str, str]:
    return {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
        "Cache-Control":   "no-cache",
    }

def make_request(
    url: str,
    cfg: Config,
    method: str = "GET",
    extra_headers: Optional[Dict] = None,
    **kwargs,
) -> Optional[requests.Response]:
    """Unified request: retry × 3, proxy, random UA, exponential backoff."""
    proxies = {"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None
    headers = rand_headers()
    if extra_headers:
        headers.update(extra_headers)

    for attempt in range(3):
        try:
            resp = requests.request(
                method, url,
                headers=headers,
                timeout=cfg.timeout,
                verify=False,
                proxies=proxies,
                allow_redirects=True,
                **kwargs,
            )
            return resp
        except requests.exceptions.Timeout:
            console.print(f"[yellow]  ⚠ Timeout {url} (attempt {attempt+1}/3)[/yellow]")
        except requests.exceptions.ConnectionError:
            console.print(f"[yellow]  ⚠ Connection error {url} (attempt {attempt+1}/3)[/yellow]")
        except Exception as e:
            console.print(f"[red]  ✗ Request failed {url}: {e}[/red]")
            break
        time.sleep(2 ** attempt)
    return None

def scrape_delay(cfg: Config) -> None:
    time.sleep(random.uniform(cfg.scrape_delay_min, cfg.scrape_delay_max))

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    banner = r"""
 ___________      .__      __________
 \__    ___/______|__|_____\______   \ ____   ____  ____   ____
   |    |  \_  __ \  \____ \|       _// __ \_/ ___\/  _ \ /    \
   |    |   |  | \/  |  |_> >    |   \  ___/\  \__(  <_> )   |  \
   |____|   |__|  |__|   __/|____|_  /\___  >\___  >____/|___|  /
                     |__|          \/     \/     \/           \/  v3.0
    """
    console.print(Panel.fit(
        Text(banner, style="bold green"),
        title=f"[blink]TripRecon v{VERSION}[/blink]",
        subtitle="[blue]Bug Bounty Edition — by CreadPag[/]",
        border_style="blue",
    ))

# ─────────────────────────────────────────────────────────────────────────────
# ARG PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "TripRecon v3.0 — Advanced Bug Bounty Reconnaissance Suite\n"
            "For authorized security testing ONLY."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # Quick scan (DNS + WHOIS + ASN + subdomains + Shodan + VirusTotal)
  python triprecon.py -d target.com

  # Full scan — all modules enabled
  python triprecon.py -d target.com --all

  # Full scan with GitHub dorking and custom output folder
  python triprecon.py -d target.com --all -o ./reports/target

  # Multiple domains from file
  python triprecon.py -l domains.txt --all -o ./reports

  # Select specific modules
  python triprecon.py -d target.com --js --takeover --cors --waf --buckets

  # Dork with custom file + multiple search engines
  python triprecon.py -d target.com --dork dorks.txt --engines google,bing,ddg

  # Use DuckDuckGo scraping (no API key needed)
  python triprecon.py -d target.com --dork dorks.txt --engines ddg

  # Force scraping instead of API (bypass key requirement)
  python triprecon.py -d target.com --sinapigoogle --sinapibing --all

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FREE MODULES (no key required — always run)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DNS records + Email security (SPF/DMARC/DKIM)
  ASN enumeration (Team Cymru DNS + RIPE Stat + ip-api.com)
  WHOIS / RDAP (rdap.org)
  crt.sh subdomains (Certificate Transparency)
  HackerTarget subdomains (free API)
  Favicon hash (MurmurHash3 → Shodan pivot)
  ProxyNova credential leaks

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Results are saved in: <output_dir>/triprecon_<domain>.[html|xlsx|json]
  Default output dir  : ./<domain_with_underscores>/
  Override with -o    : -o ./reports/client_name
""",
    )

    # ── Target ────────────────────────────────────────────────────────────────
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain", type=str,
                        metavar="DOMAIN",
                        help="Single target domain (e.g. target.com)")
    target.add_argument("-l", "--list",   type=str,
                        metavar="FILE",
                        help="File with one domain per line")

    # ── Output ────────────────────────────────────────────────────────────────
    p.add_argument("-o", "--output", type=str, default=None,
                   metavar="DIR",
                   help="Output directory for reports (default: ./<domain>/)")

    # ── Dork file ─────────────────────────────────────────────────────────────
    p.add_argument("--dork", type=str,
                   metavar="FILE",
                   help="File with dork templates — use {domain} as placeholder")

    # ── Search engines ────────────────────────────────────────────────────────
    eng = p.add_argument_group("Search Engines (require --dork)")
    eng.add_argument("--engines", type=str, default="google",
                     metavar="LIST",
                     help="Comma-separated engines: google,bing,ddg,yahoo,yandex,brave,all  (default: google)")
    eng.add_argument("--sinapigoogle", action="store_true",
                     help="Force Google scraping instead of Custom Search API")
    eng.add_argument("--sinapibing",   action="store_true",
                     help="Force Bing scraping instead of Bing Search API")

    # ── Extended recon ────────────────────────────────────────────────────────
    recon = p.add_argument_group("Extended Recon Modules")
    recon.add_argument("--all",             action="store_true",
                       help="Enable ALL extended recon modules below")
    recon.add_argument("--wayback",         action="store_true",
                       help="Fetch URLs from Wayback Machine CDX API + mine GET params")
    recon.add_argument("--analyze-headers", action="store_true",
                       help="Analyze HTTP security headers (HSTS, CSP, X-Frame, etc.)")
    recon.add_argument("--check-paths",     action="store_true",
                       help="Probe sensitive paths: /.env /.git /backup.zip /admin etc.")
    recon.add_argument("--cors",            action="store_true",
                       help="Test for CORS misconfigurations (wildcard, credential leak)")
    recon.add_argument("--waf",             action="store_true",
                       help="Detect WAF / CDN presence (Cloudflare, Akamai, etc.)")
    recon.add_argument("--detect-tech",     action="store_true",
                       help="Fingerprint technology stack (CMS, framework, server)")
    recon.add_argument("--scan-ports",      action="store_true",
                       help="TCP port scan on ~100 common ports")
    recon.add_argument("--js",              action="store_true",
                       help="Crawl JS files — extract API endpoints and leaked secrets")
    recon.add_argument("--takeover",        action="store_true",
                       help="Detect subdomain takeover (dangling CNAME → S3/GH Pages/etc.)")
    recon.add_argument("--buckets",         action="store_true",
                       help="Enumerate exposed cloud buckets: S3 / GCS / Azure Blob")
    recon.add_argument("--github",          action="store_true",
                       help="GitHub dorking for secrets/tokens/keys (set GITHUB_TOKEN for best results)")

    return p.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# DORK FILE
# ─────────────────────────────────────────────────────────────────────────────

def read_dorks(path: str) -> List[str]:
    try:
        dorks = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith("#"):
                    dorks.append(d)
        console.print(f"[green]  ✓ Loaded {len(dorks)} dorks from {path}[/green]")
        return dorks
    except FileNotFoundError:
        console.print(f"[red]  ✗ Dork file not found: {path}[/red]")
        return []

# ─────────────────────────────────────────────────────────────────────────────
# RECON MODULES — INFRASTRUCTURE
# ─────────────────────────────────────────────────────────────────────────────

def get_ip(domain: str) -> str:
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"[green]  ✓ IP resolved:[/green] {ip}")
        return ip
    except socket.gaierror as e:
        console.print(f"[red]  ✗ Cannot resolve {domain}: {e}[/red]")
        return ""

def get_dns_records(domain: str) -> Dict[str, List[str]]:
    resolver = dns.resolver.Resolver()
    result: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}

    for rtype in result:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                result[rtype] = sorted([str(r.exchange) for r in answers])
            elif rtype == "NS":
                result[rtype] = sorted([str(r.target)   for r in answers])
            else:
                result[rtype] = sorted([str(r)          for r in answers])
        except Exception:
            pass

    table = Table(title=f"DNS — {domain}", header_style="bold cyan")
    table.add_column("Type", style="dim")
    table.add_column("Values")
    for rtype, vals in result.items():
        if vals:
            table.add_row(rtype, "\n".join(vals))
    console.print(table)
    return result

def get_crtsh_subdomains(domain: str, cfg: Config) -> Tuple[List[Dict], List[str]]:
    url = f"https://crt.sh/?q={domain}&output=json"
    subdomains: set = set()
    wildcards:  set = set()

    for attempt in range(3):
        try:
            resp = requests.get(url, timeout=30 + attempt * 10)
            if resp.ok:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip()
                        if "*" in name:
                            wildcards.add(name)
                        elif name:
                            subdomains.add(name)
                break
        except Exception:
            time.sleep(5)

    def resolve(sub: str) -> Dict:
        try:
            return {"subdomain": sub, "ip": socket.gethostbyname(sub)}
        except Exception:
            return {"subdomain": sub, "ip": "unresolved"}

    with ThreadPoolExecutor(max_workers=cfg.max_threads) as ex:
        resolved = list(ex.map(resolve, subdomains))

    if resolved:
        t = Table(title=f"crt.sh — {domain}", header_style="bold green")
        t.add_column("Subdomain")
        t.add_column("IP")
        for r in resolved:
            t.add_row(r["subdomain"], r["ip"])
        console.print(t)

    return resolved, list(wildcards)

def get_hackertarget_subdomains(domain: str, cfg: Config) -> List[Dict]:
    """Free HackerTarget API — no key needed."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = make_request(url, cfg)
    if not resp or "error" in resp.text.lower():
        return []

    results = []
    for line in resp.text.strip().split("\n"):
        parts = line.split(",")
        if len(parts) == 2:
            results.append({"subdomain": parts[0].strip(), "ip": parts[1].strip()})

    if results:
        t = Table(title=f"HackerTarget — {domain}", header_style="bold green")
        t.add_column("Subdomain")
        t.add_column("IP")
        for r in results:
            t.add_row(r["subdomain"], r["ip"])
        console.print(t)

    return results

def get_securitytrails_subdomains(domain: str, cfg: Config) -> Dict:
    if not cfg.securitytrails_key:
        return {"error": "No SecurityTrails API key"}

    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    resp = make_request(url, cfg, extra_headers={"APIKEY": cfg.securitytrails_key})
    if not resp or resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code if resp else 'no response'}"}

    data = resp.json()
    subs = sorted(data.get("subdomains", []))

    def resolve(sub: str) -> Dict:
        full = f"{sub}.{domain}"
        try:
            return {"subdomain": full, "ip": socket.gethostbyname(full)}
        except Exception:
            return {"subdomain": full, "ip": "unresolved"}

    with ThreadPoolExecutor(max_workers=cfg.max_threads) as ex:
        results = list(ex.map(resolve, subs))

    return {"data": results}

def get_shodan(ip: str, cfg: Config) -> Dict:
    if not cfg.shodan_key or not ip:
        return {"error": "No Shodan key or IP"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={cfg.shodan_key}"
    resp = make_request(url, cfg)
    if not resp:
        return {"error": "No response"}
    data = resp.json()
    if "error" in data:
        return {"error": data["error"]}
    return {
        "ip":        ip,
        "ports":     sorted(data.get("ports", [])),
        "org":       data.get("org", "Unknown"),
        "country":   data.get("country_name", "Unknown"),
        "hostnames": data.get("hostnames", []),
        "vulns":     list(data["vulns"].keys()) if isinstance(data.get("vulns"), dict) else list(data.get("vulns") or []),
        "tags":      data.get("tags", []),
    }

def get_netlas(domain: str, cfg: Config) -> Dict:
    if not cfg.netlas_key:
        return {"error": "No Netlas key"}
    url = "https://app.netlas.io/api/domains/"
    params = {"q": domain, "source_type": "include", "start": 0, "fields": "*"}
    resp = make_request(url, cfg, extra_headers={"X-API-Key": cfg.netlas_key}, params=params)
    if not resp or resp.status_code != 200:
        return {"error": "Netlas request failed"}
    return resp.json()

def get_hunterhow(domain: str, cfg: Config) -> Dict:
    if not cfg.hunterhow_key:
        return {"error": "No Hunter.how key"}
    query = base64.urlsafe_b64encode(f'domain="{domain}"'.encode()).decode()
    today = datetime.today().strftime("%Y-%m-%d")
    url = (f"https://api.hunter.how/search?"
           f"api-key={cfg.hunterhow_key}&query={query}&"
           f"page=1&page_size=10&start_time={today}&end_time={today}")
    resp = make_request(url, cfg)
    if not resp or resp.status_code != 200:
        return {"error": "Hunter.how request failed"}
    try:
        data = resp.json()
    except Exception:
        return {"error": "Hunter.how invalid JSON response"}
    if not isinstance(data, dict):
        return {"error": "Hunter.how unexpected response format"}
    inner = data.get("data") or {}
    return {"results": inner.get("list", []), "limits": {
        "search_limit": inner.get("per_day_search_limit", 0),
        "search_count": inner.get("per_day_search_count", 0),
    }}

def get_virustotal(domain: str, cfg: Config) -> Dict:
    if not cfg.virustotal_key:
        return {"error": "No VirusTotal key"}
    headers = {"x-apikey": cfg.virustotal_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    resp = make_request(url, cfg, extra_headers=headers)
    if not resp or resp.status_code != 200:
        return {"error": "VT request failed"}
    try:
        _vt = resp.json() or {}
    except Exception:
        return {"error": "VT invalid JSON response"}
    data = (_vt.get("data") or {}).get("attributes") or {}
    return {
        "reputation":    data.get("reputation", 0),
        "malicious":     data.get("last_analysis_stats", {}).get("malicious", 0),
        "subdomains":    data.get("subdomains", []),
        "categories":    data.get("categories", {}),
        "registrar":     data.get("registrar", ""),
        "creation_date": data.get("creation_date", ""),
    }

def get_urlscan(domain: str, cfg: Config) -> List[Dict]:
    if not cfg.urlscan_key:
        return []
    headers = {"API-Key": cfg.urlscan_key, "Content-Type": "application/json"}
    search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20"
    resp = make_request(search_url, cfg, extra_headers=headers)
    if not resp or resp.status_code != 200:
        return []
    results = []
    for r in resp.json().get("results", []):
        results.append({
            "url":       r.get("page", {}).get("url", ""),
            "ip":        r.get("page", {}).get("ip", ""),
            "country":   r.get("page", {}).get("country", ""),
            "server":    r.get("page", {}).get("server", ""),
            "screenshot": r.get("screenshot", ""),
        })
    return results

# ─────────────────────────────────────────────────────────────────────────────
# WAYBACK MACHINE  (free, no API key)
# ─────────────────────────────────────────────────────────────────────────────

def get_wayback_urls(domain: str, cfg: Config) -> List[str]:
    """CDX API — returns unique URLs archived for domain. Essential for bug bounty."""
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url":       f"*.{domain}/*",
        "output":    "json",
        "fl":        "original",
        "collapse":  "urlkey",
        "limit":     500,
        "filter":    "statuscode:200",
    }
    console.print(f"[blue]  → Querying Wayback Machine CDX API...[/blue]")
    resp = make_request(url, cfg, params=params)
    if not resp:
        return []
    try:
        data = resp.json()
        urls = [row[0] for row in data[1:]] if len(data) > 1 else []
        console.print(f"[green]  ✓ Wayback: {len(urls)} archived URLs[/green]")
        return urls
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def analyze_headers(domain: str, cfg: Config) -> Dict[str, Any]:
    findings: Dict[str, Any] = {}
    for scheme in ("https", "http"):
        resp = make_request(f"{scheme}://{domain}", cfg)
        if not resp:
            continue
        headers_found = {}
        for h in SECURITY_HEADER_LIST:
            headers_found[h] = resp.headers.get(h, "MISSING")
        findings[scheme] = {
            "headers":    headers_found,
            "server":     resp.headers.get("Server", ""),
            "x_powered":  resp.headers.get("X-Powered-By", ""),
            "cookies":    [f"{c.name} (Secure={c.secure}, HttpOnly={c.has_nonstandard_attr('HttpOnly')})"
                           for c in resp.cookies],
            "status":     resp.status_code,
            "redirect":   resp.url if resp.url != f"{scheme}://{domain}" else "",
        }
        break  # first successful scheme is enough

    # Display table
    for scheme, data in findings.items():
        t = Table(title=f"Security Headers — {scheme.upper()}://{domain}", header_style="bold blue")
        t.add_column("Header")
        t.add_column("Value")
        t.add_column("Status")
        for h, v in data["headers"].items():
            status = "[green]✓[/green]" if v != "MISSING" else "[red]✗[/red]"
            t.add_row(h, v if v != "MISSING" else "[dim]not set[/dim]", status)
        if data["server"]:
            t.add_row("[yellow]Server[/yellow]", data["server"], "[yellow]ℹ[/yellow]")
        if data["x_powered"]:
            t.add_row("[yellow]X-Powered-By[/yellow]", data["x_powered"], "[yellow]ℹ[/yellow]")
        console.print(t)

    return findings

def check_sensitive_paths(domain: str, cfg: Config) -> List[Dict]:
    """Concurrent sensitive path check — /.env, /.git/config, etc."""
    console.print(f"[blue]  → Checking {len(SENSITIVE_PATHS)} sensitive paths...[/blue]")
    interesting_codes = {200, 206, 301, 302, 401, 403}
    results = []

    def probe(path: str) -> Optional[Dict]:
        resp = make_request(f"https://{domain}{path}", cfg)
        if not resp:
            resp = make_request(f"http://{domain}{path}", cfg)
        if resp and resp.status_code in interesting_codes:
            severity = "INFO"
            if resp.status_code == 200:
                if any(kw in path for kw in [".env", ".git", ".sql", "config", "backup", "passwd"]):
                    severity = "CRITICAL"
                elif any(kw in path for kw in ["admin", "phpinfo", "swagger", "graphql"]):
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
            elif resp.status_code in (401, 403):
                severity = "LOW"
            return {
                "path":     path,
                "status":   resp.status_code,
                "size":     len(resp.content),
                "severity": severity,
                "url":      resp.url,
            }
        return None

    with ThreadPoolExecutor(max_workers=cfg.max_threads) as ex:
        futures = {ex.submit(probe, p): p for p in SENSITIVE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[x["severity"]])

    if results:
        t = Table(title=f"Sensitive Paths — {domain}", header_style="bold red")
        t.add_column("Path")
        t.add_column("Status")
        t.add_column("Size")
        t.add_column("Severity")
        sev_color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
        for r in results:
            c = sev_color[r["severity"]]
            t.add_row(r["path"], str(r["status"]), f"{r['size']}B", f"[{c}]{r['severity']}[/{c}]")
        console.print(t)

    console.print(f"[green]  ✓ Found {len(results)} interesting paths[/green]")
    return results

def check_cors(domain: str, cfg: Config) -> List[Dict]:
    """Test common CORS misconfigurations — a frequent high-severity bug bounty finding."""
    console.print(f"[blue]  → Testing CORS misconfigurations...[/blue]")
    origins = [
        f"https://evil.com",
        f"https://{domain}.evil.com",
        f"null",
        f"https://evil{domain}",
        f"https://{domain}evil.com",
    ]
    findings = []
    for origin in origins:
        resp = make_request(
            f"https://{domain}", cfg,
            extra_headers={"Origin": origin}
        )
        if not resp:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "false")
        if acao and (acao == origin or acao == "*"):
            severity = "CRITICAL" if acac.lower() == "true" and acao != "*" else (
                       "HIGH"     if acac.lower() == "true" else "MEDIUM")
            findings.append({
                "origin":   origin,
                "acao":     acao,
                "acac":     acac,
                "severity": severity,
            })
            console.print(f"[red]  ⚠ CORS issue — origin: {origin} | severity: {severity}[/red]")

    if not findings:
        console.print("[green]  ✓ No CORS misconfigurations detected[/green]")
    return findings

def detect_waf(domain: str, cfg: Config) -> Dict:
    """Detect WAF/CDN presence by inspecting headers and behavior."""
    console.print(f"[blue]  → Detecting WAF/CDN...[/blue]")
    resp = make_request(f"https://{domain}", cfg)
    if not resp:
        return {"detected": False, "vendor": "Unknown", "evidence": []}

    resp_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    evidence = []
    vendor   = "Unknown"

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            sig_lower = sig.lower()
            for header_name, header_val in resp_headers.items():
                if sig_lower in header_name or sig_lower in header_val:
                    vendor  = waf_name
                    evidence.append(f"{header_name}: {header_val}")
                    break

    # Also test with a WAF-triggering payload
    probe_resp = make_request(
        f"https://{domain}/?id=1'+AND+1=1--",
        cfg,
    )
    if probe_resp and probe_resp.status_code in (403, 406, 429, 503):
        evidence.append(f"Blocked on SQL injection probe (HTTP {probe_resp.status_code})")
        if vendor == "Unknown":
            vendor = "Unknown WAF"

    detected = bool(evidence)
    if detected:
        console.print(f"[yellow]  ⚠ WAF/CDN detected: {vendor}[/yellow]")
    else:
        console.print(f"[green]  ✓ No WAF detected (or well hidden)[/green]")

    return {"detected": detected, "vendor": vendor, "evidence": evidence}

def detect_technologies(domain: str, cfg: Config) -> Dict[str, List[str]]:
    techs: Dict[str, List[str]] = {
        "webserver": [], "language": [], "frameworks": [],
        "analytics": [], "cms": [], "cdn": [], "misc": [],
    }
    resp = make_request(f"https://{domain}", cfg)
    if not resp:
        resp = make_request(f"http://{domain}", cfg)
    if not resp:
        return techs

    server  = resp.headers.get("Server", "").lower()
    powered = resp.headers.get("X-Powered-By", "").lower()
    body    = resp.text.lower()
    soup    = BeautifulSoup(resp.text, "html.parser")

    # Web server
    if "apache"   in server: techs["webserver"].append("Apache")
    if "nginx"    in server: techs["webserver"].append("Nginx")
    if "iis"      in server: techs["webserver"].append("IIS")
    if "lighttpd" in server: techs["webserver"].append("Lighttpd")
    if "caddy"    in server: techs["webserver"].append("Caddy")

    # Language
    if "php"    in powered or ".php" in resp.url: techs["language"].append("PHP")
    if "asp"    in powered: techs["language"].append("ASP.NET")
    if "python" in powered: techs["language"].append("Python")
    if "ruby"   in powered: techs["language"].append("Ruby")

    # CMS
    if "wp-content"  in body: techs["cms"].append("WordPress")
    if "joomla"      in body: techs["cms"].append("Joomla")
    if "drupal"      in body: techs["cms"].append("Drupal")
    if "shopify"     in body: techs["cms"].append("Shopify")
    if "magento"     in body: techs["cms"].append("Magento")
    if "squarespace" in body: techs["cms"].append("Squarespace")
    if "wix.com"     in body: techs["cms"].append("Wix")

    # JS Frameworks
    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        if "react"    in src: techs["frameworks"].append("React")
        if "vue"      in src: techs["frameworks"].append("Vue.js")
        if "angular"  in src: techs["frameworks"].append("Angular")
        if "jquery"   in src: techs["frameworks"].append("jQuery")
        if "next"     in src: techs["frameworks"].append("Next.js")
        if "nuxt"     in src: techs["frameworks"].append("Nuxt.js")
        if "ember"    in src: techs["frameworks"].append("Ember.js")
        if "svelte"   in src: techs["frameworks"].append("Svelte")

    # Analytics / Tracking
    if "google-analytics" in body or "gtag("       in body: techs["analytics"].append("Google Analytics")
    if "segment"          in body:                           techs["analytics"].append("Segment")
    if "mixpanel"         in body:                           techs["analytics"].append("Mixpanel")
    if "hotjar"           in body:                           techs["analytics"].append("Hotjar")
    if "intercom"         in body:                           techs["analytics"].append("Intercom")

    # CDN
    if "cloudflare"  in body or "cf-ray" in resp.headers: techs["cdn"].append("Cloudflare")
    if "fastly"      in body:                              techs["cdn"].append("Fastly")
    if "amazonaws"   in body:                              techs["cdn"].append("AWS CloudFront")
    if "akamai"      in body:                              techs["cdn"].append("Akamai")

    # Deduplicate
    for k in techs:
        techs[k] = list(dict.fromkeys(techs[k]))

    return techs

def port_scan(domain: str, cfg: Config, ports: Optional[List[int]] = None) -> List[Dict]:
    if ports is None:
        ports = DEFAULT_PORTS
    ip = socket.gethostbyname(domain)
    results = []

    SERVICE_MAP = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                   110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",587:"SMTP/TLS",
                   993:"IMAPS",995:"POP3S",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
                   6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt",
                   9200:"Elasticsearch",27017:"MongoDB"}

    def probe_port(port: int) -> Optional[Dict]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                svc = SERVICE_MAP.get(port, "unknown")
                severity = "HIGH" if port in (23, 3389, 6379, 9200, 27017) else "INFO"
                return {"port": port, "service": svc, "severity": severity}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(probe_port, p): p for p in ports}
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.append(r)

    results.sort(key=lambda x: x["port"])

    if results:
        t = Table(title=f"Open Ports — {domain} ({ip})", header_style="bold red")
        t.add_column("Port")
        t.add_column("Service")
        t.add_column("Risk")
        sev_color = {"HIGH": "red", "MEDIUM": "yellow", "INFO": "dim"}
        for r in results:
            c = sev_color.get(r["severity"], "white")
            t.add_row(str(r["port"]), r["service"], f"[{c}]{r['severity']}[/{c}]")
        console.print(t)

    return results

def find_leaks_proxynova(domain: str, cfg: Config) -> List[str]:
    url = f"https://api.proxynova.com/comb?query={domain}"
    resp = make_request(url, cfg, extra_headers={"User-Agent": "curl"})
    if not resp or resp.status_code != 200:
        return []
    data = resp.json()
    lines = data.get("lines", [])[:20]
    if lines:
        console.print(f"[red]  ⚠ ProxyNova: {data.get('count', 0)} records found (showing {len(lines)})[/red]")
    return lines

# ─────────────────────────────────────────────────────────────────────────────
# ASN / BGP ENUMERATION  (Team Cymru DNS + RIPE Stat — free, no key required)
# ─────────────────────────────────────────────────────────────────────────────

def _cymru_asn_lookup(ip: str) -> Optional[Dict]:
    """
    Team Cymru DNS ASN lookup — free, no key, no rate limit, extremely reliable.
    Used by every serious recon tool (Amass, ASNmap, etc.)
    Query: {reversed_ip}.origin.asn.cymru.com TXT
    Response: "asn | prefix | country | rir | date"
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        reversed_ip = ".".join(reversed(parts))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(query, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"').strip()
            # Format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
            fields = [f.strip() for f in txt.split("|")]
            if len(fields) >= 4:
                asn_num = int(fields[0]) if fields[0].isdigit() else None
                return {
                    "asn":     asn_num,
                    "prefix":  fields[1] if len(fields) > 1 else "",
                    "country": fields[2] if len(fields) > 2 else "",
                    "rir":     fields[3] if len(fields) > 3 else "",
                    "date":    fields[4] if len(fields) > 4 else "",
                }
    except Exception:
        pass
    return None


def _cymru_asn_info(asn: int) -> Optional[Dict]:
    """
    Team Cymru AS info lookup — name/description for an ASN.
    Query: AS{asn}.asn.cymru.com TXT
    Response: "asn | country | rir | date | org_name"
    """
    try:
        query = f"AS{asn}.asn.cymru.com"
        answers = dns.resolver.resolve(query, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"').strip()
            fields = [f.strip() for f in txt.split("|")]
            if len(fields) >= 5:
                return {
                    "asn":         asn,
                    "country":     fields[1] if len(fields) > 1 else "",
                    "rir":         fields[2] if len(fields) > 2 else "",
                    "name":        fields[4] if len(fields) > 4 else "",
                    "description": fields[4] if len(fields) > 4 else "",
                }
    except Exception:
        pass
    return None


def _ripestat_asn_prefixes(asn: int, cfg: Config) -> List[Dict]:
    """
    RIPE Stat API — fetch all announced prefixes for an ASN.
    Free, no key required, covers all RIRs (RIPE, ARIN, APNIC, LACNIC, AFRINIC).
    https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}
    """
    resp = make_request(
        f"https://stat.ripe.net/data/announced-prefixes/data.json",
        cfg, params={"resource": f"AS{asn}", "sourceapp": "triprecon"}
    )
    if not resp or not resp.ok:
        return []
    try:
        data = resp.json() or {}
        prefixes = data.get("data", {}).get("prefixes", [])
        result = []
        for p in prefixes:
            prefix = p.get("prefix", "")
            ptype  = "IPv6" if ":" in prefix else "IPv4"
            result.append({
                "prefix":  prefix,
                "type":    ptype,
                "name":    "",
                "country": "",
            })
        return result
    except Exception:
        return []


def get_asn_from_ip(ip: str, cfg: Config) -> Dict:
    """
    Resolve IP → ASN using a 4-provider cascade (all free, no key needed):
      1. Team Cymru DNS  — industry standard, zero downtime, used by Amass/ASNmap
      2. RIPE Stat API   — free REST API, all RIRs covered
      3. ipinfo.io       — 50k req/month free, very reliable
      4. ip-api.com      — always open, 45 req/min, no key
    """
    if not ip:
        return {}

    # ── 1. Team Cymru (DNS-based — fastest and most reliable) ────────────────
    cymru = _cymru_asn_lookup(ip)
    if cymru and cymru.get("asn"):
        # Get the org name via a second DNS TXT query
        info = _cymru_asn_info(cymru["asn"]) or {}
        name = info.get("name", "")
        console.print(f"[green]  ✓ ASN (Cymru DNS): AS{cymru['asn']} — {name} [{cymru.get('country','')}][/green]")
        return {"ip": ip, "asns": [{
            "asn":         cymru["asn"],
            "name":        name,
            "description": name,
            "prefix":      cymru.get("prefix", ""),
            "country":     cymru.get("country", ""),
            "rir":         cymru.get("rir", ""),
        }], "source": "cymru"}

    # ── 2. RIPE Stat (REST API — detailed, all RIRs) ─────────────────────────
    try:
        resp = make_request(
            "https://stat.ripe.net/data/network-info/data.json",
            cfg, params={"resource": ip, "sourceapp": "triprecon"}
        )
        if resp and resp.ok:
            d = resp.json() or {}
            data = d.get("data", {})
            asns_raw = data.get("asns", [])
            prefix   = data.get("prefix", "")
            if asns_raw:
                asn_num = int(asns_raw[0]) if str(asns_raw[0]).isdigit() else None
                if asn_num:
                    info = _cymru_asn_info(asn_num) or {}
                    name = info.get("name", "")
                    console.print(f"[green]  ✓ ASN (RIPE Stat): AS{asn_num} — {name}[/green]")
                    return {"ip": ip, "asns": [{
                        "asn":         asn_num,
                        "name":        name,
                        "description": name,
                        "prefix":      prefix,
                        "country":     info.get("country", ""),
                        "rir":         info.get("rir", ""),
                    }], "source": "ripestat"}
    except Exception:
        pass

    # ── 3. ipinfo.io (with or without key) ───────────────────────────────────
    try:
        token_param = f"?token={cfg.ipinfo_key}" if cfg.ipinfo_key else ""
        resp = make_request(f"https://ipinfo.io/{ip}/json{token_param}", cfg)
        if resp and resp.ok:
            d = resp.json() or {}
            org = d.get("org", "")          # e.g. "AS13335 Cloudflare, Inc."
            asn_num, asn_name = None, org
            if org.startswith("AS"):
                parts = org.split(" ", 1)
                try:
                    asn_num  = int(parts[0][2:])
                    asn_name = parts[1] if len(parts) > 1 else ""
                except ValueError:
                    pass
            if asn_num:
                console.print(f"[green]  ✓ ASN (ipinfo.io): AS{asn_num} — {asn_name}[/green]")
                return {"ip": ip, "asns": [{
                    "asn": asn_num, "name": asn_name,
                    "description": asn_name,
                    "prefix":  d.get("prefix", ""),
                    "country": d.get("country", ""),
                    "rir":     "",
                }], "source": "ipinfo"}
    except Exception:
        pass

    # ── 4. ip-api.com (completely free, no key, 45 req/min) ──────────────────
    try:
        resp = make_request(f"http://ip-api.com/json/{ip}?fields=as,org,country,query", cfg)
        if resp and resp.ok:
            d = resp.json() or {}
            asn_str = d.get("as", "")       # e.g. "AS13335 Cloudflare, Inc."
            asn_num, asn_name = None, d.get("org", "")
            if asn_str.startswith("AS"):
                parts = asn_str.split(" ", 1)
                try:
                    asn_num  = int(parts[0][2:])
                    asn_name = parts[1] if len(parts) > 1 else asn_name
                except ValueError:
                    pass
            if asn_num:
                console.print(f"[green]  ✓ ASN (ip-api.com): AS{asn_num} — {asn_name}[/green]")
                return {"ip": ip, "asns": [{
                    "asn": asn_num, "name": asn_name,
                    "description": d.get("org", ""),
                    "prefix":  "",
                    "country": d.get("country", ""),
                    "rir":     "",
                }], "source": "ip-api"}
    except Exception:
        pass

    console.print(f"[yellow]  ⚠ ASN lookup failed for {ip} (all providers exhausted)[/yellow]")
    return {"ip": ip, "asns": [], "source": "none"}


def get_asn_prefixes(asn: int, cfg: Config) -> List[Dict]:
    """
    Fetch all announced IP prefixes for an ASN using RIPE Stat.
    Free, no key, covers all 5 RIRs — replaces BGPView entirely.
    Returns flat list: [{"prefix", "type", "name", "country"}, ...]
    """
    prefixes = _ripestat_asn_prefixes(asn, cfg)
    if prefixes:
        ipv4 = [p for p in prefixes if p["type"] == "IPv4"]
        ipv6 = [p for p in prefixes if p["type"] == "IPv6"]
        console.print(f"[green]  ✓ AS{asn}: {len(prefixes)} prefixes via RIPE Stat ({len(ipv4)} IPv4, {len(ipv6)} IPv6)[/green]")
    else:
        console.print(f"[yellow]  ⚠ No prefixes found for AS{asn}[/yellow]")
    return prefixes


def enumerate_asn(domain: str, ip: str, cfg: Config) -> Dict:
    """
    Full ASN enumeration:
      IP → ASN (Team Cymru DNS → RIPE Stat → ipinfo → ip-api)
       → all announced prefixes via RIPE Stat
    """
    result: Dict[str, Any] = {
        "domain": domain, "ip": ip,
        "asn": None, "asn_name": "", "country": "", "rir": "",
        "asns": [], "prefixes": [], "source": "none",
    }

    asn_data = get_asn_from_ip(ip, cfg)
    if not asn_data or not asn_data.get("asns"):
        return result

    result["asns"]   = asn_data["asns"]
    result["source"] = asn_data.get("source", "unknown")

    # Promote primary ASN to top-level for easy template access
    primary = asn_data["asns"][0]
    result["asn"]      = primary.get("asn")
    result["asn_name"] = primary.get("name", "")
    result["country"]  = primary.get("country", "")
    result["rir"]      = primary.get("rir", "")

    # Fetch full prefix list via RIPE Stat (works for all sources now)
    seen_asns: Set[int] = set()
    for asn_entry in asn_data["asns"]:
        asn_num = asn_entry.get("asn")
        if asn_num and asn_num not in seen_asns:
            seen_asns.add(asn_num)
            time.sleep(cfg.request_delay)
            result["prefixes"].extend(get_asn_prefixes(asn_num, cfg))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def get_whois(domain: str, cfg: Config) -> Dict:
    """
    Fetch WHOIS data via whoisjson.com (free, no key for basic use)
    + rdap.org fallback (100% free, IANA RDAP).
    """
    result: Dict = {}

    # Primary: RDAP (IANA redirect, totally free)
    rdap_url = f"https://rdap.org/domain/{domain}"
    resp = make_request(rdap_url, cfg)
    if resp and resp.ok:
        try:
            data = resp.json() or {}
            events = {e.get("eventAction"): e.get("eventDate", "") for e in data.get("events", [])}
            entities = []
            for ent in data.get("entities", []):
                vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
                name  = next((v[3] for v in vcard if isinstance(v, list) and v[0] == "fn"), "")
                email = next((v[3] for v in vcard if isinstance(v, list) and v[0] == "email"), "")
                entities.append({
                    "name":  name,
                    "email": email,
                    "roles": ent.get("roles", []),
                })
            result = {
                "registrar":      next((l.get("value","") for l in data.get("links",[]) if l.get("rel")=="related"), ""),
                "status":         [s if isinstance(s,str) else s[0] for s in data.get("status", [])],
                "registered":     events.get("registration", ""),
                "expires":        events.get("expiration", ""),
                "last_changed":   events.get("last changed", ""),
                "nameservers":    [ns.get("ldhName","") for ns in data.get("nameservers", [])],
                "entities":       entities,
                "source":         "rdap.org",
            }
            console.print(f"[green]  ✓ WHOIS/RDAP: registered {result.get('registered','?')[:10]}[/green]")
        except Exception as e:
            result = {"error": f"RDAP parse failed: {e}"}
    else:
        result = {"error": "RDAP lookup failed"}

    return result


# ─────────────────────────────────────────────────────────────────────────────
# FAVICON HASH  (for Shodan  http.favicon.hash:)
# ─────────────────────────────────────────────────────────────────────────────

def _mmh3_hash32(data: bytes) -> int:
    """Pure-Python MurmurHash3 32-bit (same algo Shodan uses for favicon hashing)."""
    length = len(data)
    h1 = 0
    c1, c2 = 0xcc9e2d51, 0x1b873593
    remainder = length & 3
    blocks = length >> 2

    for block_start in range(0, blocks * 4, 4):
        k1 = (
            data[block_start]
            | (data[block_start + 1] << 8)
            | (data[block_start + 2] << 16)
            | (data[block_start + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail_idx = blocks * 4
    k1 = 0
    if remainder == 3:
        k1 ^= data[tail_idx + 2] << 16
    if remainder >= 2:
        k1 ^= data[tail_idx + 1] << 8
    if remainder >= 1:
        k1 ^= data[tail_idx]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return struct.unpack(">i", struct.pack(">I", h1))[0]


def get_favicon_hash(domain: str, cfg: Config) -> Dict:
    """
    Fetch /favicon.ico, compute MurmurHash3 (Shodan's method).
    Shodan search: http.favicon.hash:<hash>
    Returns hash and a ready-to-use Shodan search URL.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/favicon.ico"
        resp = make_request(url, cfg)
        if resp and resp.ok and resp.content:
            raw     = base64.encodebytes(resp.content)
            fhash   = _mmh3_hash32(raw)
            shodan_q = f"http.favicon.hash:{fhash}"
            console.print(f"[green]  ✓ Favicon hash: {fhash}[/green]  →  {shodan_q}")
            return {
                "hash":       fhash,
                "shodan_query": shodan_q,
                "shodan_url": f"https://www.shodan.io/search?query={requests.utils.quote(shodan_q)}",
                "size_bytes": len(resp.content),
                "url":        url,
            }
    console.print(f"[yellow]  ⚠ No favicon found for {domain}[/yellow]")
    return {"hash": None, "shodan_query": None}


# ─────────────────────────────────────────────────────────────────────────────
# JAVASCRIPT ENDPOINT EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

_JS_ENDPOINT_RE = re.compile(
    r"""(?:["'`]|url\s*[=:]\s*["'`])"""
    r"""(/(?:api|v\d|rest|graphql|internal|admin|auth|user|account|search|upload|export|download)[^\s"'`<>]{0,200})""",
    re.IGNORECASE,
)
_JS_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.IGNORECASE)


def extract_js_endpoints(domain: str, cfg: Config, max_js: int = 15) -> Dict:
    """
    1. Fetch main page → collect JS file URLs
    2. Fetch each JS file → extract API endpoint paths + check for secrets
    Returns {"js_files": [...], "endpoints": [...], "secrets": [...]}
    """
    found_js:      List[str]  = []
    # endpoints: list of {"endpoint": str, "source": str (js_url)}
    endpoints_list: List[Dict] = []
    endpoints_seen: Set[str]   = set()
    secrets:        List[Dict] = []

    for scheme in ("https", "http"):
        resp = make_request(f"{scheme}://{domain}", cfg)
        if resp and resp.ok:
            base_url = f"{scheme}://{domain}"
            for src in _JS_SRC_RE.findall(resp.text):
                js_url = src if src.startswith("http") else urljoin(base_url, src)
                if js_url not in found_js:
                    found_js.append(js_url)
            break

    console.print(f"[cyan]  ℹ {len(found_js)} JS files found — analyzing up to {max_js}[/cyan]")

    for js_url in found_js[:max_js]:
        time.sleep(cfg.request_delay * 0.5)
        js_resp = make_request(js_url, cfg)
        if not js_resp or not js_resp.ok:
            continue

        content = js_resp.text

        # Extract endpoints — stored as dicts {endpoint, source}
        for match in _JS_ENDPOINT_RE.findall(content):
            clean = match.strip().split("?")[0].rstrip("/")
            if 3 < len(clean) < 120 and clean not in endpoints_seen:
                endpoints_seen.add(clean)
                endpoints_list.append({"endpoint": clean, "source": js_url})

        # Scan for secrets
        for secret_name, pattern in JS_SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content):
                hit = m.group(0)[:120]
                secrets.append({
                    "type":   secret_name,
                    "match":  hit,
                    "url":    js_url,
                    "js_url": js_url,
                    "line":   content[:m.start()].count("\n") + 1,
                })

    console.print(
        f"[green]  ✓ JS analysis: {len(endpoints_list)} endpoints, "
        f"[{'red' if secrets else 'green'}]{len(secrets)} secrets found[/{'red' if secrets else 'green'}][/green]"
    )

    return {
        "js_files":  found_js,
        "endpoints": sorted(endpoints_list, key=lambda x: x["endpoint"]),
        "secrets":   secrets,
    }


# ─────────────────────────────────────────────────────────────────────────────
# WAYBACK PARAMETER MINING
# ─────────────────────────────────────────────────────────────────────────────

def mine_wayback_params(wayback_urls: List[str]) -> Dict:
    """
    From a list of Wayback URLs, extract unique GET parameters.
    No network requests — purely URL string analysis.
    Useful for: fuzzing, finding hidden params, IDOR hunting.
    """
    params: Dict[str, Set[str]] = {}   # param_name → set of example values

    for raw_url in wayback_urls:
        # Wayback CDX returns 'timestamp url' or just the url
        url = raw_url.split(" ")[-1] if " " in raw_url else raw_url
        try:
            qs = parse_qs(urlparse(url).query)
            for k, vals in qs.items():
                if k not in params:
                    params[k] = set()
                params[k].update(vals[:3])
        except Exception:
            continue

    sorted_params = sorted(
        [{"param": k, "examples": list(v)[:3], "count": len(v)} for k, v in params.items()],
        key=lambda x: -x["count"],
    )
    console.print(f"[green]  ✓ Wayback params: {len(sorted_params)} unique parameters extracted[/green]")
    return {"params": sorted_params, "total": len(sorted_params)}


# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN TAKEOVER DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def check_subdomain_takeover(subdomains: List[str], cfg: Config) -> List[Dict]:
    """
    For each subdomain:
      1. Resolve CNAME → check if CNAME matches a known dangling-service pattern
      2. Fetch the subdomain → check response body for takeover fingerprints
    Returns list of potential takeovers with severity.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    findings: List[Dict] = []

    def check_one(sub: str) -> Optional[Dict]:
        cname_target = ""
        try:
            answers = resolver.resolve(sub, "CNAME")
            cname_target = str(answers[0].target).lower().rstrip(".")
        except Exception:
            pass

        # Check CNAME match against known services
        matched_service = ""
        matched_severity = "LOW"
        for service, info in TAKEOVER_FINGERPRINTS.items():
            for pattern in info["cname"]:
                if pattern in cname_target:
                    matched_service = service
                    matched_severity = info["severity"]
                    break

        # Fetch body to verify
        body_match = False
        body_snippet = ""
        if cname_target:  # Only fetch if there's a CNAME to check
            resp = make_request(f"https://{sub}", cfg)
            if not resp:
                resp = make_request(f"http://{sub}", cfg)
            if resp:
                body_lower = resp.text.lower()[:5000]
                service_key = matched_service or ""
                check_patterns = (
                    TAKEOVER_FINGERPRINTS[service_key]["body"]
                    if service_key in TAKEOVER_FINGERPRINTS
                    else []
                )
                for fp in check_patterns:
                    if fp.lower() in body_lower:
                        body_match = True
                        body_snippet = fp
                        break

        if matched_service or body_match:
            confidence = "HIGH" if (matched_service and body_match) else "MEDIUM" if matched_service else "LOW"
            return {
                "subdomain":   sub,
                "cname":       cname_target,
                "service":     matched_service or "Unknown",
                "severity":    matched_severity,
                "confidence":  confidence,
                "body_match":  body_snippet,
                "note":        f"CNAME points to {cname_target} ({matched_service})"
                               f"{' — body confirms takeover pattern' if body_match else ''}",
            }
        return None

    with ThreadPoolExecutor(max_workers=cfg.max_threads) as ex:
        futures = {ex.submit(check_one, s): s for s in subdomains}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                severity = result["severity"]
                color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"cyan"}.get(severity,"white")
                console.print(f"[{color}]  ⚠ Takeover? {result['subdomain']} → {result['service']} [{confidence}][/{color}]"
                              .replace("[confidence]", f"[{result['confidence']}]"))
                findings.append(result)

    console.print(f"[{'red' if findings else 'green'}]  ✓ Takeover check: {len(findings)} potential vulnerabilities[/{'red' if findings else 'green'}]")
    return sorted(findings, key=lambda x: {"HIGH":0,"MEDIUM":1,"LOW":2}.get(x["severity"], 3))


# ─────────────────────────────────────────────────────────────────────────────
# CLOUD BUCKET ENUMERATION  (URL-only — no downloads)
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_cloud_buckets(domain: str, cfg: Config) -> List[Dict]:
    """
    Check common bucket name permutations for AWS S3, GCS, Azure Blob.
    Only checks HTTP status — never downloads content.
    """
    org = domain.split(".")[0]   # e.g. 'example' from 'example.com'

    bucket_names = [p.replace("{org}", org) for p in BUCKET_PATTERNS]

    targets: List[Dict] = []
    for name in bucket_names:
        targets.extend([
            {"name": name, "provider": "AWS S3",      "url": f"https://{name}.s3.amazonaws.com"},
            {"name": name, "provider": "GCS",         "url": f"https://storage.googleapis.com/{name}"},
            {"name": name, "provider": "Azure Blob",  "url": f"https://{name}.blob.core.windows.net"},
        ])

    results: List[Dict] = []

    def probe(t: Dict) -> Optional[Dict]:
        resp = make_request(t["url"], cfg)
        if not resp:
            return None
        if resp.status_code in (200, 403):
            severity    = "HIGH" if resp.status_code == 200 else "MEDIUM"
            status_str  = "PUBLIC" if resp.status_code == 200 else "EXISTS"
            label       = "PUBLIC (readable)" if resp.status_code == 200 else "EXISTS (access denied)"
            console.print(f"[{'red' if severity=='HIGH' else 'yellow'}]  ⚠ Bucket {label}: {t['url']}[/{'red' if severity=='HIGH' else 'yellow'}]")
            return {**t, "http_status": resp.status_code, "status": status_str, "label": label, "severity": severity}
        return None

    with ThreadPoolExecutor(max_workers=cfg.max_threads) as ex:
        futures = [ex.submit(probe, t) for t in targets]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    console.print(f"[{'red' if results else 'green'}]  ✓ Bucket scan: {len(results)} findings from {len(targets)} probes[/{'red' if results else 'green'}]")
    return sorted(results, key=lambda x: x["status"])


# ─────────────────────────────────────────────────────────────────────────────
# SPF / DMARC DEEP ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_spf(record: str) -> Dict:
    """Parse SPF record string into structured dict."""
    if not record:
        return {"record": "", "all_qualifier": "", "mechanisms": []}
    mechs = [t for t in record.split() if not t.startswith("v=")]
    all_q = ""
    for m in mechs:
        if m in ("+all", "-all", "~all", "?all", "all"):
            all_q = m[0] if m != "all" else "?"
            break
    return {
        "record":        record,
        "all_qualifier": all_q,
        "mechanisms":    mechs,
    }

def _parse_dmarc(record: str) -> Dict:
    """Parse DMARC record string into structured dict."""
    if not record:
        return {"record": "", "policy": "", "pct": 100, "rua": "", "ruf": ""}
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return {
        "record": record,
        "policy": tags.get("p", ""),
        "pct":    int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100,
        "rua":    tags.get("rua", ""),
        "ruf":    tags.get("ruf", ""),
        "adkim":  tags.get("adkim", ""),
        "aspf":   tags.get("aspf", ""),
    }

def analyze_email_security(domain: str) -> Dict:
    """
    Analyze SPF, DMARC, DKIM for email spoofing surface.
    Returns structured dicts (NOT raw strings) for all fields.
    Purely DNS — no HTTP requests.
    """
    resolver = dns.resolver.Resolver()
    result: Dict[str, Any] = {
        "spf":            {"record": "", "all_qualifier": "", "mechanisms": []},
        "dmarc":          {"record": "", "policy": "", "pct": 100, "rua": "", "ruf": ""},
        "dkim_selectors": {},
        "findings":       [],
        "summary":        "",
    }

    # ── SPF ───────────────────────────────────────────────────────────────────
    try:
        for t in resolver.resolve(domain, "TXT"):
            txt = str(t).strip('"')
            if txt.startswith("v=spf1"):
                result["spf"] = _parse_spf(txt)
                aq = result["spf"]["all_qualifier"]
                if aq == "+":
                    result["findings"].append({"severity": "CRITICAL", "issue": "SPF +all: anyone can send email as this domain"})
                elif aq == "?":
                    result["findings"].append({"severity": "HIGH", "issue": "SPF ?all: neutral, no enforcement"})
                elif aq == "~":
                    result["findings"].append({"severity": "MEDIUM", "issue": "SPF ~all (softfail): spoofed mails may reach inbox"})
                break
        if not result["spf"]["record"]:
            result["findings"].append({"severity": "HIGH", "issue": "No SPF record — domain can be spoofed"})
    except Exception:
        result["findings"].append({"severity": "HIGH", "issue": "No SPF record — domain can be spoofed"})

    # ── DMARC ─────────────────────────────────────────────────────────────────
    try:
        for t in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = str(t).strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = _parse_dmarc(txt)
                p = result["dmarc"]["policy"]
                if p == "none":
                    result["findings"].append({"severity": "HIGH", "issue": "DMARC p=none: monitoring only, no enforcement"})
                elif p == "quarantine":
                    result["findings"].append({"severity": "MEDIUM", "issue": "DMARC p=quarantine: partially enforced"})
                break
        if not result["dmarc"]["record"]:
            result["findings"].append({"severity": "CRITICAL", "issue": "No DMARC record — domain fully spoofable"})
    except Exception:
        result["findings"].append({"severity": "CRITICAL", "issue": "No DMARC record — domain fully spoofable"})

    # ── DKIM (common selectors) ───────────────────────────────────────────────
    dkim_selectors = ["default", "google", "mail", "k1", "selector1", "selector2",
                      "smtp", "dkim", "key1", "key2", "postfix", "zoho", "mailchimp",
                      "amazonses", "mandrill", "sendgrid", "s1", "s2", "email"]
    for sel in dkim_selectors:
        try:
            ans = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            result["dkim_selectors"][sel] = str(ans[0]).strip('"')[:120]
        except Exception:
            pass

    # ── Summary ───────────────────────────────────────────────────────────────
    spf_ok   = result["spf"]["record"] and result["spf"]["all_qualifier"] == "-"
    dmarc_ok = result["dmarc"]["policy"] == "reject"
    if spf_ok and dmarc_ok:
        result["summary"] = "✓ Properly configured (SPF + DMARC reject)"
    elif not result["spf"]["record"] and not result["dmarc"]["record"]:
        result["summary"] = "✗ CRITICAL: No SPF, No DMARC — fully spoofable"
    else:
        result["summary"] = f"⚠ Partial: {len(result['findings'])} issue(s)"

    color = "green" if not result["findings"] else ("red" if any(f["severity"] == "CRITICAL" for f in result["findings"]) else "yellow")
    console.print(f"[{color}]  ✓ Email security: {result['summary']}[/{color}]")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# GITHUB DORKING
# ─────────────────────────────────────────────────────────────────────────────

def dork_github(domain: str, cfg: Config) -> List[Dict]:
    """
    Search GitHub code for leaked secrets/tokens referencing the target domain.
    Searches by:
      - Full domain (e.g. "api.target.com")
      - Org name / first label (e.g. "target")
    Uses GitHub Search API — token optional but strongly recommended.
    Without token: 10 req/min (very limited). With token: 30 req/min.
    """
    # Extract useful variants from domain
    parts   = domain.split(".")
    org     = parts[0]                      # e.g. "target"
    tld2    = ".".join(parts[-2:])          # e.g. "target.com"

    headers: Dict[str, str] = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg.github_token:
        headers["Authorization"] = f"Bearer {cfg.github_token}"

    # Queries searching by DOMAIN (most precise — finds actual creds for this target)
    queries = [
        # High-signal: credentials referencing full domain
        (f'"{domain}" password',            "Passwords"),
        (f'"{domain}" secret',              "Secrets"),
        (f'"{domain}" api_key OR apikey',   "API Keys"),
        (f'"{domain}" token',               "Tokens"),
        (f'"{domain}" private_key',         "Private Keys"),
        # Env files and configs
        (f'"{domain}" filename:.env',       ".env files"),
        (f'"{domain}" filename:config.yml', "Config files"),
        (f'"{domain}" filename:settings.py',"Django/Flask settings"),
        (f'"{domain}" filename:wp-config.php', "WordPress config"),
        # Database / connection strings
        (f'"{domain}" jdbc: OR mongodb:// OR postgres://', "DB connection strings"),
        # Org-level (broader — may find related repos/tools)
        (f'"{org}" DB_PASSWORD OR DB_PASS', "DB passwords (org)"),
        (f'"{org}" AWS_SECRET_ACCESS_KEY',  "AWS secret (org)"),
        (f'"{org}" BEGIN RSA PRIVATE KEY',  "RSA private key (org)"),
        (f'"{org}" GITHUB_TOKEN OR GH_TOKEN', "GitHub tokens (org)"),
        (f'"{tld2}" filename:.env',         ".env with domain"),
    ]

    findings:  List[Dict] = []
    seen_urls: set        = set()
    rate_limited          = False

    for query, category in queries:
        if rate_limited:
            break
        resp = make_request(
            "https://api.github.com/search/code", cfg,
            extra_headers=headers,
            params={"q": query, "per_page": 5, "sort": "indexed", "order": "desc"},
        )
        if not resp:
            continue
        if resp.status_code == 403:
            console.print("[yellow]  ⚠ GitHub API rate limit hit — add GITHUB_TOKEN to .env for 3× more queries[/yellow]")
            rate_limited = True
            break
        if resp.status_code in (422, 400):
            continue  # invalid query syntax
        if resp.status_code == 401:
            console.print("[red]  ✗ GitHub token invalid — check GITHUB_TOKEN in .env[/red]")
            break
        try:
            data = resp.json() or {}
        except Exception:
            continue

        for item in data.get("items", [])[:3]:
            html_url = item.get("html_url", "")
            if html_url in seen_urls:
                continue
            seen_urls.add(html_url)
            repo = item.get("repository", {})
            findings.append({
                "category":    category,
                "query":       query,
                "repo":        repo.get("full_name", ""),
                "repo_url":    repo.get("html_url", ""),
                "file":        item.get("name", ""),
                "path":        item.get("path", ""),
                "url":         html_url,
                "description": repo.get("description", ""),
                "updated_at":  repo.get("updated_at", ""),
                "stars":       repo.get("stargazers_count", 0),
                "private":     repo.get("private", False),
            })
            console.print(f"[red]  ⚠ [{category}] {repo.get('full_name','')} → {item.get('path','')}[/red]")

        time.sleep(cfg.request_delay * 2)  # GitHub is strict on rate limits

    status_color = "red" if findings else "green"
    console.print(f"[{status_color}]  ✓ GitHub dork: {len(findings)} leak(s) across {len(queries)} queries[/{status_color}]")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SEARCH ENGINE DORK MODULES
# ─────────────────────────────────────────────────────────────────────────────

def _format_dorks(dorks: List[str], domain: str) -> List[str]:
    return [d.replace("{domain}", domain) for d in dorks]


def classify_dork_url(url: str) -> Dict[str, str]:
    """
    Given a URL from a dork result, return metadata about it.
    - file_type: extension label if the URL points to a file, else ""
    - is_file:   True if this URL appears to be a downloadable file
    URLs are NEVER fetched — classification is purely based on the URL string.
    """
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path.lower().rstrip("/")
        for ext, label in FILE_DORK_EXTENSIONS.items():
            if path.endswith(ext):
                return {"is_file": True, "file_type": label, "url": url}
    except Exception:
        pass
    return {"is_file": False, "file_type": "", "url": url}


def enrich_dork_results(raw: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
    """
    Convert {dork: [url, ...]} into {dork: [{"url": ..., "is_file": ..., "file_type": ...}]}
    No network requests are made — enrichment is URL-string analysis only.
    """
    enriched: Dict[str, List[Dict]] = {}
    for dork, urls in raw.items():
        if dork.startswith("_"):          # internal error/meta keys
            enriched[dork] = urls         # type: ignore[assignment]
            continue
        if not isinstance(urls, list):
            enriched[dork] = []
            continue
        enriched[dork] = [classify_dork_url(u) for u in urls]
    return enriched

# ── Google ────────────────────────────────────────────────────────────────────

def dork_google_api(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    if not cfg.google_api_key or not cfg.google_cse_id:
        return {"_error": "Google API keys missing"}
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        try:
            resp = make_request(
                "https://www.googleapis.com/customsearch/v1",
                cfg,
                params={"q": dork, "key": cfg.google_api_key, "cx": cfg.google_cse_id, "num": 10},
            )
            if resp and resp.ok:
                items = resp.json().get("items", [])
                results[dork] = [i["link"] for i in items]
            else:
                results[dork] = []
        except Exception as e:
            results[dork] = []
        time.sleep(cfg.request_delay)
    return results

def dork_google_scrape(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        encoded = requests.utils.quote(dork)
        url = f"https://www.google.com/search?q={encoded}&num=20&hl=en"
        console.print(f"[yellow]  → Google scrape:[/yellow] {dork}")
        scrape_delay(cfg)
        resp = make_request(url, cfg)
        if not resp:
            results[dork] = []
            continue
        if "unusual traffic" in resp.text.lower():
            console.print("[red]  ✗ Google blocked (CAPTCHA). Use --sinapigoogle with proxies.[/red]")
            results[dork] = ["BLOCKED: Google detected automated traffic"]
            continue
        soup  = BeautifulSoup(resp.text, "html.parser")
        links = []
        for g in soup.select("div.g a[href]"):
            href = g.get("href", "")
            if href.startswith("/url?q="):
                href = href[7:].split("&")[0]
            if href.startswith("http") and domain in href:
                links.append(href)
        results[dork] = list(dict.fromkeys(links))
    return results

# ── Bing ─────────────────────────────────────────────────────────────────────

def dork_bing_api(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    if not cfg.bing_api_key:
        return {"_error": "Bing API key missing"}
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        try:
            resp = make_request(
                "https://api.bing.microsoft.com/v7.0/search",
                cfg,
                extra_headers={"Ocp-Apim-Subscription-Key": cfg.bing_api_key},
                params={"q": dork, "count": 10, "mkt": "en-US"},
            )
            if resp and resp.ok:
                pages = resp.json().get("webPages", {}).get("value", [])
                results[dork] = [p["url"] for p in pages]
            else:
                results[dork] = []
        except Exception:
            results[dork] = []
        time.sleep(cfg.request_delay)
    return results

def dork_bing_scrape(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        encoded = requests.utils.quote(dork)
        url = f"https://www.bing.com/search?q={encoded}&count=20"
        console.print(f"[cyan]  → Bing scrape:[/cyan] {dork}")
        scrape_delay(cfg)
        resp = make_request(url, cfg)
        if not resp:
            results[dork] = []
            continue
        soup  = BeautifulSoup(resp.text, "html.parser")
        links = []
        for li in soup.select("li.b_algo"):
            a = li.find("a")
            if a and a.get("href", "").startswith("http") and domain in a["href"]:
                links.append(a["href"])
        results[dork] = list(dict.fromkeys(links))
    return results

# ── DuckDuckGo  (free, no API, excellent for bug bounty) ─────────────────────

def dork_ddg(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    if not DDG_AVAILABLE:
        console.print("[yellow]  ⚠ duckduckgo_search not installed. Run: pip install duckduckgo-search[/yellow]")
        return {"_error": "duckduckgo_search library not installed"}
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        console.print(f"[magenta]  → DDG:[/magenta] {dork}")
        try:
            with DDGS() as ddgs:
                hits = list(ddgs.text(dork, max_results=15))
            results[dork] = [h["href"] for h in hits]
        except Exception as e:
            console.print(f"[red]  ✗ DDG error: {e}[/red]")
            results[dork] = []
        scrape_delay(cfg)
    return results

# ── Yahoo ─────────────────────────────────────────────────────────────────────

def dork_yahoo(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        encoded = requests.utils.quote(dork)
        url = f"https://search.yahoo.com/search?p={encoded}&n=20"
        console.print(f"[bright_yellow]  → Yahoo:[/bright_yellow] {dork}")
        scrape_delay(cfg)
        resp = make_request(url, cfg)
        if not resp:
            results[dork] = []
            continue
        soup  = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.select("div.compTitle a[href]"):
            href = a["href"]
            if "yahoo.com" not in href and href.startswith("http") and domain in href:
                links.append(href)
        for a in soup.select("h3.title a[href]"):
            href = a.get("href", "")
            if href.startswith("http") and domain in href:
                links.append(href)
        results[dork] = list(dict.fromkeys(links))
    return results

# ── Yandex ────────────────────────────────────────────────────────────────────

def dork_yandex(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    for dork in _format_dorks(dorks, domain):
        encoded = requests.utils.quote(dork)
        url = f"https://yandex.com/search/?text={encoded}&numdoc=20&lr=213"
        console.print(f"[bold red]  → Yandex:[/bold red] {dork}")
        scrape_delay(cfg)
        resp = make_request(url, cfg)
        if not resp:
            results[dork] = []
            continue
        soup  = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.select("a.OrganicTitle-Link, a.link_theme_outer"):
            href = a.get("href", "")
            if href.startswith("http") and domain in href:
                links.append(href)
        results[dork] = list(dict.fromkeys(links))
    return results

# ── Brave ─────────────────────────────────────────────────────────────────────

def dork_brave(domain: str, dorks: List[str], cfg: Config) -> Dict[str, List[str]]:
    if not cfg.brave_api_key:
        console.print("[yellow]  ⚠ No Brave API key (BRAVE_API_KEY). Skipping Brave.[/yellow]")
        return {"_error": "No Brave API key"}
    results: Dict[str, List[str]] = {}
    headers = {
        "Accept":              "application/json",
        "Accept-Encoding":     "gzip",
        "X-Subscription-Token": cfg.brave_api_key,
    }
    for dork in _format_dorks(dorks, domain):
        try:
            resp = make_request(
                "https://api.search.brave.com/res/v1/web/search",
                cfg,
                extra_headers=headers,
                params={"q": dork, "count": 10},
            )
            if resp and resp.ok:
                items = resp.json().get("web", {}).get("results", [])
                results[dork] = [i["url"] for i in items]
            else:
                results[dork] = []
        except Exception as e:
            results[dork] = []
        time.sleep(cfg.request_delay)
    return results

# ── Engine dispatcher ─────────────────────────────────────────────────────────

def run_dork_engines(
    domain: str,
    dorks:  List[str],
    cfg:    Config,
    engines: List[str],
    args:   argparse.Namespace,
) -> Dict[str, Dict[str, List[Dict]]]:
    """
    Run selected dork engines.
    Returns {engine_name: {dork: [{"url": ..., "is_file": bool, "file_type": str}]}}
    URLs are NEVER fetched — file classification is based on URL string only.
    """
    engine_results: Dict[str, Dict] = {}

    for engine in engines:
        engine = engine.strip().lower()
        console.print(f"\n[bold]◈ Dorking with engine: {engine.upper()}[/bold]")

        raw: Dict[str, List[str]] = {}

        if engine == "google":
            if cfg.google_api_key and cfg.google_cse_id and not args.sinapigoogle:
                raw = dork_google_api(domain, dorks, cfg)
            else:
                raw = dork_google_scrape(domain, dorks, cfg)

        elif engine == "bing":
            if cfg.bing_api_key and not args.sinapibing:
                raw = dork_bing_api(domain, dorks, cfg)
            else:
                raw = dork_bing_scrape(domain, dorks, cfg)

        elif engine == "ddg":
            raw = dork_ddg(domain, dorks, cfg)

        elif engine == "yahoo":
            raw = dork_yahoo(domain, dorks, cfg)

        elif engine == "yandex":
            raw = dork_yandex(domain, dorks, cfg)

        elif engine == "brave":
            raw = dork_brave(domain, dorks, cfg)

        else:
            console.print(f"[yellow]  ⚠ Unknown engine: {engine}[/yellow]")
            continue

        # Enrich: tag each URL with file-type metadata — no network requests
        engine_results[engine] = enrich_dork_results(raw)

    return engine_results

# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORING
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title:    str
    detail:   str
    evidence: str = ""

def calculate_risk(report: Dict) -> Dict:
    """Generate prioritized findings and risk score (0–100)."""
    findings: List[Finding] = []
    penalty = 0

    # Sensitive paths
    crit_paths = [p for p in report.get("sensitive_paths", [])
                  if p.get("severity") == "CRITICAL" and p.get("status") == 200]
    high_paths = [p for p in report.get("sensitive_paths", [])
                  if p.get("severity") == "HIGH"     and p.get("status") == 200]
    if crit_paths:
        penalty += 40
        for p in crit_paths:
            findings.append(Finding("CRITICAL", "Exposed Sensitive File",
                                    f"HTTP 200 on {p['path']} ({p['size']} bytes)", p["url"]))
    if high_paths:
        penalty += 20
        findings.append(Finding("HIGH", "Exposed Admin/API Surface",
                                f"{len(high_paths)} admin/API paths accessible",
                                ", ".join(p["path"] for p in high_paths[:5])))

    # CORS
    cors = report.get("cors_findings", [])
    crit_cors = [c for c in cors if c["severity"] == "CRITICAL"]
    high_cors  = [c for c in cors if c["severity"] == "HIGH"]
    if crit_cors:
        penalty += 35
        findings.append(Finding("CRITICAL", "Critical CORS Misconfiguration",
                                "Arbitrary origin + credentials allowed",
                                str(crit_cors[0])))
    elif high_cors:
        penalty += 20
        findings.append(Finding("HIGH", "CORS Misconfiguration",
                                "Credentials allowed from reflected origin",
                                str(high_cors[0])))

    # Security headers
    headers = report.get("security_headers", {})
    if headers:
        for scheme, data in headers.items():
            missing = [h for h, v in data.get("headers", {}).items() if v == "MISSING"]
            pct = len(missing) / len(SECURITY_HEADER_LIST)
            if pct > 0.7:
                penalty += 20
                findings.append(Finding("HIGH", "Critical Security Headers Missing",
                                        f"{len(missing)}/{len(SECURITY_HEADER_LIST)} headers not set",
                                        ", ".join(missing[:5])))
            elif pct > 0.3:
                penalty += 10
                findings.append(Finding("MEDIUM", "Some Security Headers Missing",
                                        f"{len(missing)}/{len(SECURITY_HEADER_LIST)} headers not set",
                                        ", ".join(missing[:5])))
            break

    # Risky open ports
    risky_ports = [p for p in report.get("open_ports", []) if p.get("severity") == "HIGH"]
    if risky_ports:
        penalty += 15
        findings.append(Finding("HIGH", "Dangerous Ports Exposed",
                                f"Ports: {', '.join(str(p['port']) for p in risky_ports)}",
                                "Services: " + ", ".join(p["service"] for p in risky_ports)))

    # Data leaks
    if report.get("leaks"):
        penalty += 20
        findings.append(Finding("HIGH", "Credentials Found in Breach DB",
                                f"{len(report['leaks'])} records in ProxyNova",
                                report["leaks"][0] if report["leaks"] else ""))

    # Shodan vulns
    shodan_vulns = report.get("shodan_info", {}).get("vulns", [])
    if shodan_vulns:
        penalty += 25
        findings.append(Finding("HIGH", "Known CVEs (Shodan)",
                                f"{len(shodan_vulns)} vulnerabilities found",
                                ", ".join(shodan_vulns[:5])))

    # Server version disclosure
    server_str = ""
    for scheme, data in (report.get("security_headers") or {}).items():
        server_str = data.get("server", "")
        break
    if server_str and any(c.isdigit() for c in server_str):
        penalty += 5
        findings.append(Finding("LOW", "Server Version Disclosure",
                                f"Server header reveals version: {server_str}", ""))

    # JS secrets — CRITICAL
    js_secrets = (report.get("js_analysis") or {}).get("secrets", [])
    if js_secrets:
        penalty += 45
        for s in js_secrets[:3]:
            findings.append(Finding("CRITICAL", "Secret Exposed in JavaScript",
                                    f"{s.get('type','?')} found in {s.get('url','?')}",
                                    s.get("match", "")[:120]))

    # Subdomain takeover — HIGH
    takeovers = [t for t in (report.get("subdomain_takeover") or []) if t.get("vulnerable")]
    if takeovers:
        penalty += 40
        for tk in takeovers[:3]:
            findings.append(Finding("HIGH", "Subdomain Takeover Possible",
                                    f"{tk['subdomain']} → {tk.get('service','?')} (CNAME: {tk.get('cname','?')})",
                                    tk.get("detail", "")))

    # Cloud buckets — HIGH
    pub_buckets = [b for b in (report.get("cloud_buckets") or []) if b.get("status") == "PUBLIC"]
    any_buckets = [b for b in (report.get("cloud_buckets") or []) if b.get("status") in ("PUBLIC","EXISTS")]
    if pub_buckets:
        penalty += 35
        findings.append(Finding("HIGH", "Public Cloud Bucket Exposed",
                                f"{len(pub_buckets)} publicly accessible bucket(s)",
                                ", ".join(b["url"] for b in pub_buckets[:3])))
    elif any_buckets:
        penalty += 10
        findings.append(Finding("MEDIUM", "Cloud Buckets Exist",
                                f"{len(any_buckets)} bucket(s) detected (access restricted)",
                                ", ".join(b["url"] for b in any_buckets[:3])))

    # Email security (SPF/DMARC/DKIM) — CRITICAL if no DMARC
    email_sec = report.get("email_security") or {}
    # dmarc and spf are always dicts (structured by analyze_email_security)
    dmarc = email_sec.get("dmarc") or {}
    spf   = email_sec.get("spf")   or {}
    # Ensure they're dicts even if something unexpected came through
    if not isinstance(dmarc, dict):
        dmarc = {"record": str(dmarc), "policy": ""}
    if not isinstance(spf, dict):
        spf = {"record": str(spf), "all_qualifier": ""}

    if not dmarc.get("record"):
        penalty += 25
        findings.append(Finding("CRITICAL", "No DMARC Policy",
                                "Domain is vulnerable to email spoofing/phishing",
                                "Add a DMARC record: _dmarc.<domain> TXT v=DMARC1;p=reject"))
    elif dmarc.get("policy") == "none":
        penalty += 10
        findings.append(Finding("MEDIUM", "DMARC Policy = none (monitor only)",
                                "Email spoofing not actively blocked",
                                f"Record: {dmarc.get('record','')[:80]}"))
    if not spf.get("record"):
        penalty += 15
        findings.append(Finding("HIGH", "No SPF Record",
                                "Anyone can send email as this domain",
                                "Add a TXT record: v=spf1 ... ~all"))
    elif spf.get("all_qualifier") in ("+", "?"):
        penalty += 10
        findings.append(Finding("HIGH", "Weak SPF Policy (+all or ?all)",
                                "SPF allows all senders — effectively useless",
                                f"Record: {spf.get('record','')[:80]}"))

    # GitHub leaks — CRITICAL
    github_leaks = report.get("github_leaks") or []
    if github_leaks:
        penalty += 40
        findings.append(Finding("CRITICAL", "Secrets Found on GitHub",
                                f"{len(github_leaks)} result(s) from GitHub code search",
                                github_leaks[0].get("url", "") if isinstance(github_leaks[0], dict) else str(github_leaks[0])))

    # WHOIS privacy / registrar mismatch
    whois = report.get("whois") or {}
    registrar = whois.get("registrar", "")
    if registrar and "privacy" not in registrar.lower() and not whois.get("redacted"):
        # just informational — no penalty, but note it
        findings.append(Finding("INFO", "WHOIS Data Exposed",
                                f"Registrar: {registrar}",
                                f"Name: {whois.get('registrant_name','N/A')} | Email: {whois.get('registrant_email','N/A')}"))

    score = max(0, 100 - penalty)
    grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F"

    return {
        "score":    score,
        "grade":    grade,
        "penalty":  penalty,
        "findings": [asdict(f) for f in findings],
    }

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TripRecon — {{ report.domain }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  /* ── TOKENS ─────────────────────────────────────────────────────────────── */
  :root {
    /* backgrounds */
    --bg:       #080b12;
    --bg2:      #0d1117;
    --bg3:      #131920;
    --bg4:      #1a2230;
    /* brand */
    --accent:   #00d9a3;
    --accent2:  #3b82f6;
    --accent3:  #8b5cf6;
    /* text */
    --text:     #e2e8f0;
    --text2:    #94a3b8;
    --text3:    #64748b;
    /* borders */
    --border:   #1e2d3d;
    --border2:  #263345;
    /* severity */
    --critical: #f43f5e;
    --high:     #f97316;
    --medium:   #eab308;
    --low:      #3b82f6;
    --info:     #64748b;
    /* aliases */
    --green:    #00d9a3;
    --blue:     #3b82f6;
    --red:      #f43f5e;
    --orange:   #f97316;
    --yellow:   #eab308;
    --dim:      #64748b;
    --purple:   #8b5cf6;
    /* shadows */
    --shadow-sm:  0 1px 3px rgba(0,0,0,.4);
    --shadow-md:  0 4px 16px rgba(0,0,0,.5);
    --shadow-glow: 0 0 30px rgba(0,217,163,.08);
  }

  /* ── RESET & BASE ─────────────────────────────────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 14px; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.65;
    overflow-x: hidden;
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--accent2); text-decoration: none; }
  a:hover { color: var(--accent); text-decoration: underline; }
  code, .mono {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 12px;
  }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg2); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

  /* ── LAYOUT ──────────────────────────────────────────────────────────── */
  .wrapper { max-width: 1320px; margin: 0 auto; padding: 28px 24px 40px; }

  /* ── COVER / HEADER ─────────────────────────────────────────────────── */
  .header {
    background: linear-gradient(135deg, #0d1829 0%, #0a1220 40%, #0d1829 100%);
    border: 1px solid var(--border2);
    border-radius: 12px;
    padding: 0;
    margin-bottom: 24px;
    overflow: hidden;
    box-shadow: var(--shadow-md), var(--shadow-glow);
    position: relative;
  }
  .header-accent-bar {
    height: 4px;
    background: linear-gradient(90deg, var(--accent) 0%, var(--accent2) 50%, var(--accent3) 100%);
  }
  .header-inner {
    padding: 32px 36px 28px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 24px;
    align-items: center;
  }
  @media (max-width: 640px) { .header-inner { grid-template-columns: 1fr; } }
  .header-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 12px;
  }
  .header-logo {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent) 0%, var(--accent2) 100%);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    font-weight: 700;
    color: #fff;
    font-family: 'Space Grotesk', sans-serif;
    flex-shrink: 0;
    box-shadow: 0 0 20px rgba(0,217,163,.3);
  }
  .header-brand-text { display: flex; flex-direction: column; }
  .header-brand-name {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 20px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: .5px;
  }
  .header-brand-tag {
    font-size: 11px;
    color: var(--text3);
    letter-spacing: 2px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }
  .header h1 {
    font-family: 'Space Grotesk', sans-serif;
    font-size: clamp(22px, 3.5vw, 36px);
    font-weight: 700;
    color: var(--text);
    letter-spacing: -.5px;
    margin-bottom: 6px;
    line-height: 1.2;
  }
  .header h1 .domain-highlight {
    color: var(--accent);
    position: relative;
  }
  .header .subtitle {
    font-size: 13px;
    color: var(--text3);
    letter-spacing: 2px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 16px;
  }
  .header-meta-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  }
  .header-meta-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .header-meta-label { font-size: 10px; color: var(--text3); text-transform: uppercase; letter-spacing: 1.5px; font-family: 'JetBrains Mono', monospace; }
  .header-meta-val   { font-size: 13px; color: var(--text); font-weight: 600; font-family: 'JetBrains Mono', monospace; }
  .header-meta-val.accent { color: var(--accent); }
  .header-score-preview {
    text-align: center;
    background: rgba(0,0,0,.3);
    border: 1px solid var(--border2);
    border-radius: 10px;
    padding: 20px 28px;
    min-width: 160px;
  }
  .header-score-preview .preview-score {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 52px;
    font-weight: 700;
    line-height: 1;
  }
  .header-score-preview .preview-grade {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 16px;
    font-weight: 600;
    margin-top: 2px;
  }
  .header-score-preview .preview-label {
    font-size: 10px;
    color: var(--text3);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 6px;
    font-family: 'JetBrains Mono', monospace;
  }

  /* ── RISK SCORE ─────────────────────────────────────────────────────── */
  .score-A { color: #10b981; }
  .score-B { color: #34d399; }
  .score-C { color: var(--yellow); }
  .score-D { color: var(--orange); }
  .score-F { color: var(--red); }
  .score-A-glow { text-shadow: 0 0 24px rgba(16,185,129,.4); }
  .score-B-glow { text-shadow: 0 0 24px rgba(52,211,153,.4); }
  .score-C-glow { text-shadow: 0 0 24px rgba(234,179,8,.4); }
  .score-D-glow { text-shadow: 0 0 24px rgba(249,115,22,.4); }
  .score-F-glow { text-shadow: 0 0 24px rgba(244,63,94,.4); }

  .risk-row {
    display: grid;
    grid-template-columns: 240px 1fr;
    gap: 16px;
    margin-bottom: 24px;
    align-items: start;
  }
  @media (max-width: 700px) { .risk-row { grid-template-columns: 1fr; } }
  .score-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px 20px;
    text-align: center;
    box-shadow: var(--shadow-sm);
    position: relative;
    overflow: hidden;
  }
  .score-card::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, transparent, var(--score-color, var(--accent2)), transparent);
    opacity: .6;
  }
  .score-card.grade-F { border-color: rgba(244,63,94,.3); --score-color: var(--red); }
  .score-card.grade-D { border-color: rgba(249,115,22,.3); --score-color: var(--orange); }
  .score-card.grade-C { border-color: rgba(234,179,8,.3);  --score-color: var(--yellow); }
  .score-card.grade-B { border-color: rgba(52,211,153,.3); --score-color: #34d399; }
  .score-card.grade-A { border-color: rgba(16,185,129,.3); --score-color: #10b981; }
  .score-card .score-val {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 68px;
    line-height: 1;
    font-weight: 700;
  }
  .score-card .score-grade-text {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 18px;
    font-weight: 700;
    margin-top: 4px;
    letter-spacing: 1px;
  }
  .score-card .label {
    color: var(--text3);
    font-size: 9px;
    letter-spacing: 2.5px;
    margin-top: 12px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }
  .score-bar {
    height: 5px;
    background: var(--border);
    border-radius: 3px;
    margin-top: 14px;
    overflow: hidden;
  }
  .score-bar-fill { height: 100%; border-radius: 3px; }

  /* ── FINDINGS ────────────────────────────────────────────────────────── */
  .findings-list { display: flex; flex-direction: column; gap: 6px; }
  .finding-item {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-left: 4px solid var(--dim);
    border-radius: 0 10px 10px 0;
    padding: 12px 16px 12px 14px;
    display: flex;
    gap: 14px;
    align-items: flex-start;
    transition: border-left-color .15s, background .15s, box-shadow .15s;
  }
  .finding-item:hover {
    background: var(--bg4);
    box-shadow: inset 0 0 0 1px rgba(255,255,255,.04);
  }
  .finding-item.CRITICAL { border-left-color: var(--critical); }
  .finding-item.HIGH     { border-left-color: var(--high);     }
  .finding-item.MEDIUM   { border-left-color: var(--medium);   }
  .finding-item.LOW      { border-left-color: var(--low);      }
  .finding-item.INFO     { border-left-color: var(--info);     }
  .finding-item.CRITICAL:hover { background: rgba(244,63,94,.04); }
  .finding-item.HIGH:hover     { background: rgba(249,115,22,.04); }
  .finding-badge-col { flex-shrink: 0; width: 90px; padding-top: 1px; }
  .finding-body { flex: 1; min-width: 0; }
  .sev-badge {
    padding: 3px 9px;
    border-radius: 5px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-align: center;
    width: fit-content;
    font-family: 'JetBrains Mono', monospace;
    display: block;
  }
  .badge-CRITICAL { background: rgba(244,63,94,.15);  color: var(--critical); border: 1px solid rgba(244,63,94,.4); }
  .badge-HIGH     { background: rgba(249,115,22,.15); color: var(--high);     border: 1px solid rgba(249,115,22,.4); }
  .badge-MEDIUM   { background: rgba(234,179,8,.15);  color: var(--yellow);   border: 1px solid rgba(234,179,8,.4); }
  .badge-LOW      { background: rgba(59,130,246,.15); color: var(--blue);     border: 1px solid rgba(59,130,246,.4); }
  .badge-INFO     { background: rgba(100,116,139,.12); color: var(--info);    border: 1px solid rgba(100,116,139,.25); }
  .sev-badge.large { font-size: 10.5px; padding: 4px 10px; }
  .finding-body .title  { color: var(--text);  font-size: 13px; font-weight: 600; line-height: 1.4; }
  .finding-body .detail { color: var(--text2); font-size: 12px; margin-top: 4px; line-height: 1.5; }
  .finding-body .detail-url {
    color: var(--text3);
    margin-top: 5px;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* ── STATS GRID ─────────────────────────────────────────────────────── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 14px;
    margin-bottom: 28px;
  }
  .stat-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 16px 16px;
    text-align: center;
    transition: border-color .2s, box-shadow .2s, transform .15s;
    box-shadow: var(--shadow-sm);
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent2), var(--accent3));
    opacity: 0;
    transition: opacity .2s;
  }
  .stat-card:hover { border-color: var(--accent); box-shadow: 0 0 20px rgba(0,217,163,.12); transform: translateY(-1px); }
  .stat-card:hover::before { opacity: 1; }
  .stat-card .stat-icon {
    font-size: 22px;
    line-height: 1;
    margin-bottom: 8px;
    display: block;
    opacity: .8;
  }
  .stat-card .num {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 28px;
    font-weight: 700;
    color: var(--text2);
    line-height: 1;
  }
  .stat-card .num.danger { color: var(--red);    }
  .stat-card .num.warn   { color: var(--orange); }
  .stat-card .num.ok     { color: var(--accent); }
  .stat-card .num.dim    { color: var(--text3);  }
  .stat-card .stat-label {
    color: var(--text3);
    font-size: 10.5px;
    letter-spacing: .8px;
    margin-top: 7px;
    font-weight: 600;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }

  /* ── CHARTS ──────────────────────────────────────────────────────────── */
  .charts-row {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    margin-bottom: 24px;
  }
  @media (max-width: 900px) { .charts-row { grid-template-columns: 1fr 1fr; } }
  @media (max-width: 580px) { .charts-row { grid-template-columns: 1fr;     } }
  .chart-box {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    box-shadow: var(--shadow-sm);
    transition: border-color .2s;
  }
  .chart-box:hover { border-color: var(--border2); }
  .chart-box h4 {
    color: var(--text3);
    font-size: 10px;
    letter-spacing: 1.8px;
    margin-bottom: 16px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .chart-box h4::before {
    content: '';
    display: inline-block;
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
    flex-shrink: 0;
  }
  .chart-box canvas { max-height: 220px; }

  /* ── SECTIONS ────────────────────────────────────────────────────────── */
  .section {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 10px;
    overflow: hidden;
    box-shadow: var(--shadow-sm);
    transition: border-color .2s, box-shadow .2s;
  }
  .section:hover { border-color: var(--border2); box-shadow: 0 4px 20px rgba(0,0,0,.35); }
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 13px 18px;
    cursor: pointer;
    user-select: none;
    border-bottom: 1px solid var(--border);
    transition: background .15s;
    gap: 12px;
  }
  .section-header:hover { background: rgba(255,255,255,.025); }
  .section-header-left { display: flex; align-items: center; gap: 10px; }
  .section-icon {
    width: 32px; height: 32px;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 15px;
    flex-shrink: 0;
    background: linear-gradient(135deg, var(--bg4) 0%, var(--bg3) 100%);
    border: 1px solid var(--border2);
  }
  .section-header h2 {
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: .1px;
  }
  .section-header-right { display: flex; align-items: center; gap: 10px; }
  .section-header .count {
    color: var(--text3);
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    background: var(--bg4);
    border: 1px solid var(--border);
    padding: 2px 9px;
    border-radius: 20px;
  }
  .section-header .arrow {
    color: var(--text3);
    transition: transform .2s, color .15s;
    font-size: 11px;
    width: 18px; height: 18px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 4px;
    background: var(--bg4);
  }
  .section-header:hover .arrow { color: var(--accent); }
  .section-header.collapsed .arrow { transform: rotate(-90deg); }
  .section-body { padding: 16px 18px; }
  .section-body.hidden { display: none; }

  /* ── TABLES ──────────────────────────────────────────────────────────── */
  .data-table { width: 100%; border-collapse: separate; border-spacing: 0; }
  .data-table th {
    background: var(--bg4);
    color: var(--accent);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border2);
    position: sticky; top: 0; z-index: 1;
    font-family: 'JetBrains Mono', monospace;
  }
  .data-table td {
    padding: 9px 14px;
    border-bottom: 1px solid rgba(30,45,61,.7);
    vertical-align: top;
    word-break: break-all;
    font-size: 12.5px;
    color: var(--text2);
    line-height: 1.5;
  }
  .data-table tbody tr:nth-child(even) td { background: rgba(255,255,255,.018); }
  .data-table tbody tr:last-child td { border-bottom: none; }
  .data-table tr:hover td { background: rgba(0,217,163,.05) !important; color: var(--text); }
  .data-table .url a { color: var(--accent2); font-family: 'JetBrains Mono', monospace; font-size: 11.5px; }
  .data-table .url a:hover { color: var(--accent); }
  .data-table td:first-child { font-weight: 600; color: var(--text); }
  .scroll-wrap { overflow-x: auto; max-height: 460px; overflow-y: auto; border-radius: 8px; border: 1px solid var(--border); background: var(--bg2); }

  /* ── FILTER INPUT ────────────────────────────────────────────────────── */
  .filter-input {
    width: 100%;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 7px;
    color: var(--text);
    padding: 8px 14px;
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    margin-bottom: 12px;
    outline: none;
    transition: border-color .15s;
  }
  .filter-input::placeholder { color: var(--text3); }
  .filter-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0,217,163,.1); }

  /* ── CODE / PRE ──────────────────────────────────────────────────────── */
  pre {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 14px 16px;
    overflow-x: auto;
    color: var(--text2);
    white-space: pre-wrap;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    line-height: 1.7;
  }

  /* ── DORK RESULTS ────────────────────────────────────────────────────── */
  .dork-engine { margin-bottom: 12px; }
  .dork-engine-title {
    background: var(--bg3);
    padding: 9px 14px;
    border-radius: 7px;
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: var(--text);
    font-weight: 500;
    border: 1px solid var(--border);
    transition: border-color .15s;
  }
  .dork-engine-title:hover { border-color: var(--accent2); background: var(--bg4); }
  .dork-items { padding-top: 8px; }
  .dork-query { color: var(--text3); font-size: 11.5px; margin-bottom: 4px; padding-left: 8px; border-left: 2px solid var(--border2); font-family: 'JetBrains Mono', monospace; }
  .dork-url   { padding: 2px 8px; }
  .dork-url a { color: var(--accent2); font-size: 12px; }
  .dork-url a:hover { color: var(--accent); }
  .dork-empty { color: var(--text3); font-size: 12px; font-style: italic; padding: 8px 0; }

  /* ── WAF BADGE ───────────────────────────────────────────────────────── */
  .waf-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(249,115,22,.1);
    border: 1px solid rgba(249,115,22,.3);
    color: var(--orange);
    padding: 5px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 500;
    margin-top: 6px;
  }

  /* ── TOOLBAR / BUTTONS ───────────────────────────────────────────────── */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--bg3);
    border: 1px solid var(--border2);
    color: var(--text2);
    padding: 8px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-family: 'Inter', sans-serif;
    font-size: 12.5px;
    font-weight: 500;
    transition: background .15s, border-color .15s, color .15s, box-shadow .15s;
    text-decoration: none;
    letter-spacing: .2px;
  }
  .btn:hover { background: var(--bg4); border-color: rgba(0,217,163,.4); color: var(--accent); text-decoration: none; box-shadow: 0 0 0 1px rgba(0,217,163,.1); }
  .btn.primary { background: linear-gradient(135deg, var(--accent), #00c49290); color: #000; border-color: var(--accent); font-weight: 700; }
  .btn.primary:hover { background: linear-gradient(135deg, #00c492, var(--accent)); color: #000; }
  .toolbar {
    display: flex;
    gap: 8px;
    margin-bottom: 24px;
    flex-wrap: wrap;
    align-items: center;
    padding: 12px 16px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
  }

  /* ── INLINE PILLS / TAGS ─────────────────────────────────────────────── */
  .pill {
    display: inline-flex;
    align-items: center;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: .4px;
  }
  .pill-ok     { background: rgba(0,217,163,.1); color: var(--accent); border: 1px solid rgba(0,217,163,.25); }
  .pill-warn   { background: rgba(234,179,8,.1);  color: var(--yellow); border: 1px solid rgba(234,179,8,.25); }
  .pill-danger { background: rgba(244,63,94,.1);  color: var(--red);    border: 1px solid rgba(244,63,94,.25); }
  .pill-info   { background: rgba(59,130,246,.1); color: var(--blue);   border: 1px solid rgba(59,130,246,.25); }
  .pill-dim    { background: rgba(100,116,139,.1);color: var(--info);   border: 1px solid rgba(100,116,139,.2); }

  /* ── SECTION DIVIDER LABEL ───────────────────────────────────────────── */
  .section-group-label {
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2.5px;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    margin: 32px 0 12px;
    display: flex;
    align-items: center;
    gap: 10px;
    padding-left: 2px;
  }
  .section-group-label::before {
    content: '';
    width: 3px; height: 12px;
    border-radius: 2px;
    background: var(--accent);
    flex-shrink: 0;
  }
  .section-group-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, var(--border2), transparent);
  }

  /* ── FOOTER ──────────────────────────────────────────────────────────── */
  .footer {
    text-align: center;
    color: var(--text3);
    font-size: 12px;
    padding: 32px 0 12px;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 1px;
    border-top: 1px solid var(--border);
    margin-top: 32px;
  }
  .footer a { color: var(--text3); }
  .footer a:hover { color: var(--accent); text-decoration: none; }
  .footer-inner {
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 8px;
  }
  .footer-brand {
    display: flex; align-items: center; gap: 10px;
    font-weight: 600; font-size: 13px; color: var(--text);
  }
  .footer-logo {
    width: 28px; height: 28px; border-radius: 6px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: #000; font-weight: 800; font-size: 11px;
    display: flex; align-items: center; justify-content: center;
  }
  .footer-meta { font-size: 12px; color: var(--dim); }
  .footer-copy { font-size: 11px; color: var(--dim2); }

  /* ── STATUS / IMPACT / REC CELLS ────────────────────────────────────── */
  .status-badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 9px; border-radius: 5px; font-size: 10px; font-weight: 700;
    letter-spacing: .6px; white-space: nowrap;
    font-family: 'JetBrains Mono', monospace;
  }
  .status-ok   { background: rgba(0,217,163,.14); color: #00d9a3; border: 1px solid rgba(0,217,163,.25); }
  .status-bad  { background: rgba(244,63,94,.14);  color: #f43f5e; border: 1px solid rgba(244,63,94,.25); }
  .status-warn { background: rgba(234,179,8,.14);  color: #eab308; border: 1px solid rgba(234,179,8,.25); }
  .status-info { background: rgba(100,116,139,.12);color: #94a3b8; border: 1px solid rgba(100,116,139,.2); }
  .impact-cell {
    font-size: 11.5px; color: var(--text3); line-height: 1.5;
    font-style: italic; max-width: 340px;
  }
  .impact-cell span { font-style: normal; }
  .rec-cell {
    font-size: 10.5px; color: var(--accent2);
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all; max-width: 260px;
  }
  .info-badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px;
    background: rgba(59,130,246,.12); color: var(--accent2); border: 1px solid rgba(59,130,246,.2);
  }
  .info-badge.warn {
    background: rgba(249,115,22,.12); color: var(--orange); border-color: rgba(249,115,22,.2);
  }
  .section-desc {
    font-size: 11.5px; color: var(--text3); margin-bottom: 12px; line-height: 1.6;
    padding: 8px 12px; background: rgba(255,255,255,.025); border-radius: 6px;
    border-left: 3px solid var(--border2);
  }

  /* ── RESPONSIVE ──────────────────────────────────────────────────────── */
  @media (max-width: 900px) {
    .charts-row { grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 640px) {
    html { font-size: 13px; }
    .wrapper { padding: 14px 12px 28px; }
    .header-inner { grid-template-columns: 1fr; gap: 16px; }
    .header-score-preview { display: flex; align-items: center; gap: 16px; justify-content: flex-start; padding: 14px 18px; }
    .header-score-preview .preview-score { font-size: 38px; }
    .charts-row { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
    .stat-card { padding: 14px 10px 12px; }
    .stat-card .num { font-size: 22px; }
    .risk-row { grid-template-columns: 1fr; }
    .score-card { padding: 18px 14px; }
    .score-card .score-val { font-size: 52px; }
    .section-header { padding: 10px 14px; }
    .section-header h2 { font-size: 13px; }
    .section-body { padding: 12px 10px; }
    .data-table th, .data-table td { padding: 7px 10px; font-size: 11.5px; }
    .impact-cell { display: none; }  /* hide on mobile to keep tables scannable */
    .rec-cell { max-width: 140px; }
    .toolbar { gap: 6px; padding: 8px 10px; }
    .btn { padding: 6px 12px; font-size: 11px; }
    .filter-input { font-size: 12px; padding: 7px 10px; }
    .finding-badge-col { width: 74px; }
    .section-group-label { font-size: 9px; margin: 24px 0 10px; }
    .header-meta-grid { gap: 10px; }
    .header h1 { font-size: 20px; }
    .footer-inner { flex-direction: column; align-items: flex-start; gap: 6px; }
  }
  @media (max-width: 400px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .header-score-preview .preview-score { font-size: 32px; }
  }

  /* ── PRINT ───────────────────────────────────────────────────────────── */
  @media print {
    .sidebar, .topbar, .sidebar-overlay, .hamburger { display: none !important; }
    .shell { display: block; }
    .main  { display: block; }
    .content { overflow: visible; }
    .btn, .filter-input, .toolbar { display: none; }
    .section-body.hidden { display: block !important; }
    .impact-cell { display: table-cell !important; }
    body { background: #fff; color: #111; }
    .header, .section, .stat-card, .chart-box {
      border-color: #ddd; background: #fff; box-shadow: none;
    }
    .data-table td { color: #111; border-color: #eee; }
    .data-table th { background: #f5f5f5; color: #444; border-color: #ddd; }
    .header-accent-bar { display: none; }
    .score-A { color: #059669 !important; }
    .score-F { color: #dc2626 !important; }
    .status-ok  { background: #d1fae5 !important; color: #065f46 !important; }
    .status-bad { background: #fee2e2 !important; color: #991b1b !important; }
  }

  /* ── SHELL LAYOUT ─────────────────────────────────────────────────────── */
  html, body { height: 100%; overflow: hidden; }
  .shell {
    display: flex;
    height: 100vh;
    overflow: hidden;
  }

  /* ── SIDEBAR ─────────────────────────────────────────────────────────── */
  .sidebar {
    width: 230px;
    flex-shrink: 0;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    z-index: 10;
  }
  .sidebar-logo {
    padding: 16px 14px 12px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .logo-mark {
    display: flex;
    align-items: center;
    gap: 9px;
  }
  .logo-icon {
    width: 30px; height: 30px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 11px; font-weight: 800;
    color: #000; flex-shrink: 0;
    box-shadow: 0 0 14px rgba(0,217,163,.3);
  }
  .logo-text {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px; font-weight: 700;
    color: var(--text); line-height: 1.2;
  }
  .logo-text small {
    display: block; font-size: 9px; font-weight: 400;
    color: var(--text3); letter-spacing: 1.2px; text-transform: uppercase;
  }
  .sidebar-domain-strip {
    padding: 9px 14px 8px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .sidebar-domain {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: var(--accent);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .sidebar-domain small { color: var(--text3); font-size: 9px; display: block; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 2px; }
  .sidebar-nav {
    flex: 1; overflow-y: auto; padding: 6px 0 16px;
    scrollbar-width: thin; scrollbar-color: var(--border2) transparent;
  }
  .nav-group { margin-bottom: 2px; }
  .nav-group-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px; font-weight: 700;
    letter-spacing: 1.8px; text-transform: uppercase;
    color: var(--text3); padding: 10px 14px 4px;
  }
  .nav-item {
    display: flex; align-items: center; gap: 8px;
    padding: 7px 14px; cursor: pointer;
    color: var(--text2); font-size: 12px;
    border-left: 2px solid transparent;
    transition: background .1s, color .1s, border-left-color .1s;
    user-select: none;
  }
  .nav-item:hover { background: rgba(255,255,255,.04); color: var(--text); }
  .nav-item.active { background: rgba(0,217,163,.1); color: var(--accent); border-left-color: var(--accent); }
  .nav-icon { width: 15px; text-align: center; font-size: 13px; flex-shrink: 0; }
  .nav-badge {
    margin-left: auto;
    background: var(--bg4); border: 1px solid var(--border);
    border-radius: 10px; font-family: 'JetBrains Mono', monospace;
    font-size: 9px; padding: 1px 6px; color: var(--text3);
  }
  .nav-item.active .nav-badge { background: rgba(0,217,163,.12); border-color: rgba(0,217,163,.25); color: var(--accent); }
  .sidebar-score {
    padding: 12px 14px; border-top: 1px solid var(--border); flex-shrink: 0;
    display: flex; align-items: center; gap: 12px;
  }
  .sidebar-score-num {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 28px; font-weight: 700; line-height: 1;
  }
  .sidebar-score-info { font-size: 10px; color: var(--text3); font-family: 'JetBrains Mono', monospace; line-height: 1.4; }
  .sidebar-score-info strong { display: block; font-size: 12px; font-weight: 700; }
  .sidebar-overlay {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,.65); z-index: 49;
  }

  /* ── TOPBAR ───────────────────────────────────────────────────────────── */
  .main {
    flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0;
  }
  .topbar {
    height: 50px; flex-shrink: 0;
    background: var(--bg2); border-bottom: 1px solid var(--border);
    display: flex; align-items: center;
    padding: 0 20px; gap: 10px;
  }
  .hamburger {
    display: none; flex-direction: column; gap: 4px;
    background: none; border: none; cursor: pointer; padding: 5px;
  }
  .hamburger span { display: block; width: 17px; height: 2px; background: var(--text2); border-radius: 2px; }
  .topbar-breadcrumb {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px; color: var(--text3);
    display: flex; align-items: center; gap: 6px;
  }
  .topbar-breadcrumb span { color: var(--text2); }
  .topbar-sep { color: var(--border2); }
  .topbar-actions { margin-left: auto; display: flex; align-items: center; gap: 8px; }
  .tb-chip {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 4px 10px; border-radius: 6px;
    font-size: 11px; font-family: 'JetBrains Mono', monospace; font-weight: 600;
    background: var(--bg3); border: 1px solid var(--border2); color: var(--text2);
  }
  .tb-chip.green { background: rgba(0,217,163,.1); border-color: rgba(0,217,163,.25); color: var(--accent); }
  .tb-chip.red   { background: rgba(244,63,94,.1);  border-color: rgba(244,63,94,.25);  color: var(--red); }
  .tb-chip.orange{ background: rgba(249,115,22,.1); border-color: rgba(249,115,22,.25); color: var(--orange); }
  .tb-chip.yellow{ background: rgba(234,179,8,.1);  border-color: rgba(234,179,8,.25);  color: var(--yellow); }

  /* ── CONTENT SCROLL AREA ──────────────────────────────────────────────── */
  .content {
    flex: 1; overflow-y: auto; overflow-x: hidden;
    scrollbar-width: thin; scrollbar-color: var(--border2) transparent;
  }
  .wrapper { max-width: 1200px; margin: 0 auto; padding: 24px 24px 40px; }

  /* matrix canvas in header */
  .header { position: relative; }
  .header-matrix-canvas {
    position: absolute; inset: 0; opacity: .06; pointer-events: none;
    border-radius: 12px; overflow: hidden;
  }
  .header-inner { position: relative; z-index: 1; }

  /* ── MOBILE RESPONSIVE ────────────────────────────────────────────────── */
  @media (max-width: 720px) {
    html, body { overflow: auto; height: auto; }
    .shell { height: auto; overflow: visible; flex-direction: column; }
    .sidebar {
      position: fixed; inset: 0 auto 0 0; z-index: 50;
      width: 260px; transform: translateX(-100%);
      transition: transform .22s;
    }
    .sidebar.open { transform: translateX(0); }
    .sidebar-overlay.open { display: block; }
    .hamburger { display: flex; }
    .main { height: 100vh; }
    .content { overflow-y: auto; }
    .wrapper { padding: 16px 14px 32px; }
  }
</style>
</head>
<body>
<div class="shell">

  <!-- ═══════════════════════════════ SIDEBAR ═══════════════════════════════ -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-logo">
      <div class="logo-mark">
        <div class="logo-icon">TR</div>
        <div class="logo-text">TripRecon<small>v3.0 · Bug Bounty</small></div>
      </div>
    </div>
    <div class="sidebar-domain-strip">
      <div class="sidebar-domain">
        <small>Target</small>
        {{ report.domain }}
      </div>
    </div>
    <nav class="sidebar-nav" id="sideNav">
      <div class="nav-group">
        <div class="nav-group-label">Overview</div>
        <div class="nav-item" onclick="scrollTo('sec-summary')">
          <span class="nav-icon">⚡</span> Overview
        </div>
        <div class="nav-item" onclick="scrollTo('sec-exec')">
          <span class="nav-icon">🎯</span> Risk Score
        </div>
        <div class="nav-item" onclick="scrollTo('sec-charts')">
          <span class="nav-icon">📊</span> Charts
        </div>
      </div>
      <div class="nav-group">
        <div class="nav-group-label">DNS &amp; Network</div>
        <div class="nav-item" onclick="scrollTo('sec-dns')">
          <span class="nav-icon">🌐</span> DNS Records
        </div>
        <div class="nav-item" onclick="scrollTo('sec-subs')">
          <span class="nav-icon">🔀</span> Subdomains
        </div>
        <div class="nav-item" onclick="scrollTo('sec-ports')">
          <span class="nav-icon">🔌</span> Open Ports
        </div>
      </div>
      <div class="nav-group">
        <div class="nav-group-label">Attack Surface</div>
        <div class="nav-item" onclick="scrollTo('sec-paths')">
          <span class="nav-icon">📂</span> Sensitive Paths
        </div>
        <div class="nav-item" onclick="scrollTo('sec-js')">
          <span class="nav-icon">📜</span> JS Analysis
        </div>
        <div class="nav-item" onclick="scrollTo('sec-dorks')">
          <span class="nav-icon">🔍</span> Google Dorks
        </div>
        <div class="nav-item" onclick="scrollTo('sec-leaks')">
          <span class="nav-icon">🚨</span> Leaked Creds
        </div>
      </div>
      <div class="nav-group">
        <div class="nav-group-label">Web Security</div>
        <div class="nav-item" onclick="scrollTo('sec-headers')">
          <span class="nav-icon">🛡</span> Security Headers
        </div>
        <div class="nav-item" onclick="scrollTo('sec-cors')">
          <span class="nav-icon">🔗</span> CORS Policy
        </div>
        <div class="nav-item" onclick="scrollTo('sec-waf')">
          <span class="nav-icon">🧱</span> WAF Detection
        </div>
        <div class="nav-item" onclick="scrollTo('sec-tech')">
          <span class="nav-icon">⚙</span> Technologies
        </div>
        <div class="nav-item" onclick="scrollTo('sec-email')">
          <span class="nav-icon">✉</span> Email Security
        </div>
      </div>
      <div class="nav-group">
        <div class="nav-group-label">Intelligence</div>
        <div class="nav-item" onclick="scrollTo('sec-shodan')">
          <span class="nav-icon">👁</span> Shodan
        </div>
        <div class="nav-item" onclick="scrollTo('sec-vt')">
          <span class="nav-icon">🦠</span> VirusTotal
        </div>
        <div class="nav-item" onclick="scrollTo('sec-wayback')">
          <span class="nav-icon">🕰</span> Wayback URLs
        </div>
        <div class="nav-item" onclick="scrollTo('sec-whois')">
          <span class="nav-icon">📋</span> WHOIS
        </div>
      </div>
    </nav>
    <div class="sidebar-score">
      <div class="sidebar-score-num score-{{ risk.grade }}">{{ risk.score }}</div>
      <div class="sidebar-score-info">
        <strong class="score-{{ risk.grade }}">Grade {{ risk.grade }}</strong>
        Risk Score
      </div>
    </div>
  </aside>

  <div class="sidebar-overlay" id="sideOverlay" onclick="closeSidebar()"></div>

  <!-- ═══════════════════════════════ MAIN ═══════════════════════════════ -->
  <div class="main">
    <!-- Topbar -->
    <div class="topbar">
      <button class="hamburger" onclick="openSidebar()" aria-label="Menu">
        <span></span><span></span><span></span>
      </button>
      <div class="topbar-breadcrumb">
        TripRecon
        <span class="topbar-sep">/</span>
        <span>{{ report.domain }}</span>
      </div>
      <div class="topbar-actions">
        <span class="tb-chip">{{ scan_date }}</span>
        {%- if risk.grade in ['A','B'] %}
        <span class="tb-chip green">Grade {{ risk.grade }} · {{ risk.score }}/100</span>
        {%- elif risk.grade == 'C' %}
        <span class="tb-chip yellow">Grade {{ risk.grade }} · {{ risk.score }}/100</span>
        {%- elif risk.grade == 'D' %}
        <span class="tb-chip orange">Grade {{ risk.grade }} · {{ risk.score }}/100</span>
        {%- else %}
        <span class="tb-chip red">Grade {{ risk.grade }} · {{ risk.score }}/100</span>
        {%- endif %}
        <button class="btn primary" onclick="window.print()">⎙ PDF</button>
      </div>
    </div>

    <!-- Scrollable content -->
    <div class="content" id="mainContent">
    <div class="wrapper">

  <!-- HEADER / COVER -->
  <div class="header" id="sec-summary">
    <canvas class="header-matrix-canvas" id="hdrCanvas"></canvas>
    <div class="header-accent-bar"></div>
    <div class="header-inner">
      <div>
        <div class="header-brand">
          <div class="header-logo">TR</div>
          <div class="header-brand-text">
            <span class="header-brand-name">TripRecon</span>
            <span class="header-brand-tag">Security Intelligence Report · v3.0</span>
          </div>
        </div>
        <h1>Attack Surface Report — <span class="domain-highlight">{{ report.domain }}</span></h1>
        <div class="subtitle">Domain Intelligence &amp; Vulnerability Assessment</div>
        <div class="header-meta-grid">
          <div class="header-meta-item">
            <span class="header-meta-label">Target IP</span>
            <span class="header-meta-val">{{ report.ip or "unresolved" }}</span>
          </div>
          <div class="header-meta-item">
            <span class="header-meta-label">Scan Date</span>
            <span class="header-meta-val">{{ scan_date }}</span>
          </div>
          <div class="header-meta-item">
            <span class="header-meta-label">ASN</span>
            <span class="header-meta-val accent">{{ (report.asn_info or {}).get('asn', '—') }}</span>
          </div>
          <div class="header-meta-item">
            <span class="header-meta-label">Country</span>
            <span class="header-meta-val">{{ (report.asn_info or {}).get('country', '—') }}</span>
          </div>
          <div class="header-meta-item">
            <span class="header-meta-label">Registrar</span>
            <span class="header-meta-val">{{ ((report.whois or {}).get('registrar') or '—')[:24] }}</span>
          </div>
        </div>
      </div>
      <div class="header-score-preview">
        <div class="preview-score score-{{ risk.grade }} score-{{ risk.grade }}-glow">{{ risk.score }}</div>
        <div class="preview-grade score-{{ risk.grade }}">Grade {{ risk.grade }}</div>
        <div class="preview-label">Risk Score</div>
      </div>
    </div>
  </div>

  <!-- TOOLBAR -->
  <div class="toolbar">
    <button class="btn" onclick="expandAll()">▾ Expand All</button>
    <button class="btn" onclick="collapseAll()">▸ Collapse All</button>
  </div>

  <!-- STATS CARDS -->
  {%- set _sp200 = (report.sensitive_paths or [])|selectattr('status', 'equalto', 200)|list|length %}
  {%- set _first_hdata = (report.security_headers or {}).values()|list|first %}
  {%- set _hcount = (_first_hdata.headers.values()|reject('equalto','MISSING')|list|length) if _first_hdata else 0 %}
  {%- set wb_count = (report.wayback_urls or [])|length %}
  {%- set dork_total = namespace(n=0, files=0) %}
  {%- for engine, dresults in (report.dork_results or {}).items() %}
    {%- for dork, hits in dresults.items() %}
      {%- if hits is iterable and hits is not string %}
        {%- for h in hits %}
          {%- if h is mapping %}
            {%- set dork_total.n = dork_total.n + 1 %}
            {%- if h.is_file %}{%- set dork_total.files = dork_total.files + 1 %}{%- endif %}
          {%- elif h is string %}
            {%- set dork_total.n = dork_total.n + 1 %}
          {%- endif %}
        {%- endfor %}
      {%- endif %}
    {%- endfor %}
  {%- endfor %}
  {%- set _vuln_tko = (report.subdomain_takeover or [])|selectattr('vulnerable')|list|length %}
  {%- set _js_secs  = (report.js_analysis or {}).get('secrets',[]) or [] %}
  {%- set _dmarc_ok = (report.email_security or {}).get('dmarc',{}).get('policy','') == 'reject' %}
  {%- set _spf_ok   = (report.email_security or {}).get('spf',{}).get('record','') %}
  {%- set _cors_n   = (report.cors_findings or [])|length %}
  {%- set _ports_n  = report.open_ports|length %}
  {%- set _leaks_n  = report.leaks|length %}
  {%- set _subs_n   = report.crtsh_subdomains|length + (report.hackertarget_subdomains or [])|length %}
  {%- set _asn_val  = (report.asn_info or {}).get('asn','—') %}
  <div class="stats-grid">
    <div class="stat-card">
      <span class="stat-icon">🔍</span>
      <div class="num">{{ _subs_n }}</div>
      <div class="stat-label">Subdomains</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🔌</span>
      <div class="num{{ ' danger' if _ports_n > 3 else '' }}">{{ _ports_n }}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🗂️</span>
      <div class="num{{ ' danger' if _sp200 > 0 else '' }}">{{ _sp200 }}</div>
      <div class="stat-label">Sensitive Paths</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🛡️</span>
      <div class="num{{ ' warn' if _hcount < 5 else '' }}">{{ _hcount }}/10</div>
      <div class="stat-label">Sec Headers</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">💧</span>
      <div class="num{{ ' danger' if _leaks_n > 0 else '' }}">{{ _leaks_n }}</div>
      <div class="stat-label">Leak Records</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🕰️</span>
      <div class="num">{{ wb_count }}</div>
      <div class="stat-label">Wayback URLs</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🔎</span>
      <div class="num{{ ' warn' if dork_total.n > 0 else '' }}">{{ dork_total.n }}</div>
      <div class="stat-label">Dork Hits{% if dork_total.files %} · {{ dork_total.files }} files{% endif %}</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🌐</span>
      <div class="num{{ ' danger' if _cors_n > 0 else '' }}">{{ _cors_n }}</div>
      <div class="stat-label">CORS Issues</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">⚡</span>
      <div class="num{{ ' danger' if _vuln_tko > 0 else '' }}">{{ _vuln_tko }}</div>
      <div class="stat-label">Takeover Vulns</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">📜</span>
      <div class="num{{ ' danger' if _js_secs|length > 0 else '' }}">{{ _js_secs|length }}</div>
      <div class="stat-label">JS Secrets</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">🗺️</span>
      <div class="num dim">{{ 'AS' ~ _asn_val if _asn_val != '—' else '—' }}</div>
      <div class="stat-label">ASN</div>
    </div>
    <div class="stat-card">
      <span class="stat-icon">✉️</span>
      <div class="num{{ ' ok' if _dmarc_ok and _spf_ok else ' danger' }}">{{ '✓' if _dmarc_ok and _spf_ok else '✗' }}</div>
      <div class="stat-label">Email Auth</div>
    </div>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="section-group-label">Executive Summary</div>
  <div class="section" id="sec-exec">
    <div class="section-header" onclick="toggleSection('sec-exec')">
      <div class="section-header-left">
        <div class="section-icon">⚡</div>
        <h2>Security Score &amp; Key Findings</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ risk.findings|length }} findings</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-exec">
  <div class="risk-row">
    <div class="score-card grade-{{ risk.grade }}">
      <div class="score-val score-{{ risk.grade }} score-{{ risk.grade }}-glow">{{ risk.score }}</div>
      <div class="score-grade-text score-{{ risk.grade }}">Grade {{ risk.grade }}</div>
      <div class="label">SECURITY SCORE</div>
      <div class="score-bar">
        <div class="score-bar-fill" id="scoreBar"
             style="width:{{ risk.score }}%;
                    background: {% if risk.score >= 80 %}var(--accent){% elif risk.score >= 60 %}#34d399{% elif risk.score >= 40 %}var(--yellow){% elif risk.score >= 20 %}var(--orange){% else %}var(--red){% endif %}">
        </div>
      </div>
      <div style="margin-top:14px;font-size:12px;color:var(--text3)">
        {{ risk.findings|length }} finding{{ 's' if risk.findings|length != 1 else '' }} total
      </div>
    </div>
    <div>
      {% if risk.findings %}
      <div class="findings-list">
        {% for f in risk.findings %}
        <div class="finding-item {{ f.severity }}">
          <div class="finding-badge-col">
            <span class="sev-badge large badge-{{ f.severity }}">{{ f.severity }}</span>
          </div>
          <div class="finding-body">
            <div class="title">{{ f.title }}</div>
            <div class="detail">{{ f.detail }}</div>
            {% if f.evidence %}<div class="detail-url">↳ {{ f.evidence[:150] }}</div>{% endif %}
          </div>
        </div>
        {% endfor %}
      </div>
      {% else %}
      <div style="color:var(--accent);padding:20px;font-size:14px;font-weight:500">✓ No significant security findings detected.</div>
      {% endif %}
    </div>
  </div>
  {% if risk.findings %}
  <div style="margin-top:18px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:var(--text3);font-family:'JetBrains Mono',monospace;margin-bottom:10px;">Attack Vectors & Recommendations</div>
    <div class="scroll-wrap">
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Finding</th><th>Attack Vector</th><th>Recommendation</th></tr></thead>
        <tbody>
          {% for f in risk.findings %}
          <tr>
            <td><span class="badge-{{ f.severity }} sev-badge">{{ f.severity|upper }}</span></td>
            <td style="font-weight:500;color:var(--text)">{{ f.title }}</td>
            <td class="impact-cell"><span>{{ f.detail }}</span></td>
            <td class="rec-cell">
              {%- if f.severity == 'critical' %}Immediate patch / takedown required
              {%- elif f.severity == 'high' %}Fix within 7 days — exploitable in bug bounty chain
              {%- elif f.severity == 'medium' %}Fix within 30 days — lower-impact but reportable
              {%- else %}Best practice — include in security hardening report
              {%- endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}
    </div>
  </div>

  <!-- CHARTS -->
  <div class="section" id="sec-charts">
    <div class="section-header" onclick="toggleSection('sec-charts')">
      <div class="section-header-left">
        <div class="section-icon">📊</div>
        <h2>Visual Summary</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-charts">
  <div class="charts-row">
    <div class="chart-box">
      <h4>Security Headers</h4>
      <canvas id="hdrsChart"></canvas>
    </div>
    <div class="chart-box">
      <h4>Open Ports</h4>
      <canvas id="portsChart"></canvas>
    </div>
    <div class="chart-box">
      <h4>Subdomain Sources</h4>
      <canvas id="subChart"></canvas>
    </div>
  </div>
    </div>
  </div>

  <!-- DNS -->
  <div class="section-group-label">DNS &amp; Network</div>
  <div class="section" id="sec-dns">
    <div class="section-header" onclick="toggleSection('sec-dns')">
      <div class="section-header-left">
        <div class="section-icon">🌐</div>
        <h2>DNS Records</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-dns">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Type</th><th>Records</th><th>Security Note</th></tr></thead>
          <tbody>
            {% for rtype, vals in report.dns_info.items() %}{% if vals %}
            <tr>
              <td><strong style="color:var(--accent2);font-family:'JetBrains Mono',monospace">{{ rtype }}</strong></td>
              <td style="word-break:break-all">{{ vals|join("<br>")|safe }}</td>
              <td class="impact-cell">
                {%- if rtype == 'A' or rtype == 'AAAA' %}Check if behind CDN; if direct IP exposed, WAF bypass possible
                {%- elif rtype == 'MX' %}Validate SPF/DMARC — prevents email spoofing &amp; phishing
                {%- elif rtype == 'NS' %}Verify registrar lock; expired delegation = subdomain takeover risk
                {%- elif rtype == 'TXT' %}May leak SPF, DMARC, site verification tokens, API keys
                {%- elif rtype == 'CNAME' %}Dangling CNAME → subdomain takeover if target service is unclaimed
                {%- elif rtype == 'SOA' %}Zone serial reveals update cadence; zone transfer (AXFR) check
                {%- elif rtype == 'SRV' %}Exposes internal service topology (VoIP, XMPP, internal apps)
                {%- elif rtype == 'CAA' %}Restricts which CAs can issue TLS certs — hardens against misissue
                {%- elif rtype == 'PTR' %}Reverse DNS — may expose hostnames of internal/staging infrastructure
                {%- elif rtype == 'DNSKEY' or rtype == 'DS' %}DNSSEC — validates zone integrity against cache poisoning
                {%- else %}—{%- endif %}
              </td>
            </tr>
            {% endif %}{% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- SUBDOMAINS -->
  <div class="section" id="sec-subs">
    <div class="section-header" onclick="toggleSection('sec-subs')">
      <div class="section-header-left">
        <div class="section-icon">🔍</div>
        <h2>Subdomains</h2>
      </div>
      <div class="section-header-right">
        <span class="count">crt.sh: {{ report.crtsh_subdomains|length }} · HT: {{ (report.hackertarget_subdomains or [])|length }} · ST: {{ (report.securitytrails.data or [])|length if report.securitytrails and not report.securitytrails.error else 0 }}</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-subs">
      <input class="filter-input" oninput="filterTable('subsTable', this.value)" placeholder="Filter subdomains...">
      <div class="scroll-wrap">
        <table class="data-table" id="subsTable">
          <thead><tr><th>Subdomain</th><th>IP</th><th>Source</th></tr></thead>
          <tbody>
            {% for s in report.crtsh_subdomains %}
            <tr><td>{{ s.subdomain }}</td><td>{{ s.ip }}</td><td>crt.sh</td></tr>
            {% endfor %}
            {% for s in (report.hackertarget_subdomains or []) %}
            <tr><td>{{ s.subdomain }}</td><td>{{ s.ip }}</td><td>HackerTarget</td></tr>
            {% endfor %}
            {% if report.securitytrails and not report.securitytrails.error %}
              {% for s in (report.securitytrails.data or []) %}
              <tr><td>{{ s.subdomain }}</td><td>{{ s.ip }}</td><td>SecurityTrails</td></tr>
              {% endfor %}
            {% endif %}
          </tbody>
        </table>
      </div>
      {% if report.crtsh_wildcards %}
      <p style="margin-top:12px;color:var(--yellow);font-size:11px">Wildcards: {{ report.crtsh_wildcards|join(", ") }}</p>
      {% endif %}
    </div>
  </div>

  <div class="section-group-label">Attack Surface</div>
  <!-- SENSITIVE PATHS -->
  {% if report.sensitive_paths %}
  <div class="section" id="sec-paths">
    <div class="section-header" onclick="toggleSection('sec-paths')">
      <div class="section-header-left">
        <div class="section-icon">🗂</div>
        <h2>Sensitive Paths</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ report.sensitive_paths|length }} found</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-paths">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Path</th><th>Status</th><th>Size</th><th>Severity</th></tr></thead>
          <tbody>
            {% for p in report.sensitive_paths %}
            <tr>
              <td><a href="{{ p.url }}" target="_blank" style="color:var(--blue)">{{ p.path }}</a></td>
              <td>{{ p.status }}</td>
              <td>{{ p.size }}B</td>
              <td><span class="sev-badge badge-{{ p.severity }}">{{ p.severity }}</span></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- SECURITY HEADERS -->
  <div class="section-group-label">Web Security</div>
  {% if report.security_headers %}
  <div class="section" id="sec-headers">
    <div class="section-header" onclick="toggleSection('sec-headers')">
      <div class="section-header-left">
        <div class="section-icon">🛡</div>
        <h2>Security Headers</h2>
      </div>
      <div class="section-header-right"><span class="arrow">▾</span></div>
    </div>
    <div class="section-body" id="body-sec-headers">
      {% for scheme, data in report.security_headers.items() %}
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
        <h4 style="color:var(--blue);text-transform:uppercase;margin:0;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1px">{{ scheme }}://{{ report.domain }}</h4>
        {% if data.server %}<span class="info-badge warn">⚠ Server: {{ data.server }}</span>{% endif %}
        {% if data.x_powered %}<span class="info-badge warn">⚠ X-Powered-By: {{ data.x_powered }}</span>{% endif %}
      </div>
      <div class="scroll-wrap" style="margin-bottom:16px">
        <table class="data-table">
          <thead><tr><th>Security Header</th><th>Status</th><th>Current Value</th><th>Recommended Value</th></tr></thead>
          <tbody>
            {% for h, v in data.headers.items() %}
            {%- set is_set = v != 'MISSING' %}
            <tr>
              <td><code style="color:var(--accent2);font-size:11.5px">{{ h }}</code></td>
              <td>
                {% if is_set %}<span class="status-badge status-ok">✓ SET</span>
                {% else %}<span class="status-badge status-bad">✗ MISSING</span>{% endif %}
              </td>
              <td style="font-size:11.5px;color:{% if not is_set %}var(--dim){% else %}var(--text){% endif %}">
                {% if is_set %}{{ v[:120] }}{% else %}<em style="opacity:.45">not configured</em>{% endif %}
              </td>
              <td class="rec-cell">
                {%- if h == 'Strict-Transport-Security' %}max-age=31536000; includeSubDomains; preload
                {%- elif h == 'Content-Security-Policy' %}default-src 'self'; script-src 'self'; object-src 'none'
                {%- elif h == 'X-Frame-Options' %}DENY
                {%- elif h == 'X-Content-Type-Options' %}nosniff
                {%- elif h == 'Referrer-Policy' %}strict-origin-when-cross-origin
                {%- elif h == 'Permissions-Policy' %}geolocation=(), microphone=(), camera=()
                {%- elif h == 'X-XSS-Protection' %}1; mode=block
                {%- elif h == 'Cache-Control' %}no-store, max-age=0
                {%- elif h == 'Cross-Origin-Opener-Policy' %}same-origin
                {%- elif h == 'Cross-Origin-Resource-Policy' %}same-origin
                {%- elif h == 'Cross-Origin-Embedder-Policy' %}require-corp
                {%- else %}—{%- endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- CORS -->
  {% if report.cors_findings %}
  <div class="section" id="sec-cors">
    <div class="section-header" onclick="toggleSection('sec-cors')">
      <div class="section-header-left">
        <div class="section-icon">🔓</div>
        <h2>CORS Misconfigurations</h2>
      </div>
      <div class="section-header-right">
        <span class="count" style="color:var(--critical)">{{ report.cors_findings|length }} issues</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-cors">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Test Origin</th><th>ACAO Header</th><th>Credentials</th><th>Severity</th><th>Attack Vector</th></tr></thead>
          <tbody>
            {% for c in report.cors_findings %}
            <tr>
              <td><code style="font-size:10px;word-break:break-all">{{ c.origin }}</code></td>
              <td><code style="font-size:10px;color:{% if c.acao == '*' %}var(--red){% else %}var(--accent){% endif %}">{{ c.acao }}</code></td>
              <td>
                {%- if c.acac == 'true' %}<span class="status-badge status-bad">✗ true</span>
                {%- else %}<span class="status-badge status-ok">false</span>{%- endif %}
              </td>
              <td><span class="sev-badge badge-{{ c.severity }}">{{ c.severity }}</span></td>
              <td class="impact-cell">
                {%- if c.acac == 'true' and c.severity in ['high','critical'] %}Cross-origin requests can read cookies/session tokens — full account takeover via malicious site
                {%- elif c.acao == '*' %}Wildcard allows any origin to read responses — data exfil risk
                {%- else %}Origin reflected — attacker controls origin, may access authenticated APIs
                {%- endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- WAF -->
  {% if report.waf_info %}
  <div class="section" id="sec-waf">
    <div class="section-header" onclick="toggleSection('sec-waf')">
      <div class="section-header-left">
        <div class="section-icon">🧱</div>
        <h2>WAF / CDN Detection</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-waf">
      {% if report.waf_info.detected %}
      <p>WAF detected: <span class="waf-badge">{{ report.waf_info.vendor }}</span></p>
      {% if report.waf_info.evidence %}
        <ul style="margin-top:10px;color:var(--dim);font-size:11px">
          {% for e in report.waf_info.evidence %}<li style="margin-bottom:4px">{{ e }}</li>{% endfor %}
        </ul>
      {% endif %}
      {% else %}
      <p style="color:var(--green)">✓ No WAF/CDN detected</p>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- TECHNOLOGIES -->
  {% if report.technologies %}
  <div class="section" id="sec-tech">
    <div class="section-header" onclick="toggleSection('sec-tech')">
      <div class="section-header-left">
        <div class="section-icon">⚙️</div>
        <h2>Technologies</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-tech">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Category</th><th>Detected</th></tr></thead>
          <tbody>
            {% for cat, vals in report.technologies.items() %}{% if vals %}
            <tr><td>{{ cat|title }}</td><td>{{ vals|join(", ") }}</td></tr>
            {% endif %}{% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- OPEN PORTS -->
  {% if report.open_ports %}
  <div class="section" id="sec-ports">
    <div class="section-header" onclick="toggleSection('sec-ports')">
      <div class="section-header-left">
        <div class="section-icon">🔌</div>
        <h2>Open Ports</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ report.open_ports|length }} open</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-ports">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Attack Surface Note</th></tr></thead>
          <tbody>
            {% for p in report.open_ports %}
            {%- set pn = p.port|string %}
            <tr>
              <td><strong style="color:var(--accent2);font-family:'JetBrains Mono',monospace">{{ p.port }}</strong></td>
              <td>{{ p.service }}</td>
              <td><span class="sev-badge badge-{{ p.severity }}">{{ p.severity }}</span></td>
              <td class="impact-cell">
                {%- if pn == '21' %}FTP — unencrypted transfer; check anonymous login, brute-force
                {%- elif pn == '22' %}SSH — check for outdated OpenSSH CVEs; brute-force / key auth only
                {%- elif pn == '23' %}Telnet — cleartext credentials; CRITICAL — disable immediately
                {%- elif pn in ['25','465','587'] %}SMTP — test open relay; email spoofing vector
                {%- elif pn == '53' %}DNS — check for zone transfer (AXFR) and DNS amplification
                {%- elif pn == '80' %}HTTP — check redirect to HTTPS; enumerate endpoints, methods
                {%- elif pn == '443' %}HTTPS — audit TLS version, cipher suites, certificate validity
                {%- elif pn == '445' %}SMB — EternalBlue risk; should never be internet-facing
                {%- elif pn == '3306' %}MySQL — DB exposed publicly; check for auth bypass, empty password
                {%- elif pn == '5432' %}PostgreSQL — DB exposed publicly; check for default credentials
                {%- elif pn == '6379' %}Redis — unauthenticated access common; RCE via config write
                {%- elif pn == '27017' %}MongoDB — check for unauthenticated access; data exfiltration risk
                {%- elif pn in ['8080','8443','8888','8000','8001'] %}Alt HTTP/S — may expose admin panels, dev servers, or staging env
                {%- elif pn == '3389' %}RDP — brute-force target; check BlueKeep (CVE-2019-0708)
                {%- elif pn in ['9200','9300'] %}Elasticsearch — unauthenticated read/write common; critical data exposure
                {%- elif pn == '9200' %}Elasticsearch — check auth; unauthenticated access = full data dump
                {%- elif pn == '11211' %}Memcached — UDP amplification DDoS; may leak cached data
                {%- elif pn == '2181' %}Zookeeper — config exposure; no auth in default setup
                {%- elif pn in ['4444','5555','9001','9050'] %}Suspicious — potential C2, proxy, or reverse shell port
                {%- else %}Identify service banner; check for known CVEs on Shodan/NVD{%- endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <div class="section-group-label">Intelligence Sources</div>
  <!-- SHODAN -->
  {% if report.shodan_info and not report.shodan_info.error %}
  <div class="section" id="sec-shodan">
    <div class="section-header" onclick="toggleSection('sec-shodan')">
      <div class="section-header-left">
        <div class="section-icon">📡</div>
        <h2>Shodan</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-shodan">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Field</th><th>Value</th><th>Security Note</th></tr></thead>
          <tbody>
            <tr>
              <td>Organization</td>
              <td>{{ report.shodan_info.org }}</td>
              <td class="impact-cell">Hosting provider / company — use for pivot to related assets</td>
            </tr>
            <tr>
              <td>Country</td>
              <td>{{ report.shodan_info.country }}</td>
              <td class="impact-cell">Jurisdiction affects applicable data regulations and legal context</td>
            </tr>
            <tr>
              <td>Open Ports (Shodan)</td>
              <td><code style="font-size:11px">{{ (report.shodan_info.ports or [])|join(", ") }}</code></td>
              <td class="impact-cell">
                {%- set pc = (report.shodan_info.ports or [])|length %}
                {%- if pc > 6 %}<span style="color:var(--red)">⚠ {{ pc }} ports exposed — high attack surface</span>
                {%- elif pc > 3 %}<span style="color:var(--orange)">⚠ Moderate exposure — review each service banner</span>
                {%- else %}<span style="color:var(--accent)">Minimal internet-facing services</span>{%- endif %}
              </td>
            </tr>
            {% if (report.shodan_info.hostnames or []) %}
            <tr>
              <td>Hostnames</td>
              <td style="word-break:break-all">{{ report.shodan_info.hostnames|join(", ") }}</td>
              <td class="impact-cell">Additional hostnames on same IP — potential pivot to other services or staging environments</td>
            </tr>
            {% endif %}
            {% if report.shodan_info.isp %}
            <tr>
              <td>ISP</td>
              <td>{{ report.shodan_info.isp }}</td>
              <td class="impact-cell">Internet service provider — use for BGP-level reconnaissance</td>
            </tr>
            {% endif %}
            {% if report.shodan_info.asn %}
            <tr>
              <td>ASN</td>
              <td><a href="https://www.shodan.io/search?query=asn%3A{{ report.shodan_info.asn }}" target="_blank" style="color:var(--accent2)">{{ report.shodan_info.asn }}</a></td>
              <td class="impact-cell">Click to search all Shodan results for this ASN — enumerate sibling assets</td>
            </tr>
            {% endif %}
            {% if report.shodan_info.vulns %}
            <tr>
              <td><span style="color:var(--red);font-weight:700">🚨 CVEs</span></td>
              <td>
                {% for cve in report.shodan_info.vulns %}
                <a href="https://nvd.nist.gov/vuln/detail/{{ cve }}" target="_blank" style="color:var(--red);font-weight:600;margin-right:8px">{{ cve }}</a>
                {% endfor %}
              </td>
              <td class="impact-cell"><span style="color:var(--red)">CRITICAL — publicly known vulnerabilities indexed by Shodan on this IP</span></td>
            </tr>
            {% endif %}
            {% if report.shodan_info.tags %}
            <tr>
              <td>Tags</td>
              <td>{{ report.shodan_info.tags|join(", ") }}</td>
              <td class="impact-cell">Shodan behavioral tags (self-signed, honeypot, cloud, vpn, etc.)</td>
            </tr>
            {% endif %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- WAYBACK MACHINE -->
  {% if report.wayback_urls %}
  <div class="section" id="sec-wayback">
    <div class="section-header" onclick="toggleSection('sec-wayback')">
      <div class="section-header-left">
        <div class="section-icon">🕰</div>
        <h2>Wayback Machine URLs</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ report.wayback_urls|length }} archived URLs</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-wayback">
      <input class="filter-input" oninput="filterTable('waybackTable', this.value)" placeholder="Filter URLs (e.g. .php, /api, .js, .bak, admin)...">
      <div class="scroll-wrap">
        <table class="data-table" id="waybackTable">
          <thead><tr><th>URL</th><th>Type / Risk Signal</th></tr></thead>
          <tbody>
            {% for u in report.wayback_urls %}
            {%- set url_lower = u|lower %}
            {%- set risk_label = '' %}
            {%- set risk_class = '' %}
            {%- if '.sql' in url_lower or '.bak' in url_lower or '.backup' in url_lower %}{%- set risk_label = '💣 Backup/DB file' %}{%- set risk_class = 'status-bad' %}
            {%- elif '.env' in url_lower or 'config' in url_lower %}{%- set risk_label = '🔑 Config/Env file' %}{%- set risk_class = 'status-bad' %}
            {%- elif '/admin' in url_lower or '/manage' in url_lower or '/dashboard' in url_lower %}{%- set risk_label = '🔐 Admin panel' %}{%- set risk_class = 'status-warn' %}
            {%- elif '/api/' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower %}{%- set risk_label = '⚡ API endpoint' %}{%- set risk_class = 'status-warn' %}
            {%- elif '.php' in url_lower %}{%- set risk_label = '📄 PHP endpoint' %}{%- set risk_class = 'status-info' %}
            {%- elif '.zip' in url_lower or '.tar' in url_lower or '.gz' in url_lower %}{%- set risk_label = '📦 Archive file' %}{%- set risk_class = 'status-bad' %}
            {%- elif '.log' in url_lower %}{%- set risk_label = '📋 Log file' %}{%- set risk_class = 'status-warn' %}
            {%- elif '.js' in url_lower %}{%- set risk_label = 'JS file' %}{%- set risk_class = 'status-info' %}
            {%- else %}{%- set risk_label = 'URL' %}{%- set risk_class = '' %}{%- endif %}
            <tr>
              <td class="url"><a href="{{ u }}" target="_blank" rel="noopener">{{ u }}</a></td>
              <td>{% if risk_class %}<span class="status-badge {{ risk_class }}">{{ risk_label }}</span>{% else %}<span style="color:var(--text3);font-size:11px">{{ risk_label }}</span>{% endif %}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- DORK RESULTS -->
  {% if report.dork_results %}
  <div class="section" id="sec-dorks">
    <div class="section-header" onclick="toggleSection('sec-dorks')">
      <div class="section-header-left">
        <div class="section-icon">🔎</div>
        <h2>Dork Results</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-dorks">

      <div style="margin-bottom:12px;padding:8px 12px;background:rgba(255,210,0,.08);border-left:3px solid var(--yellow);border-radius:4px;font-size:12px;color:var(--yellow)">
        ⚠ URLs below are collected from search-engine results only — <strong>no files are downloaded</strong>.
        File badges (PDF, SQL, ZIP…) indicate what the URL points to.
        Open manually to inspect.
      </div>

      {% for engine, dresults in report.dork_results.items() %}
      <div class="dork-engine" style="margin-bottom:16px">
        <div class="dork-engine-title" onclick="this.nextElementSibling.classList.toggle('hidden')"
             style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--bg2);border-radius:6px;cursor:pointer;user-select:none">
          <span style="font-weight:700;letter-spacing:.5px">{{ engine|upper }}</span>
          <span style="color:var(--dim);font-size:12px">
            {% set total = namespace(n=0, files=0) %}
            {% for dork, hits in dresults.items() %}
              {% if hits is iterable and hits is not string %}
                {% for h in hits %}
                  {% if h is mapping %}
                    {% set total.n = total.n + 1 %}
                    {% if h.is_file %}{% set total.files = total.files + 1 %}{% endif %}
                  {% endif %}
                {% endfor %}
              {% endif %}
            {% endfor %}
            {{ total.n }} URLs &nbsp;·&nbsp;
            <span style="color:var(--yellow)">{{ total.files }} files</span>
          </span>
        </div>

        <div class="dork-items" style="padding:4px 0 4px 8px">
          {% for dork, hits in dresults.items() %}
            {% if not dork.startswith('_') %}
            <div class="dork-query" style="margin:10px 0 4px;font-size:12px;color:var(--blue);font-family:monospace">
              🔍 {{ dork }}
            </div>

            {% if hits is iterable and hits is not string and hits|length > 0 %}
              {% for h in hits %}
                {% if h is mapping %}
                <div class="dork-url" style="display:flex;align-items:center;gap:8px;padding:3px 6px;border-radius:3px;margin:2px 0">
                  {% if h.is_file %}
                  <span style="background:var(--yellow);color:#000;font-size:10px;font-weight:700;padding:1px 5px;border-radius:3px;white-space:nowrap;flex-shrink:0">
                    {{ h.file_type }}
                  </span>
                  {% else %}
                  <span style="background:var(--bg3);color:var(--dim);font-size:10px;padding:1px 5px;border-radius:3px;white-space:nowrap;flex-shrink:0">URL</span>
                  {% endif %}
                  <a href="{{ h.url }}" target="_blank" rel="noopener noreferrer"
                     style="color:{% if h.is_file %}var(--yellow){% else %}var(--blue){% endif %};font-size:12px;word-break:break-all;text-decoration:none"
                     title="{{ h.url }}">{{ h.url }}</a>
                </div>
                {% elif h is string %}
                {# fallback for legacy string entries #}
                <div class="dork-url" style="padding:3px 6px;font-size:12px">
                  <a href="{{ h }}" target="_blank" style="color:var(--blue);word-break:break-all">{{ h }}</a>
                </div>
                {% endif %}
              {% endfor %}
            {% else %}
            <div style="padding-left:8px;color:var(--dim);font-size:12px;font-style:italic">no results</div>
            {% endif %}
            {% endif %}
          {% endfor %}
        </div>
      </div>
      {% endfor %}

    </div>
  </div>
  {% endif %}

  <div class="section-group-label">Leaks &amp; Exposure</div>
  <!-- DATA LEAKS -->
  {% if report.leaks %}
  <div class="section" id="sec-leaks">
    <div class="section-header" onclick="toggleSection('sec-leaks')">
      <div class="section-header-left">
        <div class="section-icon">💧</div>
        <h2 style="color:var(--red)">Data Leaks</h2>
      </div>
      <div class="section-header-right">
        <span class="count" style="color:var(--red)">{{ report.leaks|length }} records</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-leaks">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Leak Record</th></tr></thead>
          <tbody>
            {% for l in report.leaks %}
            <tr><td>{{ l }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- VIRUSTOTAL -->
  {% if report.virustotal and not report.virustotal.error %}
  <div class="section" id="sec-vt">
    <div class="section-header" onclick="toggleSection('sec-vt')">
      <div class="section-header-left">
        <div class="section-icon">🦠</div>
        <h2>VirusTotal</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-vt">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Check</th><th>Result</th><th>Security Note</th></tr></thead>
          <tbody>
            <tr>
              <td><strong>Reputation Score</strong></td>
              <td>
                {%- set rep = report.virustotal.reputation|int %}
                {%- if rep >= 0 %}<span class="status-badge status-ok">{{ rep }} (clean)</span>
                {%- elif rep >= -10 %}<span class="status-badge status-warn">{{ rep }}</span>
                {%- else %}<span class="status-badge status-bad">{{ rep }} (flagged)</span>{%- endif %}
              </td>
              <td class="impact-cell">Negative score = vendor detections; low scores suggest past malicious activity or hosting</td>
            </tr>
            <tr>
              <td><strong>Malicious Votes</strong></td>
              <td>
                {%- if report.virustotal.malicious > 0 %}<span class="status-badge status-bad">{{ report.virustotal.malicious }} vendors</span>
                {%- else %}<span class="status-badge status-ok">0 detections</span>{%- endif %}
              </td>
              <td class="impact-cell">Number of security vendors flagging this domain as malicious or phishing</td>
            </tr>
            <tr>
              <td>Registrar</td>
              <td><code style="font-size:11px">{{ report.virustotal.registrar or '—' }}</code></td>
              <td class="impact-cell">Registrar identity; some registrars are associated with bulletproof hosting</td>
            </tr>
            <tr>
              <td>Categories</td>
              <td style="font-size:11px">{{ report.virustotal.categories.values()|join(", ") if report.virustotal.categories else '—' }}</td>
              <td class="impact-cell">Content classification across security vendors</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- URLSCAN -->
  {% if report.urlscan_results %}
  <div class="section" id="sec-urlscan">
    <div class="section-header" onclick="toggleSection('sec-urlscan')">
      <div class="section-header-left">
        <div class="section-icon">🌍</div>
        <h2>URLScan.io</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ report.urlscan_results|length }} scans</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-urlscan">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>URL</th><th>IP</th><th>Country</th><th>Server</th></tr></thead>
          <tbody>
            {% for r in report.urlscan_results %}
            <tr>
              <td class="url"><a href="{{ r.url }}" target="_blank">{{ r.url[:80] }}</a></td>
              <td>{{ r.ip }}</td>
              <td>{{ r.country }}</td>
              <td>{{ r.server }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <div class="section-group-label">Domain Intelligence</div>
  <!-- ASN / BGP -->
  {% if report.asn_info and not report.asn_info.error %}
  <div class="section" id="sec-asn">
    <div class="section-header" onclick="toggleSection('sec-asn')">
      <div class="section-header-left">
        <div class="section-icon">🗺</div>
        <h2>ASN / BGP Intelligence</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ (report.asn_info.prefixes or [])|length }} prefixes</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-asn">
      <table class="data-table">
        <tbody>
          <tr><td>ASN</td><td><strong style="color:var(--green)">{{ report.asn_info.asn }}</strong></td></tr>
          <tr><td>Organisation</td><td>{{ report.asn_info.asn_name }}</td></tr>
          <tr><td>Country</td><td>{{ report.asn_info.country }}</td></tr>
          <tr><td>IPv4 Prefixes</td><td>{{ (report.asn_info.prefixes or [])|selectattr('type','equalto','IPv4')|list|length }}</td></tr>
          <tr><td>IPv6 Prefixes</td><td>{{ (report.asn_info.prefixes or [])|selectattr('type','equalto','IPv6')|list|length }}</td></tr>
          <tr><td>Shodan Pivot</td><td><a href="https://www.shodan.io/search?query=asn%3A{{ report.asn_info.asn }}" target="_blank" class="url">shodan.io → ASN:{{ report.asn_info.asn }}</a></td></tr>
        </tbody>
      </table>
      {% if report.asn_info.prefixes %}
      <h3 style="margin:1rem 0 .5rem;color:var(--blue)">IP Ranges (Attack Surface)</h3>
      <div class="scroll-wrap">
        <table class="data-table" id="prefixTable">
          <thead><tr><th>Prefix</th><th>Type</th><th>Name</th><th>Country</th><th>Shodan</th></tr></thead>
          <tbody>
            {% for px in report.asn_info.prefixes %}
            <tr>
              <td><code>{{ px.prefix }}</code></td>
              <td>{{ px.type }}</td>
              <td>{{ px.name }}</td>
              <td>{{ px.country }}</td>
              <td><a href="https://www.shodan.io/search?query=net%3A{{ px.prefix }}" target="_blank" class="url">Scan ↗</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- WHOIS / RDAP -->
  {% if report.whois and not report.whois.error %}
  <div class="section" id="sec-whois">
    <div class="section-header" onclick="toggleSection('sec-whois')">
      <div class="section-header-left">
        <div class="section-icon">📋</div>
        <h2>WHOIS / RDAP</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-whois">
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Field</th><th>Value</th><th>Security Note</th></tr></thead>
          <tbody>
            <tr>
              <td>Registrar</td>
              <td>{{ report.whois.registrar or '—' }}</td>
              <td class="impact-cell">Some registrars offer weak hijack protection — verify registrar lock is enabled</td>
            </tr>
            <tr>
              <td>Created</td>
              <td>{{ report.whois.created or '—' }}</td>
              <td class="impact-cell">Very new domains may indicate a spun-up phishing or shadow domain</td>
            </tr>
            <tr>
              <td><strong>Expires</strong></td>
              <td>{{ report.whois.expires or '—' }}</td>
              <td class="impact-cell">⚠ If expiry is soon, domain takeover is possible if registration lapses</td>
            </tr>
            <tr>
              <td>Updated</td>
              <td>{{ report.whois.updated or '—' }}</td>
              <td class="impact-cell">Recent updates may indicate nameserver or registrant changes worth investigating</td>
            </tr>
            <tr>
              <td>Status</td>
              <td>
                {% for s in (report.whois.status or []) %}
                <span class="info-badge" style="margin:1px 2px;display:inline-block">{{ s }}</span>
                {% endfor %}
              </td>
              <td class="impact-cell"><code>clientTransferProhibited</code> = good; missing lock = transfer hijack risk</td>
            </tr>
            <tr>
              <td>Nameservers</td>
              <td><code style="font-size:10.5px">{{ (report.whois.nameservers or [])|join('<br>')|safe }}</code></td>
              <td class="impact-cell">Shared/third-party nameservers — check for subdomain takeover or dangling NS records</td>
            </tr>
            <tr>
              <td>Registrant</td>
              <td style="font-size:11.5px">{{ report.whois.registrant_name or '' }} {{ report.whois.registrant_email or '' }}</td>
              <td class="impact-cell">Exposed registrant email is a target for spear phishing &amp; social engineering</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- FAVICON HASH -->
  {% if report.favicon and report.favicon.hash %}
  <div class="section" id="sec-favicon">
    <div class="section-header" onclick="toggleSection('sec-favicon')">
      <div class="section-header-left">
        <div class="section-icon">🖼</div>
        <h2>Favicon Hash (Shodan Pivot)</h2>
      </div>
      <div class="section-header-right">
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-favicon">
      <table class="data-table">
        <tbody>
          <tr><td>MurmurHash3</td><td><code style="color:var(--yellow)">{{ report.favicon.hash }}</code></td></tr>
          <tr><td>Source URL</td><td><a href="{{ report.favicon.url }}" target="_blank" class="url">{{ report.favicon.url }}</a></td></tr>
          <tr><td>Shodan Query</td><td><code>http.favicon.hash:{{ report.favicon.hash }}</code></td></tr>
          <tr><td>Shodan Pivot</td><td><a href="{{ report.favicon.shodan_url }}" target="_blank" class="url">Search identical servers on Shodan ↗</a></td></tr>
        </tbody>
      </table>
      <p style="margin-top:.8rem;font-size:11px;color:var(--dim)">💡 Servers sharing this favicon fingerprint may be additional assets of the same target (staging, admin panels, CDN origins).</p>
    </div>
  </div>
  {% endif %}

  <!-- EMAIL SECURITY -->
  {% if report.email_security %}
  <div class="section" id="sec-email">
    <div class="section-header" onclick="toggleSection('sec-email')">
      <div class="section-header-left">
        <div class="section-icon">✉️</div>
        <h2>Email Security (SPF / DMARC / DKIM)</h2>
      </div>
      {% set _em = report.email_security %}
      {% set _issues = [] %}
      {% if not _em.spf.record %}{% set _ = _issues.append('No SPF') %}{% endif %}
      {% if not _em.dmarc.record %}{% set _ = _issues.append('No DMARC') %}{% endif %}
      {% if not _em.dkim_selectors %}{% set _ = _issues.append('DKIM ?') %}{% endif %}
      <div class="section-header-right">
        <span class="count" style="color:{% if _issues %}var(--red){% else %}var(--green){% endif %}">{{ _issues|join(' · ') if _issues else '✓ Configured' }}</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-email">
      {% set em = report.email_security %}

      <!-- Unified summary table -->
      <div class="scroll-wrap" style="margin-bottom:16px">
        <table class="data-table">
          <thead><tr><th>Check</th><th>Status</th><th>Current Value</th><th>Recommended</th><th>Risk if Missing</th></tr></thead>
          <tbody>
            <!-- SPF -->
            {%- set spf_ok = em.spf and em.spf.record %}
            {%- set spf_strict = em.spf and em.spf.all_qualifier == '-' %}
            <tr>
              <td><strong>SPF Record</strong></td>
              <td>{% if spf_ok %}<span class="status-badge status-ok">✓ SET</span>{% else %}<span class="status-badge status-bad">✗ MISSING</span>{% endif %}</td>
              <td><code style="font-size:10px;word-break:break-all">{{ (em.spf.record or '—')[:120] }}</code></td>
              <td class="rec-cell">v=spf1 include:_spf.yourmailprovider.com -all</td>
              <td class="impact-cell">Anyone can send email as @{{ report.domain }} — phishing &amp; BEC attacks</td>
            </tr>
            <!-- SPF all qualifier -->
            <tr>
              <td>SPF <code>all</code> qualifier</td>
              <td>
                {%- set q = em.spf.all_qualifier if em.spf else '' %}
                {%- if q == '-' %}<span class="status-badge status-ok">-all (strict)</span>
                {%- elif q == '~' %}<span class="status-badge status-warn">~all (soft fail)</span>
                {%- elif q in ['+','?',''] %}<span class="status-badge status-bad">{{ q or 'none' }} (permissive)</span>
                {%- else %}<span class="status-badge status-info">{{ q }}</span>{%- endif %}
              </td>
              <td><code>{{ em.spf.all_qualifier if em.spf else '—' }}</code></td>
              <td class="rec-cell">-all</td>
              <td class="impact-cell"><code>~all</code> = soft fail (not enforced); <code>+all</code> = anyone can send</td>
            </tr>
            <!-- SPF mechanisms -->
            {% if em.spf and em.spf.mechanisms %}
            <tr>
              <td>SPF Mechanisms</td>
              <td><span class="status-badge status-info">INFO</span></td>
              <td style="font-size:11px">{{ em.spf.mechanisms|join(', ') }}</td>
              <td class="rec-cell">Limit to authorized senders only</td>
              <td class="impact-cell">Excess <code>include:</code> entries expand attack surface</td>
            </tr>
            {% endif %}
            <!-- DMARC -->
            {%- set dmarc_ok = em.dmarc and em.dmarc.record %}
            {%- set dmarc_policy = em.dmarc.policy if em.dmarc else '' %}
            <tr>
              <td><strong>DMARC Record</strong></td>
              <td>{% if dmarc_ok %}<span class="status-badge status-ok">✓ SET</span>{% else %}<span class="status-badge status-bad">✗ MISSING</span>{% endif %}</td>
              <td><code style="font-size:10px;word-break:break-all">{{ (em.dmarc.record or '—')[:120] }}</code></td>
              <td class="rec-cell">v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{{ report.domain }}</td>
              <td class="impact-cell">Without DMARC, SPF/DKIM failures are not enforced — phishing succeeds</td>
            </tr>
            <!-- DMARC policy -->
            <tr>
              <td>DMARC Policy (<code>p=</code>)</td>
              <td>
                {%- if dmarc_policy == 'reject' %}<span class="status-badge status-ok">reject ✓</span>
                {%- elif dmarc_policy == 'quarantine' %}<span class="status-badge status-warn">quarantine</span>
                {%- elif dmarc_policy == 'none' %}<span class="status-badge status-bad">none (monitor only)</span>
                {%- else %}<span class="status-badge status-bad">{{ dmarc_policy or 'MISSING' }}</span>{%- endif %}
              </td>
              <td><code>{{ dmarc_policy or '—' }}</code></td>
              <td class="rec-cell">reject</td>
              <td class="impact-cell"><code>none</code> = monitoring only, spoofed emails still delivered</td>
            </tr>
            <!-- DMARC pct -->
            {% if em.dmarc and em.dmarc.pct is not none %}
            <tr>
              <td>DMARC <code>pct=</code></td>
              <td>
                {%- if em.dmarc.pct|int == 100 %}<span class="status-badge status-ok">100%</span>
                {%- else %}<span class="status-badge status-warn">{{ em.dmarc.pct }}%</span>{%- endif %}
              </td>
              <td><code>{{ em.dmarc.pct }}%</code></td>
              <td class="rec-cell">pct=100</td>
              <td class="impact-cell">Low % = policy only applied to a fraction of failing emails</td>
            </tr>
            {% endif %}
            <!-- DKIM -->
            {%- set dkim_count = (em.dkim_selectors or {})|length %}
            <tr>
              <td><strong>DKIM Selectors</strong></td>
              <td>{% if dkim_count > 0 %}<span class="status-badge status-ok">{{ dkim_count }} found</span>{% else %}<span class="status-badge status-warn">? Unknown</span>{% endif %}</td>
              <td style="font-size:11px">{% if dkim_count %}{{ (em.dkim_selectors or {}).keys()|join(', ') }}{% else %}—{% endif %}</td>
              <td class="rec-cell">default, google, sendgrid…</td>
              <td class="impact-cell">DKIM signs outgoing mail; absence weakens DMARC alignment</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- DKIM selector detail -->
      {% if em.dkim_selectors %}
      <h4 style="color:var(--blue);font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;font-family:'JetBrains Mono',monospace">DKIM Selector Records</h4>
      <div class="scroll-wrap">
        <table class="data-table">
          <thead><tr><th>Selector</th><th>TXT Record</th></tr></thead>
          <tbody>
            {% for sel, rec in em.dkim_selectors.items() %}
            <tr>
              <td><code style="color:var(--accent)">{{ sel }}._domainkey</code></td>
              <td style="font-size:10px;word-break:break-all;color:var(--text2)">{{ rec[:200] }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- JS ANALYSIS -->
  {% if report.js_analysis and (report.js_analysis.endpoints or report.js_analysis.secrets) %}
  <div class="section" id="sec-js">
    <div class="section-header" onclick="toggleSection('sec-js')">
      <div class="section-header-left">
        <div class="section-icon">📜</div>
        <h2>JavaScript Analysis</h2>
      </div>
      <div class="section-header-right">
        <span class="count" style="{% if report.js_analysis.secrets %}color:var(--critical){% endif %}">
          {{ (report.js_analysis.endpoints or [])|length }} endpoints
          {% if report.js_analysis.secrets %}· ⚠ {{ report.js_analysis.secrets|length }} SECRETS{% endif %}
        </span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-js">
      {% if report.js_analysis.secrets %}
      <div style="background:rgba(255,34,85,.12);border:1px solid var(--critical);border-radius:6px;padding:1rem;margin-bottom:1rem">
        <strong style="color:var(--critical)">🚨 SECRETS FOUND IN JAVASCRIPT FILES</strong>
        <table class="data-table" style="margin-top:.5rem">
          <thead><tr><th>Type</th><th>Match (truncated)</th><th>File</th></tr></thead>
          <tbody>
            {% for s in report.js_analysis.secrets %}
            <tr>
              <td><span class="sev-badge sev-CRITICAL">{{ s.type or '?' }}</span></td>
              <td><code style="color:var(--red)">{{ (s.match or '')[:60] }}…</code></td>
              <td class="url"><a href="{{ s.url or s.js_url or '#' }}" target="_blank">{{ (s.url or s.js_url or '')[-60:] }}</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endif %}
      {% if report.js_analysis.endpoints %}
      <input class="filter-input" oninput="filterTable('jsEndpointTable', this.value)" placeholder="Filter endpoints...">
      <div class="scroll-wrap">
        <table class="data-table" id="jsEndpointTable">
          <thead><tr><th>Endpoint</th><th>Source JS</th></tr></thead>
          <tbody>
            {% for ep in report.js_analysis.endpoints %}
            <tr>
              {%- if ep is mapping %}
              <td class="url">{{ ep.endpoint }}</td>
              <td class="url" style="font-size:10px"><a href="{{ ep.source }}" target="_blank">{{ ep.source[-60:] }}</a></td>
              {%- else %}
              <td class="url" colspan="2">{{ ep }}</td>
              {%- endif %}
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- WAYBACK PARAMS -->
  {% if report.wayback_params %}
  <div class="section" id="sec-wbparams">
    <div class="section-header" onclick="toggleSection('sec-wbparams')">
      <div class="section-header-left">
        <div class="section-icon">🎯</div>
        <h2>Wayback GET Parameters (Fuzzing Targets)</h2>
      </div>
      <div class="section-header-right">
        <span class="count">{{ report.wayback_params|length }} unique params</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-wbparams">
      <p style="font-size:11px;color:var(--dim);margin-bottom:.8rem">Parameters mined from {{ (report.wayback_urls or [])|length }} archived URLs — potential injection points for SQLi, XSS, SSRF, Open Redirect.</p>
      <input class="filter-input" oninput="filterTable('wbParamsTable', this.value)" placeholder="Filter parameters...">
      <div class="scroll-wrap">
        <table class="data-table" id="wbParamsTable">
          <thead><tr><th>Parameter</th><th>Seen In URLs</th><th>Example Values</th></tr></thead>
          <tbody>
            {% for param, info in (report.wayback_params or {}).items() %}
            {%- if info is mapping %}
            <tr>
              <td><code style="color:var(--yellow)">{{ param }}</code></td>
              <td>{{ info.get('count', 0) }}</td>
              <td style="font-size:10px;color:var(--dim)">{{ (info.get('values') or [])|join(', ') }}</td>
            </tr>
            {%- elif info is iterable and info is not string %}
            <tr>
              <td><code style="color:var(--yellow)">{{ param }}</code></td>
              <td>{{ info|length }}</td>
              <td style="font-size:10px;color:var(--dim)">{{ info[:5]|join(', ') }}</td>
            </tr>
            {%- endif %}
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- SUBDOMAIN TAKEOVER -->
  {% set vuln_takeovers = (report.subdomain_takeover or [])|selectattr('vulnerable')|list %}
  {% if vuln_takeovers %}
  <div class="section" id="sec-takeover">
    <div class="section-header" onclick="toggleSection('sec-takeover')">
      <div class="section-header-left">
        <div class="section-icon">⚡</div>
        <h2>Subdomain Takeover</h2>
      </div>
      <div class="section-header-right">
        <span class="count" style="color:var(--critical)">⚠ {{ vuln_takeovers|length }} VULNERABLE</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-takeover">
      <table class="data-table">
        <thead><tr><th>Subdomain</th><th>Service</th><th>CNAME</th><th>Severity</th><th>Detail</th></tr></thead>
        <tbody>
          {% for tk in vuln_takeovers %}
          <tr>
            <td class="url">{{ tk.subdomain }}</td>
            <td>{{ tk.service }}</td>
            <td style="font-size:10px">{{ tk.cname }}</td>
            <td><span class="sev-badge sev-{{ tk.severity }}">{{ tk.severity }}</span></td>
            <td style="font-size:10px">{{ tk.detail }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% elif report.subdomain_takeover %}
  <div class="section" id="sec-takeover">
    <div class="section-header" onclick="toggleSection('sec-takeover')">
      <div class="section-header-left">
        <div class="section-icon">⚡</div>
        <h2>Subdomain Takeover</h2>
      </div>
      <div class="section-header-right">
        <span class="count" style="color:var(--green)">✓ {{ (report.subdomain_takeover or [])|length }} checked — none vulnerable</span>
        <span class="arrow">▾</span>
      </div>
    </div>

  </div>
  {% endif %}

  <!-- CLOUD BUCKETS -->
  {% if report.cloud_buckets %}
  <div class="section" id="sec-buckets">
    <div class="section-header" onclick="toggleSection('sec-buckets')">
      <div class="section-header-left">
        <div class="section-icon">☁️</div>
        <h2>Cloud Bucket Enumeration</h2>
      </div>
      {% set pub = (report.cloud_buckets or [])|selectattr('status','equalto','PUBLIC')|list %}
      <div class="section-header-right">
        <span class="count" style="{% if pub %}color:var(--critical){% endif %}">
          {{ (report.cloud_buckets or [])|length }} probed
          {% if pub %}· ⚠ {{ pub|length }} PUBLIC{% endif %}
        </span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-buckets">
      <p style="font-size:11px;color:var(--dim);margin-bottom:.8rem">Status-only probing — no files downloaded or listed.</p>
      <table class="data-table">
        <thead><tr><th>Provider</th><th>Bucket URL</th><th>Status</th></tr></thead>
        <tbody>
          {% for b in report.cloud_buckets %}
          <tr>
            <td>{{ b.provider }}</td>
            <td class="url"><a href="{{ b.url }}" target="_blank">{{ b.url }}</a></td>
            <td><span class="sev-badge sev-{{ 'CRITICAL' if b.status == 'PUBLIC' else 'LOW' if b.status == 'EXISTS' else 'INFO' }}">{{ b.status }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- GITHUB LEAKS -->
  {% if report.github_leaks %}
  <div class="section" id="sec-github">
    <div class="section-header" onclick="toggleSection('sec-github')">
      <div class="section-header-left">
        <div class="section-icon">🐙</div>
        <h2>GitHub Leaked Secrets</h2>
      </div>
      <div class="section-header-right">
        <span class="count" style="color:var(--critical)">⚠ {{ report.github_leaks|length }} results</span>
        <span class="arrow">▾</span>
      </div>
    </div>
    <div class="section-body" id="body-sec-github">
      <table class="data-table">
        <thead><tr><th>Repository</th><th>File</th><th>Description</th><th>Link</th></tr></thead>
        <tbody>
          {% for g in report.github_leaks %}
          <tr>
            <td>{{ g.repo }}</td>
            <td style="font-size:10px">{{ g.path }}</td>
            <td style="font-size:10px">{{ g.description }}</td>
            <td><a href="{{ g.url }}" target="_blank" class="url">View ↗</a></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- NETLAS / HUNTERHOW / PROXYNOVA already in findings; collapsed by default -->

  <div class="footer">
    <div class="footer-inner">
      <div class="footer-brand">
        <span class="footer-logo">TR</span>
        <span>TripRecon <strong>v3.0</strong></span>
      </div>
      <div class="footer-meta">
        Generated {{ scan_date }} &nbsp;·&nbsp; {{ report.domain }} &nbsp;·&nbsp; <span style="color:var(--accent)">Authorized Security Testing Only</span>
      </div>
      <div class="footer-copy">© {{ scan_date[:4] }} CREADPAG</div>
    </div>
  </div>
</div><!-- /wrapper -->
    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /shell -->

<script>
/* ── section toggle ── */
function toggleSection(id) {
  const hdr  = document.querySelector('#'+id+' .section-header');
  const body = document.getElementById('body-'+id);
  hdr.classList.toggle('collapsed');
  body.classList.toggle('hidden');
}
function expandAll()  { document.querySelectorAll('.section-body').forEach(b=>b.classList.remove('hidden')); document.querySelectorAll('.section-header').forEach(h=>h.classList.remove('collapsed')); }
function collapseAll(){ document.querySelectorAll('.section-body').forEach(b=>b.classList.add('hidden')); document.querySelectorAll('.section-header').forEach(h=>h.classList.add('collapsed')); }

/* ── table filter ── */
function filterTable(tableId, q) {
  const rows = document.querySelectorAll('#'+tableId+' tbody tr');
  const qlo  = q.toLowerCase();
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(qlo) ? '' : 'none';
  });
}

/* ── Chart defaults ── */
Chart.defaults.color = '#7d8590';
Chart.defaults.font.family = "'Share Tech Mono', monospace";

/* Security Headers doughnut */
const hdrsCtx = document.getElementById('hdrsChart');
if (hdrsCtx) {
  const present = {{ headers_present }};
  const missing = {{ headers_missing }};
  new Chart(hdrsCtx, {
    type: 'doughnut',
    data: {
      labels: ['Present', 'Missing'],
      datasets: [{ data: [present, missing], backgroundColor: ['rgba(0,255,136,.7)','rgba(255,68,68,.5)'], borderWidth: 0 }]
    },
    options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }, cutout: '65%' }
  });
}

/* Open ports bar */
const portsCtx = document.getElementById('portsChart');
if (portsCtx) {
  const portLabels  = [{% for p in report_ports %}"{{ p.port }}/{{ p.service }}",{% endfor %}];
  const portColors  = [{% for p in report_ports %}"{{ 'rgba(255,68,68,.7)' if p.severity == 'HIGH' else 'rgba(0,180,255,.5)' }}",{% endfor %}];
  if (portLabels.length > 0) {
    new Chart(portsCtx, {
      type: 'bar',
      data: { labels: portLabels, datasets: [{ label: 'Port', data: portLabels.map(()=>1), backgroundColor: portColors, borderWidth: 0 }] },
      options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { ticks: { font: { size: 10 } } } } }
    });
  } else {
    portsCtx.parentElement.innerHTML += '<p style="color:var(--dim);font-size:11px">No ports scanned</p>';
    portsCtx.style.display='none';
  }
}

/* Subdomain sources doughnut */
const subCtx = document.getElementById('subChart');
if (subCtx) {
  new Chart(subCtx, {
    type: 'doughnut',
    data: {
      labels: ['crt.sh', 'HackerTarget', 'SecurityTrails'],
      datasets: [{
        data: [{{ report.crtsh_subdomains|length }}, {{ (report.hackertarget_subdomains or [])|length }}, {{ (report.securitytrails.data or [])|length if report.securitytrails and not report.securitytrails.error else 0 }}],
        backgroundColor: ['rgba(0,255,136,.7)','rgba(0,180,255,.6)','rgba(255,215,0,.6)'],
        borderWidth: 0,
      }]
    },
    options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }, cutout: '60%' }
  });
}

/* ── sidebar scroll spy ── */
(function() {
  const sections = document.querySelectorAll('.section[id], .header[id]');
  const navItems = document.querySelectorAll('.nav-item');
  const content  = document.getElementById('mainContent');
  if (!content || !sections.length) return;

  function updateActive() {
    let active = null;
    const scrollY = content.scrollTop;
    sections.forEach(sec => {
      if (sec.offsetTop - 80 <= scrollY) active = sec.id;
    });
    navItems.forEach(ni => {
      const fn = ni.getAttribute('onclick') || '';
      const m  = fn.match(/scrollTo\\('([^']+)'\\)/);
      if (m) ni.classList.toggle('active', m[1] === active);
    });
  }
  content.addEventListener('scroll', updateActive, { passive: true });
  updateActive();
})();

/* ── sidebar toggle (mobile) ── */
function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sideOverlay').classList.add('open');
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sideOverlay').classList.remove('open');
}
function scrollTo(id) {
  const el = document.getElementById(id);
  const content = document.getElementById('mainContent');
  if (el && content) content.scrollTo({ top: el.offsetTop - 16, behavior: 'smooth' });
  closeSidebar();
}

/* ── matrix rain canvas (header) ── */
(function() {
  const canvas = document.getElementById('hdrCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&TripRecon';
  let drops = [];
  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    const cols = Math.floor(canvas.width / 14);
    drops = Array.from({ length: cols }, () => Math.random() * -40);
  }
  function draw() {
    ctx.fillStyle = 'rgba(8,11,18,.25)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#00d9a3';
    ctx.font = '12px "JetBrains Mono", monospace';
    drops.forEach((y, i) => {
      const ch = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(ch, i * 14, y * 14);
      drops[i] = y > canvas.height / 14 + Math.random() * 20 ? 0 : y + 0.6;
    });
  }
  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 60);
})();
</script>
</body>
</html>
"""

def generate_html(report: Dict, risk: Dict, output_dir: Path) -> Path:
    # Pre-compute chart data
    headers_present = headers_missing = 0
    for scheme, data in (report.get("security_headers") or {}).items():
        for v in data.get("headers", {}).values():
            if v != "MISSING":
                headers_present += 1
            else:
                headers_missing += 1
        break

    tmpl = Template(HTML_TEMPLATE)
    html = tmpl.render(
        report         = report,
        risk           = risk,
        scan_date      = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        headers_present= headers_present,
        headers_missing= headers_missing,
        report_ports   = report.get("open_ports", []),
    )
    out = output_dir / f"triprecon_{report['domain']}.html"
    out.write_text(html, encoding="utf-8")
    return out

def generate_excel(report: Dict, risk: Dict, output_dir: Path) -> Optional[Path]:
    """Generate a styled Excel report. Handles empty / large / variable-shape data."""
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    out = output_dir / f"triprecon_{report['domain']}.xlsx"

    # ── helpers ──────────────────────────────────────────────────────────
    HDR_FILL   = PatternFill("solid", fgColor="0D1117")
    HDR_FONT   = Font(bold=True, color="00D9A3", name="Calibri", size=10)
    ALT_FILL   = PatternFill("solid", fgColor="0D1117")
    ALT_FILL2  = PatternFill("solid", fgColor="131920")
    CRIT_FILL  = PatternFill("solid", fgColor="1a0a0d")
    HIGH_FILL  = PatternFill("solid", fgColor="1a0d08")
    DATA_FONT  = Font(name="Calibri", size=9)
    THIN       = Side(style="thin", color="1E2D3D")
    CELL_BORDER = Border(bottom=Side(style="thin", color="1E2D3D"))
    WRAP        = Alignment(wrap_text=True, vertical="top")

    SEV_FILL = {
        "CRITICAL": PatternFill("solid", fgColor="1f0a10"),
        "HIGH":     PatternFill("solid", fgColor="1a0e08"),
        "MEDIUM":   PatternFill("solid", fgColor="1a1708"),
        "LOW":      PatternFill("solid", fgColor="080e1a"),
        "INFO":     PatternFill("solid", fgColor="0e1015"),
    }
    SEV_FONT = {
        "CRITICAL": Font(bold=True, color="F43F5E", name="Calibri", size=9),
        "HIGH":     Font(bold=True, color="F97316", name="Calibri", size=9),
        "MEDIUM":   Font(bold=True, color="EAB308", name="Calibri", size=9),
        "LOW":      Font(bold=True, color="3B82F6", name="Calibri", size=9),
        "INFO":     Font(bold=True, color="64748B", name="Calibri", size=9),
    }

    def _safe_str(v, max_len: int = 32767) -> str:
        """Convert value to string, truncate to Excel cell limit."""
        s = str(v) if v is not None else ""
        return s[:max_len]

    def _write_sheet(ws, headers: list[str], rows: list[dict], sev_col: str | None = None):
        """Write headers + rows with styling and auto-width."""
        # Header row
        for ci, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=ci, value=h)
            cell.fill  = HDR_FILL
            cell.font  = HDR_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center")

        # Data rows
        for ri, row in enumerate(rows, 2):
            sev = (row.get(sev_col) or "INFO").upper() if sev_col else None
            fill = SEV_FILL.get(sev, ALT_FILL) if sev else (ALT_FILL if ri % 2 == 0 else ALT_FILL2)
            for ci, h in enumerate(headers, 1):
                val = _safe_str(row.get(h, ""))
                cell = ws.cell(row=ri, column=ci, value=val)
                cell.fill = fill
                cell.font = SEV_FONT.get(sev, DATA_FONT) if sev and ci == headers.index(sev_col) + 1 else DATA_FONT
                cell.alignment = WRAP
                cell.border = CELL_BORDER

        # Auto-fit columns (estimate from data)
        for ci, h in enumerate(headers, 1):
            col_letter = get_column_letter(ci)
            max_len = len(h)
            for ri in range(2, ws.max_row + 1):
                val = ws.cell(row=ri, column=ci).value or ""
                # Cap width estimation to avoid huge columns
                max_len = max(max_len, min(len(str(val).split("\n")[0]), 80))
            ws.column_dimensions[col_letter].width = min(max(max_len + 2, 8), 82)

        # Freeze header row
        ws.freeze_panes = "A2"
        ws.row_dimensions[1].height = 20

    def _sheet_from_list(writer_wb, sheet_name: str, rows: list[dict],
                         default_headers: list[str] | None = None,
                         sev_col: str | None = None):
        """Create a sheet from a list of dicts. Skips if empty with no default."""
        if not rows:
            if default_headers is None:
                return  # skip empty sheet
            rows = []   # write header-only sheet
        # Gather all keys preserving insertion order
        if default_headers:
            headers = list(default_headers)
            # add any extra keys found in data
            seen = set(headers)
            for r in rows:
                for k in r:
                    if k not in seen:
                        headers.append(k); seen.add(k)
        else:
            seen, headers = set(), []
            for r in rows:
                for k in r:
                    if k not in seen:
                        headers.append(k); seen.add(k)

        ws = writer_wb.create_sheet(sheet_name)
        ws.sheet_view.showGridLines = False
        _write_sheet(ws, headers, rows, sev_col=sev_col)

    # ── build workbook ────────────────────────────────────────────────────
    try:
        wb = openpyxl.Workbook()
        # Remove default sheet
        if "Sheet" in wb.sheetnames:
            del wb["Sheet"]

        # 1 · Risk Findings
        risk_rows = [
            {"Severity": f.get("severity","INFO"), "Title": f.get("title",""), "Detail": f.get("detail",""), "Evidence": (f.get("evidence") or "")[:500]}
            for f in (risk.get("findings") or [])
        ]
        _sheet_from_list(wb, "Risk Findings",
                         risk_rows or [{"Severity": "INFO", "Title": "No findings", "Detail": "", "Evidence": ""}],
                         default_headers=["Severity", "Title", "Detail", "Evidence"],
                         sev_col="Severity")

        # 2 · Subdomains (with source tracking)
        subs: list[dict] = []
        for s in (report.get("crtsh_subdomains") or []):
            subs.append({"Subdomain": s.get("subdomain",""), "IP": s.get("ip",""), "Source": "crt.sh"})
        for s in (report.get("hackertarget_subdomains") or []):
            subs.append({"Subdomain": s.get("subdomain",""), "IP": s.get("ip",""), "Source": "HackerTarget"})
        st = report.get("securitytrails") or {}
        if not st.get("error"):
            for s in (st.get("data") or []):
                subs.append({"Subdomain": s.get("subdomain",""), "IP": s.get("ip",""), "Source": "SecurityTrails"})
        _sheet_from_list(wb, "Subdomains", subs,
                         default_headers=["Subdomain", "IP", "Source"])

        # 3 · DNS
        dns_rows = [{"Type": k, "Records": "\n".join(v) if isinstance(v, list) else str(v)}
                    for k, v in (report.get("dns_info") or {}).items() if v]
        _sheet_from_list(wb, "DNS", dns_rows, default_headers=["Type", "Records"])

        # 4 · Sensitive Paths
        sp_rows = [{"Path": r.get("path",""), "Status": r.get("status",""), "Size": r.get("size",""),
                    "Severity": r.get("severity",""), "URL": r.get("url","")}
                   for r in (report.get("sensitive_paths") or [])]
        _sheet_from_list(wb, "Sensitive Paths", sp_rows,
                         default_headers=["Path","Status","Size","Severity","URL"],
                         sev_col="Severity")

        # 5 · Security Headers
        hdr_rows = []
        for scheme, data in (report.get("security_headers") or {}).items():
            for h, v in (data.get("headers") or {}).items():
                present = v != "MISSING"
                hdr_rows.append({"Protocol": scheme, "Header": h, "Value": v if present else "", "Present": "YES" if present else "NO"})
        _sheet_from_list(wb, "Security Headers", hdr_rows,
                         default_headers=["Protocol","Header","Value","Present"])

        # 6 · CORS
        cors_rows = [{"URL": r.get("url",""), "Origin": r.get("origin",""), "Status": r.get("status","")}
                     for r in (report.get("cors_findings") or [])]
        _sheet_from_list(wb, "CORS Findings", cors_rows,
                         default_headers=["URL","Origin","Status"])

        # 7 · Open Ports
        port_rows = [{"Port": r.get("port",""), "Service": r.get("service",""), "Severity": r.get("severity","")}
                     for r in (report.get("open_ports") or [])]
        _sheet_from_list(wb, "Open Ports", port_rows,
                         default_headers=["Port","Service","Severity"],
                         sev_col="Severity")

        # 8 · Dork Results
        dork_rows = []
        for engine, dresults in (report.get("dork_results") or {}).items():
            for dork, hits in dresults.items():
                if not isinstance(hits, list):
                    continue
                for h in hits:
                    if isinstance(h, dict):
                        dork_rows.append({"Engine": engine, "Query": dork[:200],
                                          "URL": h.get("url","")[:500],
                                          "File Type": h.get("file_type",""),
                                          "Is File": "YES" if h.get("is_file") else "NO"})
                    elif isinstance(h, str):
                        dork_rows.append({"Engine": engine, "Query": dork[:200], "URL": h[:500], "File Type": "", "Is File": "NO"})
        _sheet_from_list(wb, "Dork Results", dork_rows,
                         default_headers=["Engine","Query","URL","File Type","Is File"])

        # 9 · Wayback URLs (potentially very large — stream efficiently)
        wb_list = report.get("wayback_urls") or []
        wb_rows = [{"URL": u} for u in wb_list]
        _sheet_from_list(wb, "Wayback URLs", wb_rows, default_headers=["URL"])

        # 10 · Data Leaks
        leak_rows = [{"Record": _safe_str(l, 500)} for l in (report.get("leaks") or [])]
        _sheet_from_list(wb, "Data Leaks", leak_rows, default_headers=["Record"])

        # 11 · Wayback Params
        wb_params = report.get("wayback_params") or {}
        def _wp_count(item):
            v = item[1]
            return v.get("count", 0) if isinstance(v, dict) else (len(v) if isinstance(v, list) else 0)
        def _wp_row(k, v):
            if isinstance(v, dict):
                return {"Parameter": k, "Count": v.get("count", 0),
                        "Example Values": ", ".join((v.get("values") or [])[:8])}
            if isinstance(v, list):
                return {"Parameter": k, "Count": len(v),
                        "Example Values": ", ".join(str(x) for x in v[:8])}
            return {"Parameter": k, "Count": 0, "Example Values": str(v)}
        wp_rows = [_wp_row(k, v)
                   for k, v in sorted(wb_params.items(), key=_wp_count, reverse=True)]
        _sheet_from_list(wb, "Wayback Params", wp_rows,
                         default_headers=["Parameter","Count","Example Values"])

        # 12 · JS Secrets
        js = report.get("js_analysis") or {}
        _sheet_from_list(wb, "JS Secrets",
                         [{"Type": s.get("type",""), "Match": _safe_str(s.get("match",""),300),
                           "Source": s.get("source","")} for s in (js.get("secrets") or [])],
                         default_headers=["Type","Match","Source"])

        # 13 · JS Endpoints
        _sheet_from_list(wb, "JS Endpoints",
                         [{"Endpoint": e.get("endpoint",""), "Source": e.get("source","")}
                          for e in (js.get("endpoints") or [])],
                         default_headers=["Endpoint","Source"])

        # 14 · Subdomain Takeover
        tko_rows = [{"Subdomain": r.get("subdomain",""), "CNAME": r.get("cname",""),
                     "Service": r.get("service",""), "Vulnerable": "YES" if r.get("vulnerable") else "NO",
                     "Confidence": r.get("confidence","")}
                    for r in (report.get("subdomain_takeover") or [])]
        _sheet_from_list(wb, "Takeover Check", tko_rows,
                         default_headers=["Subdomain","CNAME","Service","Vulnerable","Confidence"])

        # 15 · Cloud Buckets
        bkt_rows = [{"URL": r.get("url",""), "Status": r.get("status",""), "Provider": r.get("provider","")}
                    for r in (report.get("cloud_buckets") or [])]
        _sheet_from_list(wb, "Cloud Buckets", bkt_rows,
                         default_headers=["URL","Status","Provider"])

        # 16 · GitHub Leaks
        gh_rows = []
        for item in (report.get("github_leaks") or []):
            if isinstance(item, dict):
                gh_rows.append({"Repo": item.get("repo",""), "Path": item.get("path",""),
                                 "Match": _safe_str(item.get("match",""),400)})
            else:
                gh_rows.append({"Repo": "", "Path": "", "Match": _safe_str(item,400)})
        _sheet_from_list(wb, "GitHub Leaks", gh_rows,
                         default_headers=["Repo","Path","Match"])

        # 17 · WHOIS
        whois = report.get("whois") or {}
        if whois and not whois.get("error"):
            whois_rows = [{"Field": k, "Value": _safe_str(v, 1000)} for k, v in whois.items() if k != "error"]
            _sheet_from_list(wb, "WHOIS", whois_rows, default_headers=["Field","Value"])

        # 18 · Email Security
        em = report.get("email_security") or {}
        if em:
            em_rows = [
                {"Check": "SPF Record",   "Value": (em.get("spf") or {}).get("record","")},
                {"Check": "SPF All Tag",  "Value": (em.get("spf") or {}).get("all_qualifier","")},
                {"Check": "DMARC Record", "Value": (em.get("dmarc") or {}).get("record","")},
                {"Check": "DMARC Policy", "Value": (em.get("dmarc") or {}).get("policy","")},
                {"Check": "DMARC pct",    "Value": str((em.get("dmarc") or {}).get("pct",""))},
            ]
            for sel, rec in ((em.get("dkim_selectors") or {}).items()):
                em_rows.append({"Check": f"DKIM:{sel}", "Value": _safe_str(rec, 500)})
            _sheet_from_list(wb, "Email Security", em_rows, default_headers=["Check","Value"])

        # 19 · ASN / Network
        asn = report.get("asn_info") or {}
        if asn and not asn.get("error"):
            asn_rows = [{"Field": k, "Value": _safe_str(v, 500)}
                        for k, v in asn.items() if k not in ("prefixes","error")]
            prefixes = asn.get("prefixes") or []
            if prefixes:
                for p in prefixes:
                    asn_rows.append({"Field": "Prefix", "Value": _safe_str(p, 200)})
            _sheet_from_list(wb, "ASN Info", asn_rows, default_headers=["Field","Value"])

        # 20 · Shodan
        si = report.get("shodan_info") or {}
        if si and not si.get("error"):
            _sheet_from_list(wb, "Shodan",
                             [{"Field": k, "Value": _safe_str(v,1000)} for k, v in si.items() if k != "error"],
                             default_headers=["Field","Value"])

        wb.save(out)
        return out
    except Exception as e:
        import traceback
        console.print(f"[red]  ✗ Excel generation failed: {e}[/red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return None

def generate_json(report: Dict, risk: Dict, output_dir: Path) -> Path:
    out = output_dir / f"triprecon_{report['domain']}.json"
    payload = {"report": report, "risk": risk, "generated": datetime.now().isoformat()}
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return out

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def analyze_domain(domain: str, dorks: List[str], cfg: Config, args: argparse.Namespace) -> Dict:
    report: Dict[str, Any] = {
        # Core
        "domain": domain, "ip": "", "dns_info": {}, "whois": {},
        # Subdomains
        "crtsh_subdomains": [], "crtsh_wildcards": [],
        "hackertarget_subdomains": [], "securitytrails": {},
        # Infrastructure
        "asn_info": {}, "shodan_info": {}, "netlas_info": {},
        "hunterhow_info": {}, "virustotal": {}, "urlscan_results": [],
        # Fingerprinting
        "favicon": {}, "waf_info": {}, "technologies": {}, "security_headers": {},
        # Email security
        "email_security": {},
        # Content discovery
        "wayback_urls": [], "wayback_params": {}, "js_analysis": {},
        "sensitive_paths": [], "cors_findings": [],
        # Attack surface
        "open_ports": [], "cloud_buckets": [], "subdomain_takeover": [],
        "github_leaks": [],
        # Dorks & leaks
        "leaks": [], "dork_results": {},
    }

    use_all = args.all

    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), BarColumn(),
                  TimeElapsedColumn(), console=console, transient=True) as prog:

        t = prog.add_task("Resolving IP...", total=None)
        report["ip"] = get_ip(domain)

        prog.update(t, description="WHOIS / RDAP...")
        report["whois"] = get_whois(domain, cfg)

        prog.update(t, description="DNS records + Email security...")
        report["dns_info"] = get_dns_records(domain)
        report["email_security"] = analyze_email_security(domain)

        prog.update(t, description="ASN / BGP enumeration...")
        report["asn_info"] = enumerate_asn(domain, report["ip"], cfg)

        prog.update(t, description="crt.sh subdomains...")
        report["crtsh_subdomains"], report["crtsh_wildcards"] = get_crtsh_subdomains(domain, cfg)

        prog.update(t, description="HackerTarget subdomains (free)...")
        report["hackertarget_subdomains"] = get_hackertarget_subdomains(domain, cfg)

        prog.update(t, description="SecurityTrails subdomains...")
        report["securitytrails"] = get_securitytrails_subdomains(domain, cfg)

        # Aggregate all unique subdomains for takeover check
        all_subs: List[str] = list({
            s.get("subdomain", s) if isinstance(s, dict) else s
            for s in (
                report["crtsh_subdomains"]
                + report["hackertarget_subdomains"]
                + report["securitytrails"].get("subdomains", [])
            )
        })

        prog.update(t, description="Favicon hash (Shodan pivot)...")
        report["favicon"] = get_favicon_hash(domain, cfg)

        prog.update(t, description="Shodan...")
        report["shodan_info"] = get_shodan(report["ip"], cfg)

        prog.update(t, description="Netlas...")
        report["netlas_info"] = get_netlas(domain, cfg)

        prog.update(t, description="Hunter.how...")
        report["hunterhow_info"] = get_hunterhow(domain, cfg)

        prog.update(t, description="VirusTotal...")
        report["virustotal"] = get_virustotal(domain, cfg)

        prog.update(t, description="URLScan.io...")
        report["urlscan_results"] = get_urlscan(domain, cfg)

        prog.update(t, description="ProxyNova leaks...")
        report["leaks"] = find_leaks_proxynova(domain, cfg)

        # ── Conditional modules ──
        if use_all or args.wayback:
            prog.update(t, description="Wayback Machine CDX...")
            report["wayback_urls"] = get_wayback_urls(domain, cfg)
            prog.update(t, description="Wayback param mining...")
            report["wayback_params"] = mine_wayback_params(report["wayback_urls"])

        if use_all or args.analyze_headers:
            prog.update(t, description="Security headers...")
            report["security_headers"] = analyze_headers(domain, cfg)

        if use_all or args.check_paths:
            prog.update(t, description="Sensitive paths...")
            report["sensitive_paths"] = check_sensitive_paths(domain, cfg)

        if use_all or args.cors:
            prog.update(t, description="CORS check...")
            report["cors_findings"] = check_cors(domain, cfg)

        if use_all or args.waf:
            prog.update(t, description="WAF detection...")
            report["waf_info"] = detect_waf(domain, cfg)

        if use_all or args.detect_tech:
            prog.update(t, description="Technology detection...")
            report["technologies"] = detect_technologies(domain, cfg)

        if use_all or args.scan_ports:
            prog.update(t, description="Port scan...")
            report["open_ports"] = port_scan(domain, cfg)

        if use_all or getattr(args, "js", False):
            prog.update(t, description="JS endpoint extraction...")
            report["js_analysis"] = extract_js_endpoints(domain, cfg)

        if use_all or getattr(args, "takeover", False):
            prog.update(t, description="Subdomain takeover detection...")
            report["subdomain_takeover"] = check_subdomain_takeover(all_subs[:80], cfg)

        if use_all or getattr(args, "buckets", False):
            prog.update(t, description="Cloud bucket enumeration...")
            report["cloud_buckets"] = enumerate_cloud_buckets(domain, cfg)

        if use_all or getattr(args, "github", False):
            prog.update(t, description="GitHub dorking...")
            report["github_leaks"] = dork_github(domain, cfg)

        # ── Dork engines ──
        if dorks:
            engines_raw = args.engines.lower()
            engines = [e.strip() for e in
                       (["google","bing","ddg","yahoo","yandex","brave"] if engines_raw == "all" else engines_raw.split(","))]
            prog.update(t, description=f"Dorking ({', '.join(engines)})...")
            report["dork_results"] = run_dork_engines(domain, dorks, cfg, engines, args)

        prog.update(t, description="Done.")

    return report

def main() -> None:
    print_banner()
    args = parse_args()
    cfg  = Config()

    console.print(Panel(
        f"[dim]Config loaded from .env[/dim]\n\n"
        f"[bold]Core OSINT[/bold]\n"
        f"  Shodan:         {'[green]✓[/green]' if cfg.shodan_key         else '[yellow]–  (IP intel limited)[/yellow]'}\n"
        f"  SecurityTrails: {'[green]✓[/green]' if cfg.securitytrails_key else '[yellow]–  (subdomain history off)[/yellow]'}\n"
        f"  VirusTotal:     {'[green]✓[/green]' if cfg.virustotal_key     else '[dim]–[/dim]'}\n"
        f"  URLScan:        {'[green]✓[/green]' if cfg.urlscan_key        else '[dim]–[/dim]'}\n"
        f"  Netlas:         {'[green]✓[/green]' if cfg.netlas_key         else '[dim]–[/dim]'}\n"
        f"  Hunter.how:     {'[green]✓[/green]' if cfg.hunterhow_key      else '[dim]–[/dim]'}\n\n"
        f"[bold]Search Engines (dorks)[/bold]\n"
        f"  Google API:     {'[green]✓[/green]' if cfg.google_api_key     else '[yellow]–  (scraping fallback)[/yellow]'}\n"
        f"  Bing API:       {'[green]✓[/green]' if cfg.bing_api_key       else '[yellow]–  (scraping fallback)[/yellow]'}\n"
        f"  Brave API:      {'[green]✓[/green]' if cfg.brave_api_key      else '[dim]–[/dim]'}\n"
        f"  DDG library:    {'[green]✓[/green]' if DDG_AVAILABLE          else '[yellow]pip install duckduckgo-search[/yellow]'}\n\n"
        f"[bold]v4 Modules (free — no key required)[/bold]\n"
        f"  ASN:            [green]✓  (Team Cymru DNS + RIPE Stat + ip-api)[/green]\n"
        f"  WHOIS/RDAP:     [green]✓  (rdap.org free API)[/green]\n"
        f"  Favicon hash:   [green]✓  (MurmurHash3 built-in)[/green]\n"
        f"  Wayback CDX:    [green]✓  (archive.org free)[/green]\n"
        f"  Email security: [green]✓  (DNS only — SPF/DMARC/DKIM)[/green]\n\n"
        f"[bold]v4 Modules (optional key)[/bold]\n"
        f"  GitHub dork:    {'[green]✓[/green]' if cfg.github_token        else '[yellow]–  set GITHUB_TOKEN (rate limited without)[/yellow]'}\n"
        f"  IPInfo ASN:     {'[green]✓[/green]' if cfg.ipinfo_key          else '[dim]–  (fallback, Cymru DNS is primary)[/dim]'}\n\n"
        f"  Proxy:          {cfg.proxy or '[dim]none[/dim]'}",
        title="[bold]TripRecon v3.0 — API Status[/bold]",
        border_style="green",
        expand=False,
    ))

    dorks: List[str] = read_dorks(args.dork) if args.dork else []

    domains: List[str] = []
    if args.domain:
        domains.append(args.domain)
    else:
        try:
            domains = [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
        except FileNotFoundError:
            console.print(f"[red]Domain list file not found: {args.list}[/red]")
            sys.exit(1)

    for domain in domains:
        console.print(f"\n[bold green]{'='*60}[/bold green]")
        console.print(Panel(f"[bold]Target:[/bold] [green]{domain}[/green]", border_style="green", expand=False))

        if args.output:
            out_dir = Path(args.output)
        else:
            out_dir = Path(domain.replace(".", "_"))
        out_dir.mkdir(parents=True, exist_ok=True)

        report = analyze_domain(domain, dorks, cfg, args)
        risk   = calculate_risk(report)

        # Print risk summary
        grade_color = {"A": "green","B": "green","C": "yellow","D": "orange3","F": "red"}
        gc = grade_color.get(risk["grade"], "white")
        console.print(f"\n[bold]Risk Score:[/bold] [{gc}]{risk['score']}/100 (Grade {risk['grade']})[/{gc}]")
        if risk["findings"]:
            for f in risk["findings"][:5]:
                sev_colors = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"blue","INFO":"dim"}
                c = sev_colors.get(f["severity"], "white")
                console.print(f"  [{c}]▶ {f['severity']:8}[/{c}] {f['title']}")

        # Generate reports
        html_path  = generate_html(report, risk, out_dir)
        excel_path = generate_excel(report, risk, out_dir)
        json_path  = generate_json(report, risk, out_dir)

        console.print(f"\n[bold green]Reports saved to ./{out_dir}/[/bold green]")
        console.print(f"  [blue]HTML:[/blue]  {html_path.name}")
        console.print(f"  [blue]Excel:[/blue] {excel_path.name if excel_path else 'failed'}")
        console.print(f"  [blue]JSON:[/blue]  {json_path.name}")

if __name__ == "__main__":
    main()
