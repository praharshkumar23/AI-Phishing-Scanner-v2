# 🛡️ AI Phishing Link Scanner v2.0

> Multi-layer phishing detection tool combining static analysis, VirusTotal + AbuseIPDB reputation checks, and AI semantic analysis using Google Gemini or OpenAI GPT-4o.

Built by **Praharsh Kumar** — SOC Analyst | Detection Engineering | SC-200 Certified

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Version](https://img.shields.io/badge/version-2.0-orange)
![Made by](https://img.shields.io/badge/made%20by-Praharsh%20Kumar-blueviolet)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What's New in v2.0](#-whats-new-in-v20)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Detection Logic](#-detection-logic)
- [Risk Score Calculation](#-risk-score-calculation)
- [Example Output](#-example-output)
- [API Rate Limits](#-api-rate-limits)
- [Troubleshooting](#-troubleshooting)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔎 Overview

Most phishing detection tools rely on a single source — either a regex check or one API lookup. That's not enough.

This scanner runs every URL through **4 independent detection layers** and combines their signals into a single weighted risk score out of 100.

**The question it answers:**

> Is this link safe, suspicious, or malicious — and why?

Instead of giving you a yes/no, it tells you:
- what patterns triggered the alert,
- what VirusTotal engines flagged it,
- what the AI thinks and why,
- and what you should do next.

---

## ✨ What's New in v2.0

| Feature | v1.0 | v2.0 |
|---|---|---|
| AbuseIPDB IP reputation check | ❌ | ✅ |
| Batch URL scanning | ❌ | ✅ |
| JSON report export | ❌ | ✅ |
| Scan history logging | ❌ | ✅ |
| MITRE ATT&CK technique mapping | ❌ | ✅ |
| Interactive menu | ❌ | ✅ |
| Hex encoding detection | ❌ | ✅ |
| Double slash path detection | ❌ | ✅ |
| Expanded TLD coverage | Basic | `.tk .ml .ga .cf .gq .pw .xyz .top` |
| Expanded phishing keywords | 15 | 22 |
| Expanded typosquatting patterns | 8 | 12 |

---

## 🔬 How It Works

```text
URL Input
   │
   ├──  URL Validation
   │       → Regex structure check
   │       → Rejects malformed input early
   │
   ├──  Static Analysis
   │       → IP address in URL
   │       → Typosquatting patterns (amaz0n, g00gle, etc.)
   │       → Suspicious TLD detection
   │       → Keyword scanning (login, verify, suspend, etc.)
   │       → HTTP vs HTTPS
   │       → URL length, subdomains, hex encoding
   │       → Risk score: 0–100
   │
   ├──  VirusTotal Reputation Check
   │       → Submits URL to VirusTotal API v3
   │       → Waits for 70+ AV engine analysis
   │       → Returns malicious / suspicious / harmless counts
   │
   ├──  AbuseIPDB Check (if IP in URL)
   │       → Checks IP abuse confidence score
   │       → Returns total reports, country, ISP, Tor status
   │
   ├──  AI Semantic Analysis
   │       → Sends URL + static results to Gemini or GPT-4o
   │       → Returns VERDICT, CONFIDENCE, RED FLAGS, MITRE technique, REASONING
   │
   └── Final Verdict
           → Weighted risk score: Static 25% | VT 40% | AbuseIPDB 15% | AI 20%
           → SAFE (0–39) / SUSPICIOUS (40–69) / MALICIOUS (70–100)
           → Saved to scan_history.json
           → Exportable as JSON report
```

---

 📁 Project Structure
AI-Phishing-Scanner-v2/
│
├── phishing_scanner.py # Main scanner — all detection logic here
├── requirements.txt # Python package dependencies
├── .env.example # API key template (rename to .env)
├── .gitignore # Excludes .env, venv, cache, reports
├── README.md # Project documentation
│
└── (auto-generated on use)
├── scan_history.json # Logs every scan with timestamp + verdict
└── scan_report_YYYYMMDD_HHMMSS.json # Per-scan JSON export

text

---

## 📦 Requirements

### Software

- Python 3.8 or higher
- pip
- Internet access for API calls

### API Keys Needed

| Service | Purpose | Cost | Get Key |
|---|---|---|---|
| **VirusTotal** | URL reputation — 70+ AV engines | Free (4 req/min) | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| **Google Gemini** | AI semantic analysis | Free tier available | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) |
| **OpenAI** | AI semantic analysis (alternative) | ~$0.01–0.03/scan | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| **AbuseIPDB** | IP reputation check | Free (1,000/day) | [abuseipdb.com/register](https://www.abuseipdb.com/register) |

> You only need **one** LLM provider — either Gemini or OpenAI.
> AbuseIPDB is optional. The scanner skips it automatically if no key is provided.

### Python Packages

| Package | Version | Purpose |
|---|---|---|
| `requests` | 2.31.0+ | HTTP calls to APIs |
| `python-dotenv` | 1.0.0+ | Load `.env` config |
| `colorama` | 0.4.6+ | Colored terminal output |
| `google-generativeai` | 0.3.0+ | Gemini AI integration |
| `openai` | 1.12.0+ | OpenAI GPT integration |

---

## 🚀 Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/praharshkumar23/AI-Phishing-Scanner-v2.git
cd AI-Phishing-Scanner-v2
```

### Step 2 — Create a virtual environment

```bash
python -m venv venv
```

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Verify installation

```bash
python --version
pip list
```

You should see `requests`, `python-dotenv`, `colorama`, `google-generativeai`, and `openai` in the list.

---

## ⚙️ Configuration

### Step 1 — Create your `.env` file

Copy the template:

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

### Step 2 — Add your API keys

Open `.env` and fill in your keys:

```ini
# VirusTotal API Key (required)
# Get from: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# AbuseIPDB API Key (optional — used only if URL has an IP address)
# Get from: https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# LLM Provider — choose one: gemini or openai
LLM_PROVIDER=gemini

# Google Gemini API Key
# Get from: https://aistudio.google.com/app/apikey
GOOGLE_API_KEY=your_gemini_key_here

# OpenAI API Key (use this instead if LLM_PROVIDER=openai)
# Get from: https://platform.openai.com/api-keys
OPENAI_API_KEY=your_openai_key_here
```

> ⚠️ Never push `.env` to GitHub. It's already blocked in `.gitignore`.

---

## 💻 Usage

### Single URL — command line

```bash
python phishing_scanner.py "https://example.com"
```

### Interactive menu

```bash
python phishing_scanner.py
```

You'll see:
OPTIONS
1 Scan a single URL
2 Batch scan (multiple URLs)
3 View scan history
q Quit

text

### Batch scan

Select option `2` in interactive mode.
Enter URLs one per line. Leave a blank line to start scanning.
Results are saved automatically.

### Export report

After a scan, you'll be prompted:
Save report to JSON? (y/n)

text
The report is saved as `scan_report_YYYYMMDD_HHMMSS.json`.

---

## 🔍 Detection Logic

### Static Analysis — what it checks

| Indicator | Risk Points | Example |
|---|---|---|
| IP address in URL | 30 | `http://192.168.1.1/login` |
| Typosquatting pattern | 30 | `amaz0n.com`, `paypa1.com` |
| Suspicious TLD | 25 | `.tk`, `.ml`, `.ga`, `.xyz`, `.pw` |
| Excessive subdomains | 20 | `secure.verify.login.paypal.com` |
| `@` symbol in URL | 20 | `http://safe.com@evil.com` |
| Double slash in path | 15 | `https://site.com//redirect` |
| URL length > 75 chars | 15 | Long obfuscated URLs |
| HTTP instead of HTTPS | 10 | `http://` |
| Hex encoding | 10 | `%2F`, `%40` |
| Suspicious keyword | 5 each | `login`, `verify`, `urgent`, `suspend` |

### Typosquatting patterns checked

- `amaz[o0]n`, `g[o0]{2}gle`, `faceb[o0]{2}k`, `micr[o0]s[o0]ft`
- `paypa[l1]`, `app[l1]e`, `netf[l1]ix`, `tw[i1]tter`
- `ins[t7]agram`, `[l1]inked[i1]n`, `dropb[o0]x`, `[o0]ff[i1]ce365`

### Suspicious keywords checked

`login` · `signin` · `account` · `verify` · `secure` · `update` · `confirm` · `banking` · `paypal` · `amazon` · `apple` · `microsoft` · `password` · `suspend` · `locked` · `unusual` · `click` · `urgent` · `alert` · `validate` · `authorize` · `recover`

### AI Semantic Analysis — what it detects

- Brand impersonation
- Urgency and fear tactics
- Credential harvesting patterns
- Fake login page indicators
- Suspicious path and domain combinations
- MITRE ATT&CK technique mapping

---

## 📊 Risk Score Calculation

The final risk score is calculated using weighted signals:

| Layer | Weight | Source |
|---|---|---|
| Static Analysis | 25% | URL structure and pattern matching |
| VirusTotal | 40% | AV engine malicious + suspicious votes |
| AbuseIPDB | 15% | IP abuse confidence score |
| AI Semantic Analysis | 20% | LLM phishing confidence |

**Final Verdict:**

| Score | Verdict |
|---|---|
| `0 – 39` | ✅ SAFE — URL appears legitimate |
| `40 – 69` | ⚠️ SUSPICIOUS — verify before clicking |
| `70 – 100` | 🚨 MALICIOUS — do not visit |

---

## 📊 Example Output

### Safe URL
======================================================================
SCANNING: https://www.google.com
======================================================================

[1/4] Static analysis...
[+] Risk score: 0/100

[2/4] VirusTotal check...
[+] Done

[3/4] AbuseIPDB check...
[!] No IP in URL — AbuseIPDB skipped

[4/4] AI semantic analysis...
[+] Done — 1% confidence

======================================================================
SCAN REPORT

URL : https://www.google.com
Scanned : 2026-05-05 18:00:00

STATIC ANALYSIS
Risk Score : 0/100
IP in URL : No
HTTP (no HTTPS) : No
Suspicious TLD : No
Hex Encoding : No

VIRUSTOTAL REPUTATION
Malicious : 0/89
Suspicious : 0/89
Harmless : 89/89

AI SEMANTIC ANALYSIS
Verdict : LEGITIMATE
Confidence : 1%
Red Flags : None
MITRE Technique : Not applicable

======================================================================
FINAL VERDICT: APPEARS SAFE — LOW RISK
Overall Risk : 1/100
Action : URL looks legitimate. Always verify sender context.
======================================================================

text

### Phishing URL
======================================================================
SCAN REPORT

URL : http://amaz0n-security-update.com/verify-account
Scanned : 2026-05-05 18:02:00

STATIC ANALYSIS
Risk Score : 75/100
HTTP (no HTTPS) : YES
Keywords : security, update, verify, account
Typosquatting : amaz[o0]n

VIRUSTOTAL REPUTATION
Malicious : 12/89
Suspicious : 8/89
Harmless : 69/89

AI SEMANTIC ANALYSIS
Verdict : PHISHING
Confidence : 95%
Red Flags : Typosquatting, urgency keywords, HTTP protocol
MITRE Technique : T1566 - Phishing

======================================================================
FINAL VERDICT: MALICIOUS — HIGH RISK
Overall Risk : 87/100
Action : DO NOT VISIT. Strong phishing indicators detected.
======================================================================

text

---

## ⏱️ API Rate Limits

| Service | Free Tier Limit | Notes |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | Scanner auto-waits 15s between submit and retrieve |
| Google Gemini | 60 req/min | Free tier, no credit card needed |
| OpenAI GPT-4o | ~$0.01–0.03/scan | Paid per token |
| AbuseIPDB | 1,000 checks/day | Only triggers when URL has an IP address |

---

## 🐛 Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `VIRUSTOTAL_API_KEY not found` | `.env` file missing or wrong | Create `.env` from `.env.example`. No spaces around `=`. |
| `GOOGLE_API_KEY not found` | Wrong provider set | Set `LLM_PROVIDER=gemini` and add `GOOGLE_API_KEY` |
| `No compatible Gemini model found` | API key invalid or expired | Check key at [aistudio.google.com](https://aistudio.google.com) |
| `pip is not recognized` | Python not on PATH | Use `python -m pip install -r requirements.txt` |
| `Rate limit exceeded` | Too many VT requests | Wait 1 minute. VT free tier: 4 req/min |
| `OpenAI error 429` | Quota exceeded | Add credits at [platform.openai.com/usage](https://platform.openai.com/usage) or switch to Gemini |
| `colorama not installed` | Skipped install | Run `pip install colorama` |
| Scan history not saving | Write permissions | Run terminal as admin or check folder permissions |

---

## 🔐 Security Notes

- The scanner **never visits** the target URL in a browser or makes HTTP requests to it.
- All analysis is done on the URL string and external reputation APIs only.
- URLs are sent to VirusTotal and your chosen LLM for analysis. Do not scan sensitive or internal URLs.
- Always add `.env` to `.gitignore` before pushing to GitHub.

```text
# .gitignore
.env
__pycache__/
*.pyc
venv/
.venv/
scan_history.json
scan_report_*.json
*.log
.DS_Store
```

---

## 🤝 Contributing

Contributions are welcome. Steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes.
4. Test the scanner manually.
5. Commit: `git commit -m "Add: your feature description"`
6. Push: `git push origin feature/your-feature-name`
7. Open a Pull Request.

### Ideas for contributions

- Add screenshot/title scraping for URL preview.
- Add CSV batch input support.
- Add email header scanning.
- Add Streamlit or Flask web UI.
- Add threat intel feed integration.
- Add Slack or email alert output.

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute with attribution.

---

## 🙏 Acknowledgements

- [VirusTotal](https://www.virustotal.com) — URL and file reputation API
- [AbuseIPDB](https://www.abuseipdb.com) — IP reputation and abuse tracking
- [Google Gemini](https://aistudio.google.com) — AI semantic analysis
- [OpenAI](https://openai.com) — GPT-4o AI analysis
- [MITRE ATT&CK](https://attack.mitre.org) — Threat technique framework

---

Made with 🔍 by **Praharsh Kumar**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-praharshkumar23-blue?logo=linkedin)](https://linkedin.com/in/praharshkumar23)
[![GitHub](https://img.shields.io/badge/GitHub-praharshkumar23-black?logo=github)](https://github.com/praharshkumar23)
