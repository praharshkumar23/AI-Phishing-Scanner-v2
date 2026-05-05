# 🛡️ AI Phishing Link Scanner v2.0

> Multi-layer phishing detection combining static analysis, VirusTotal + AbuseIPDB reputation checks, and AI semantic analysis (Gemini / GPT-4o).

Built by **Praharsh Kumar** — SOC Analyst | Detection Engineering | SC-200

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Version](https://img.shields.io/badge/version-2.0-orange)

---

## 📌 What It Does

Scans any URL through 4 detection layers and returns a risk verdict:

```
URL Input
   │
   ├── [1] Static Analysis       → structure, keywords, typosquatting, TLD
   ├── [2] VirusTotal Check      → 70+ AV engine reputation scan
   ├── [3] AbuseIPDB Check       → IP reputation (if URL contains IP)
   └── [4] AI Semantic Analysis  → Gemini / GPT-4o phishing verdict + MITRE mapping
               │
               └── Final Verdict: SAFE / SUSPICIOUS / MALICIOUS + Risk Score /100
```

---

## ✨ What's New in v2.0

| Feature | v1.0 | v2.0 |
|---|---|---|
| AbuseIPDB reputation check | ❌ | ✅ |
| Batch URL scanning | ❌ | ✅ |
| JSON report export | ❌ | ✅ |
| Scan history log | ❌ | ✅ |
| MITRE ATT&CK mapping | ❌ | ✅ |
| Interactive menu | ❌ | ✅ |
| Expanded keyword + TLD detection | Basic | Expanded |

---

## 📦 Requirements

- Python 3.8+
- VirusTotal API key (free)
- Google Gemini **or** OpenAI API key
- AbuseIPDB API key (optional)

---

## 🚀 Installation

```bash
git clone https://github.com/praharshkumar23/ai-phishing-scanner.git
cd ai-phishing-scanner

python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

---

## ⚙️ Configuration

Create a `.env` file in the project root:

```ini
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
LLM_PROVIDER=gemini
GOOGLE_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
```

> ⚠️ Never commit `.env` to GitHub. It's already in `.gitignore`.

---

## 💻 Usage

```bash
# Single URL
python phishing_scanner.py "https://example.com"

# Interactive menu
python phishing_scanner.py
```

---

## 📊 Risk Score Weights

| Layer | Weight |
|---|---|
| Static Analysis | 25% |
| VirusTotal | 40% |
| AbuseIPDB | 15% |
| AI Analysis | 20% |

- `0–39` → ✅ SAFE
- `40–69` → ⚠️ SUSPICIOUS
- `70–100` → 🚨 MALICIOUS

---

## 🔍 Static Analysis Indicators

| Indicator | Points |
|---|---|
| IP address in URL | 30 |
| Typosquatting pattern | 30 |
| Suspicious TLD (.tk, .ml, .xyz) | 25 |
| Excessive subdomains | 20 |
| @ symbol in URL | 20 |
| Double slash in path | 15 |
| URL length > 75 chars | 15 |
| HTTP (no HTTPS) | 10 |
| Hex encoding | 10 |
| Suspicious keyword | 5 each |

---

## 📁 Project Structure

```
ai-phishing-scanner/
├── phishing_scanner.py
├── requirements.txt
├── .env.example
├── .gitignore
├── scan_history.json     # auto-generated
└── README.md
```

---

## 🔐 Security Notes

- Scanner **never visits** the target URL
- URLs are sent to VirusTotal and your chosen LLM only
- Do not scan confidential or internal URLs

---

## 🐛 Common Issues

| Issue | Fix |
|---|---|
| `VIRUSTOTAL_API_KEY not found` | Check `.env` exists, no spaces around `=` |
| `pip is not recognized` | Use `python -m pip install -r requirements.txt` |
| `Rate limit exceeded` | Wait 1 min (VT free tier: 4 req/min) |
| `No compatible Gemini model found` | Check `GOOGLE_API_KEY` is valid |

---

## 📄 License

MIT License

---

Made with 🔍 by **Praharsh Kumar**
[LinkedIn](https://linkedin.com/in/praharshkumar23) · [GitHub](https://github.com/praharshkumar23)
