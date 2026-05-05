# 📖 How to Use — AI Phishing Link Scanner v2.0

A complete step-by-step guide to setting up and running the scanner from scratch.

---

## 🖥️ Step 1 — Check Python is Installed

Open your terminal or command prompt and run:

```bash
python --version
```

You should see something like `Python 3.10.0` or higher.

If Python is not installed, download it from:
👉 https://www.python.org/downloads/

⚠️ During installation on Windows, check the box that says **"Add Python to PATH"**.

---

## 📥 Step 2 — Download the Project

### Option A — Clone from GitHub (recommended)

```bash
git clone https://github.com/praharshkumar23/AI-Phishing-Scanner-v2.git
cd AI-Phishing-Scanner-v2
```

### Option B — Download ZIP

1. Go to the GitHub repository page.
2. Click the green **Code** button.
3. Click **Download ZIP**.
4. Extract the folder.
5. Open the extracted folder in your terminal.

---

## 🧪 Step 3 — Create a Virtual Environment

A virtual environment keeps your project dependencies separate from your main Python installation.

```bash
python -m venv venv
```

### Activate the virtual environment

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

You'll see `(venv)` at the start of your terminal line when it's active.

---

## 📦 Step 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all required packages:
- `requests` — for API calls
- `python-dotenv` — to load your API keys from `.env`
- `colorama` — for color output in terminal
- `google-generativeai` — for Gemini AI integration
- `openai` — for OpenAI integration

### Verify installation

```bash
pip list
```

You should see all 5 packages listed.

---

## 🔑 Step 5 — Get Your API Keys

You need at least 2 API keys to run the scanner:

### 1. VirusTotal API Key (Required)

1. Go to → https://www.virustotal.com/gui/join-us
2. Create a free account.
3. After logging in, click your profile icon (top right).
4. Click **API Key**.
5. Copy the key.

### 2. Google Gemini API Key (Recommended — Free)

1. Go to → https://aistudio.google.com/app/apikey
2. Sign in with your Google account.
3. Click **Create API Key**.
4. Copy the key.

### 3. OpenAI API Key (Alternative to Gemini)

1. Go to → https://platform.openai.com/api-keys
2. Sign in or create account.
3. Click **Create new secret key**.
4. Copy and save it — it's shown only once.

### 4. AbuseIPDB API Key (Optional)

Used only when the URL contains an IP address directly.

1. Go to → https://www.abuseipdb.com/register
2. Create a free account.
3. Go to **API** in your dashboard.
4. Copy the key.

---

## ⚙️ Step 6 — Create Your .env File

Copy the template:

**Windows:**
```bash
copy .env.example .env
```

**Linux / macOS:**
```bash
cp .env.example .env
```

Open `.env` and paste your keys:

```ini
# VirusTotal API Key (required)
VIRUSTOTAL_API_KEY=paste_your_virustotal_key_here

# AbuseIPDB API Key (optional)
ABUSEIPDB_API_KEY=paste_your_abuseipdb_key_here

# LLM Provider — write either: gemini or openai
LLM_PROVIDER=gemini

# Google Gemini Key
GOOGLE_API_KEY=paste_your_gemini_key_here

# OpenAI Key (leave blank if using Gemini)
OPENAI_API_KEY=
```

Save the file.

⚠️ Never share this file. Never push it to GitHub.
It is already listed in `.gitignore` so it won't be committed.

---

## 🚀 Step 7 — Run the Scanner

### Single URL scan

```bash
python phishing_scanner.py "https://www.google.com"
```

### Interactive mode (recommended for beginners)

```bash
python phishing_scanner.py
```

You'll see a menu:

```
  OPTIONS
  1  Scan a single URL
  2  Batch scan (multiple URLs)
  3  View scan history
  q  Quit
```

Type `1` and press Enter, then enter your URL when asked.

---

## 🗂️ Step 8 — Batch Scan Multiple URLs

Select option `2` from the interactive menu.

Enter URLs one by one:

```
  URL 1 > https://www.google.com
  URL 2 > http://amaz0n-verify.tk/login
  URL 3 > https://paypal.com
  URL 4 > (press Enter to start scanning)
```

The scanner processes each URL one by one and prints a report for each.

---

## 💾 Step 9 — Save and Export Reports

After every scan, you'll be asked:

```
Save report to JSON? (y/n) >
```

Type `y` to save. The file is saved as:

```
scan_report_20260505_180000.json
```

This JSON file contains the full scan result including:
- URL scanned
- Timestamp
- Static analysis details
- VirusTotal verdict
- AbuseIPDB result
- AI analysis with MITRE technique
- Final verdict and risk score

---

## 📜 Step 10 — View Scan History

Select option `3` from the interactive menu to see the last 20 scans:

```
SCAN HISTORY (15 scans)
2026-05-05 18:00:00  SAFE         Risk:  2/100  https://www.google.com
2026-05-05 18:02:00  MALICIOUS    Risk: 87/100  http://amaz0n-verify.tk/login
2026-05-05 18:04:00  SUSPICIOUS   Risk: 52/100  http://free-gift-claim.xyz
```

History is stored in `scan_history.json` automatically.

---

## ✅ You're Done

You can now:
- Scan any URL for phishing indicators
- Run batch scans
- Export reports as JSON
- View your scan history
- Share results with your team

---

## ❓ Common Errors and Fixes

| Error | Fix |
|---|---|
| `VIRUSTOTAL_API_KEY not found` | Check `.env` exists and key is correct |
| `No compatible Gemini model found` | Check your Gemini API key is valid |
| `pip is not recognized` | Run `python -m pip install -r requirements.txt` |
| `Rate limit exceeded` | Wait 1 minute and retry (VT free: 4 req/min) |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again |
| `KeyboardInterrupt` | Press Ctrl+C to stop the scanner at any time |

---

## 💡 Tips

- Always activate your virtual environment before running the scanner.
- Use Gemini if you want a free AI option.
- The scanner never visits the URL — safe to scan any suspicious link.
- Export your reports as JSON for documentation or sharing with your team.
