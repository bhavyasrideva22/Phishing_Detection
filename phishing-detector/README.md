# 🛡 PhishDetect AI — Phishing Email Detection System

An AI-powered phishing email detection system with a professional web dashboard, machine learning threat scoring, SOC-style alerts, and full scan history.

---

## ✅ Features

- **Login & Registration** — secure SQLite3 user accounts with hashed passwords
- **Theme Toggle** — dark and light mode (persisted)
- **3 Input Methods** — text input, email paste, file/image upload (.eml, .txt, .jpg, .png, etc.)
- **ML-Based Detection** — Naive Bayes classifier trained on phishing/safe examples
- **URL Analysis** — detects malicious URLs, IP addresses, URL shorteners, suspicious TLDs, typosquatting
- **Keyword Detection** — 40+ phishing keywords scanned
- **Risk Score** — 0–100 score with Safe / Suspicious / Phishing classification
- **SOC Alerts** — real-time alert bar on scan results
- **Dashboard** — stats overview, donut chart, recent scans
- **Scan History** — full history with date/time, stored in SQLite
- **Scan Detail Modal** — click any past scan to review full results
- **Report Download** — generate and download TXT security reports

---

## 🚀 Installation

### 1. Install Python 3.11+
https://www.python.org/downloads/

### 2. Create Virtual Environment
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Database
```bash
python setup.py
```

### 5. Run the App
```bash
python app.py
```

Open: **http://localhost:5000**

**Demo credentials:** `admin` / `admin123`

---

## 📁 Project Structure

```
phishing-detector/
├── app.py              # Flask application (routes)
├── parser_module.py    # Email content parser (regex)
├── scanner.py          # URL analysis + risk scoring
├── model.py            # ML model (Naive Bayes)
├── database.py         # SQLite3 database operations
├── report_generator.py # TXT report generation
├── setup.py            # First-time setup script
├── requirements.txt    # Python dependencies
├── templates/
│   ├── login.html      # Login / Register page
│   └── index.html      # Main dashboard
├── reports/            # Generated reports (auto-created)
└── logs/               # Log files (auto-created)
```

---

## 🎯 How It Works

1. User logs in → Dashboard shows scan stats
2. User submits email (text / paste / file)
3. Parser extracts URLs, emails, suspicious words
4. URL Scanner checks each URL for 10+ threat signals
5. ML Model predicts phishing vs safe
6. Risk Engine calculates 0–100 score
7. Result displayed with SOC alert, indicators, URL list
8. Scan saved to SQLite with timestamp
9. History page shows all past scans with click-to-review

---

## 📊 Risk Score Guide

| Score | Threat Level |
|-------|-------------|
| 0–30  | ✅ SAFE      |
| 31–60 | ⚡ SUSPICIOUS |
| 61+   | 🚨 PHISHING  |

---

## 🔬 Technologies

| Area | Technology |
|------|-----------|
| Backend | Python + Flask |
| Frontend | HTML + CSS + JavaScript |
| ML | Scikit-learn (MultinomialNB) |
| Database | SQLite3 |
| Security | Regex, URL analysis, tldextract |

---

## 📄 Resume Description

> Developed an AI-powered phishing email detection system using Python, Flask, and Naive Bayes machine learning to analyze suspicious URLs, phishing indicators, and email content with automated risk scoring, SOC-style alert generation, scan history logging in SQLite3, and professional web dashboard with dark/light theme.

---

## 📸 Pages

- **Login Page** — sign in or register
- **Dashboard** — overview stats + quick scan + donut chart + recent scans
- **Scan Email** — full analysis with text/file/email input
- **Scan History** — all past scans with click-to-review modal

---

Built with ❤️ for cybersecurity learning and SOC internship portfolios.
