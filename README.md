# AI Security Log Analyzer

An AI-powered cybersecurity application that analyzes security logs, detects suspicious activity, extracts Indicators of Compromise (IOCs), and generates AI-powered security insights.

## 🚀 Features

* Security log analysis
* Brute-force attack detection
* Port-scan detection
* Suspicious login detection
* Possible account-compromise detection
* IP, domain, URL, and hash extraction
* Gemini AI security analysis
* SQLite analysis history
* Interactive cybersecurity dashboard

## 🛠️ Technologies

* Python
* FastAPI
* SQLAlchemy
* SQLite
* Google Gemini AI
* HTML
* CSS
* JavaScript

## 🔄 How It Works

```text
Security Log
     ↓
Log Parser
     ↓
Threat Detection
     ↓
IOC Extraction
     ↓
Gemini AI Analysis
     ↓
SQLite Database
     ↓
Security Dashboard
```

## 📁 Project Structure

```text
AI_Security_Log_Analyzer/
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── analyzer.py
├── database.py
├── detector.py
├── ioc.py
├── main.py
├── model.py
├── parser.py
├── schemas.py
├── requirements.txt
├── .gitignore
└── README.md
```

## ▶️ Installation

```bash
git clone https://github.com/your-username/AI_Security_Log_Analyzer.git
cd AI_Security_Log_Analyzer

python -m venv venv
```

Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file:

```env
GEMINI_API_KEY=your_api_key_here
```

Start the application:

```bash
uvicorn main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## 🎯 Purpose

This project demonstrates practical skills in **backend development, cybersecurity, threat detection, IOC analysis, AI integration, database management, and frontend/backend development**.
