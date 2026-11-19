# 🛡️ Vigía

> Lightweight attack detection platform for small businesses, with built-in purple team validation.

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.15-blue)
![React](https://img.shields.io/badge/react-typescript-61dafb)

---

## 🚨 The Problem

Small and medium businesses run public websites, APIs and servers, but they can't afford a Security Operations Center (SOC) or enterprise SIEM tools like Splunk or QRadar. Their logs are generated every day and **nobody reads them**. As a result, brute-force attempts, SQL injection probes and vulnerability scans go unnoticed until real damage is done.

## 💡 The Solution

**Vigía** ingests server and application logs, detects common attack patterns in real time, maps every alert to the **MITRE ATT&CK** framework and presents everything in a clean, actionable dashboard.

What makes Vigía different is its **purple team approach**: the repository ships with an attack simulation module that emulates real adversary techniques against a lab environment, so every detection rule is **proven to work**, not just assumed to.

## ✨ MVP Features

1. **Log ingestion**: upload or stream nginx access logs, Linux SSH auth logs (`auth.log`) and JSON application logs through a REST API.
2. **Detection engine**: rules written in YAML (Sigma-inspired), easy to read, version and extend.
3. **MITRE ATT&CK mapping**: each alert is tagged with its tactic and technique ID (e.g. `T1110.001`).
4. **Alert dashboard**: filter alerts by severity, source IP, technique and time range.
5. **Purple team validation**: attack simulation scripts plus a detection coverage report showing which techniques are detected.

## 🏗️ Architecture

flowchart LR
  A[Log sourcesnginx / SSH / apps] --> B[Ingestion APIFastAPI]
  B --> C[(PostgreSQL)]
  B --> D[Detection EngineYAML rules]
  D --> C
  C --> E[DashboardReact + TS]
  F[attack-simRed team scripts] -.validates.-> D

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.15, FastAPI, SQLAlchemy |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Database | PostgreSQL |
| Detection rules | YAML (Sigma-inspired) |
| Attack simulation | Python scripts in an isolated Docker lab |
| DevOps | Docker Compose, GitHub Actions |

## 📁 Project Structure

vigia/
├── backend/       # FastAPI ingestion API and detection engine
├── frontend/      # React + TypeScript dashboard
├── attack-sim/    # Red team: controlled attack emulation scripts
├── detections/    # Blue team: YAML detection rules
└── docs/          # Threat model, architecture and design decisions

## 🗺️ Roadmap

- [x] **Phase 0** – Project structure, documentation and threat model
- [ ] **Phase 1** – Backend: log ingestion API and database models
- [ ] **Phase 2** – Detection engine and first rules (brute force, SQLi)
- [ ] **Phase 3** – Attack simulation lab with Docker
- [ ] **Phase 4** – React dashboard with authentication
- [ ] **Phase 5** – MITRE ATT&CK coverage report
- [ ] **Phase 6** – CI/CD, tests and security scanning (SAST, dependency audit)
- [ ] **Phase 7** – Public demo deployment

## 🚀 Getting Started (backend preview)

```bash
cd backend
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\activate
# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000/docs` for the interactive API docs.

Log ingestion example (PowerShell):

```powershell
$body = @'
{"source": "ssh", "level": "warning", "message": "Failed password for root from 203.0.113.5", "source_ip": "203.0.113.5"}
'@
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/logs -Method Post -ContentType "application/json" -Body $body
```

## ⚠️ Ethical Use

The `attack-sim/` module is intended **only** for authorized testing in the provided isolated lab or on systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal.

## 📄 License

This project is licensed under the [MIT License](LICENSE).