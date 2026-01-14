# P.E.A.K.
**Proactive Engine for Assessment & Knowledge**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![Status](https://img.shields.io/badge/Status-Active-success)

> **"The Ultimate Command Center for Modern Offensive Security."**

**P.E.A.K.** is an AI-powered Offensive Security Orchestration platform that unifies your entire pentesting toolkit into one "Cyberpunk" interface. It replaces disjointed CLI scripts with a fully automated, intelligent pipeline.

![PEAK Dashboard]<img width="900" height="428" alt="PEAK" src="https://github.com/user-attachments/assets/ec479023-cf6a-4669-9072-5345852385f4" />
)

(Note: Client data in screenshots has been redacted for confidentiality)
---

## ⚡ Key Capabilities

### 1. Fully Automated Arsenal
Stop manually running scripts. PEAK orchestrates the industry's heaviest hitters with one click:
- **Nmap Automation:** Full infrastructure scanning, port discovery, and service versioning running in the background.
- **Burp Suite Integration:** Headless orchestration for automated web crawling and vulnerability scanning.
- **MobSF Pipeline:** Drag-and-drop static analysis for Android (`.apk`) and iOS (`.ipa`) binaries.

### 2. 🧠 P.E.A.K. Intelligence (AI Agent)
- **Active Reconnaissance:** Automatically probes targets for sensitive exposures (e.g., `.git`, `.env`, Admin Panels).
- **Tech Stack Fingerprinting:** Instantly identifies CMS (WordPress, Drupal) and Frameworks (Django, React).
- **AI Attack Planner:** Utilizes **Phi-3 (via Ollama)** to analyze findings and generate specific, executable attack commands (e.g., `sqlmap -u...`, `wpscan...`).
- **One-Click Reporting:** Export full intelligence reports to CSV for client delivery.

### 3. 🖥️ The Command Center
Perform all your work from a single, powerful UI:
- **Glassmorphism Design:** A reactive, dark-mode interface built for speed and focus.
- **Terminal Console:** Integrated shell for manual command overrides.
- **Project Isolation:** Manage multiple client engagements with separate databases and history.

---
## 📋 Prerequisites

Before installing P.E.A.K, ensure the following are available on your system:

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **Ollama** (Required for AI Attack Planner)

---
## 🛠️ Installation & Setup

### 1. Prerequisites
- [Python 3.10+](https://www.python.org/)
- [Ollama](https://ollama.com/) (Required for AI Attack Planner)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
