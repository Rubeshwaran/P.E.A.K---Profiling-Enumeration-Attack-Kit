# P.E.A.K.
**Proactive Engine for Assessment & Knowledge**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![Status](https://img.shields.io/badge/Status-Active-success)

> **"The Ultimate Command Center for Modern Offensive Security."**

**P.E.A.K.** is an AI-powered Offensive Security Orchestration platform that unifies your entire pentesting toolkit into one "Cyberpunk" interface. It replaces disjointed CLI scripts with a fully automated, intelligent pipeline.

### 🚧 Project Status: Under Active Development
**This project is currently in Beta (v3.0).**
We are actively building and integrating new modules daily. Expect frequent updates as we add full automation for Nmap, Burp Suite, and advanced reporting capabilities.

![PEAK Login -v3.0]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/186e9f79-b87f-4e7d-9f2e-13943a7a5396" />

![PEAK Register -v3.0]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/fded48d4-d1ff-427a-a7c9-931d1e755c19" />

![PEAK Dashboard -v3.0]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/271be901-3920-4464-94c8-fd316884817b" />

![PEAK Dashboard - Web]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/22101fad-7c15-44db-b192-b42d3ae6a940" />

![PEAK Dashboard -Mobile Lab]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/7aa2ba08-b93b-49b5-b369-e823be86a4cd" />

![PEAK Dashboard -Android Emulator]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/8743be77-eef5-4943-a136-1e2c7a39f586" />

![PEAK Dashboard -iOS Bridge]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/87b9eb6e-d39a-4df2-b70b-92f25c2a6003" />

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
```
**3. Setup AI (Ollama)**
P.E.A.K requires a local LLM to generate attack plans. Open a terminal and run:
```bash
ollama pull phi3
ollama serve
```
**4. Configuration**

1.Rename config.example.py to config.py.
2.Open config.py in a text editor.
3.Add your API keys (MobSF, Shodan, etc.).

**5. Launch**
```bash
python app.py
```
Access the dashboard at: http://localhost:5000

---

**🙏 Acknowledgements & Credits**

Special thanks to OWASP VISTO for the foundational concepts and inspiration behind this project. The architecture of PEAK builds upon the ideas pioneered by the VISTO framework to make security orchestration accessible and visual.

---

**⚠️ Legal Disclaimer**

FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY.

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
