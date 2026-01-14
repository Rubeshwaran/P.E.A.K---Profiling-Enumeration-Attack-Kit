# 🏔️ P.E.A.K.
**Proactive Engine for Assessment & Knowledge**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![Status](https://img.shields.io/badge/Status-Active-success)

**P.E.A.K.** is an AI-powered Offensive Security Orchestration platform designed for the modern red teamer. It unifies active reconnaissance, static mobile analysis, and LLM-driven attack planning into a single "Cyberpunk" Command Center.

## 🚀 Key Capabilities

### 🧠 P.E.A.K. Intelligence
- **Active Profiling:** Probes targets for sensitive exposures (`.git`, `.env`, Admin Panels).
- **Tech Stack Fingerprinting:** Identifies CMS, Frameworks, and Server technologies.
- **AI Attack Planner:** Utilizes **Phi-3 (via Ollama)** to generate specific, executable attack commands (e.g., `sqlmap`, `wpscan`) based on real-time findings.
- **CSV Export:** Generate instant intelligence reports.

### 📱 Mobile Ops (MobSF)
- **Static Analysis:** Automated scanning of `.apk` and `.ipa` files.
- **Vulnerability Scoring:** Auto-calculates security scores and extracts critical permissions/misconfigurations.

### 🖥️ Command Center
- **Glassmorphism UI:** A reactive, dark-mode interface built with Tailwind CSS.
- **Terminal Console:** Integrated shell for manual command execution.
- **Role-Based Access:** Secure Login & Registration system with 2FA support.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
You must have [Python](https://www.python.org/) and [Ollama](https://ollama.com/) installed.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
