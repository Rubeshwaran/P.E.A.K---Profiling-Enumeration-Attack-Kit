![License](https://img.shields.io/badge/License-MIT-yellow.svg)

# P.E.A.K.
**Proactive Engine for Assessment & Knowledge**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![Status](https://img.shields.io/badge/Status-Active-success)

> **"The Ultimate Command Center for Modern Offensive Security."**

**P.E.A.K.** is an AI-powered Offensive Security Orchestration platform that unifies your entire pentesting toolkit into one interface. It replaces disjointed CLI scripts with a fully automated, intelligent pipeline — from reconnaissance to reporting.


### 🚧 Project Status: Under Active Development
**This project is currently in Beta (v3.1).**
We are actively building and integrating new modules. Expect frequent updates as we add full automation for scanning, AI test planning, and advanced reporting capabilities.

![PEAK Login -v3.0]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/186e9f79-b87f-4e7d-9f2e-13943a7a5396" />

![PEAK Register -v3.0]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/fded48d4-d1ff-427a-a7c9-931d1e755c19" />

![PEAK Dashboard -v3.0]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/271be901-3920-4464-94c8-fd316884817b" />

![PEAK Dashboard - Web]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/2fbb48c6-85d5-4e56-abbb-b659f7492cd6" />

![PEAK Dashboard - AI Test Plan]<img width="900" height="428" alt="AI Test Plan" src="https://github.com/user-attachments/assets/fe84688d-0650-402e-918f-923db837917c" />

![PEAK Dashboard - Admin Panel]<img width="900" height="428" alt="Admin" src="https://github.com/user-attachments/assets/29e1dba8-e7ea-4220-9821-1f80dcfade29" />

![PEAK Dashboard -Mobile Lab]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/7aa2ba08-b93b-49b5-b369-e823be86a4cd" />

![PEAK Dashboard -Android Emulator]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/8743be77-eef5-4943-a136-1e2c7a39f586" />

![PEAK Dashboard -iOS Bridge]<img width="900" height="428" alt="image" src="https://github.com/user-attachments/assets/87b9eb6e-d39a-4df2-b70b-92f25c2a6003" />

---

## ⚡ Key Capabilities

**1.🌐 Web Operations**
   
A comprehensive suite designed for speed and depth in web application security.

- **AI Threat Profiling** — Automatically fingerprints targets, detects technology stacks, and builds threat profiles with risk ratings
- **AI Test Plan Engine** — Generates 80+ security tests across 11 OWASP WSTG categories with per-category AI analysis, executable commands, and evidence-based rationale
- **Burp Suite Integration**— Import Burp Professional HTML scan reports with full finding extraction (severity, description, remediation, affected URLs)
- **OWASP ZAP Integration**— REST API bridge for active scanning, spider crawling, and JSON/HTML report import
- **Findings Board** — Consolidated findings from all tools with severity filtering, deduplication, AI interpretation, and PDF/CSV export
- **Live Scan Feed** — Real-time SSE streaming with category-by-category progress during AI analysis
- **Active Reconnaissance** — Automated discovery of subdomains, exposed assets, and technology stacks
- **Archive Mining** — Instant retrieval of historical data and hidden endpoints


**2. 📱 Android Laboratory (Turbo)**
   
A zero-latency Android environment embedded directly into your dashboard.

- **High-Performance Streaming:** Experience 60 FPS real-time video control of emulated devices.
- **Instant Deployment:** Simply drag & drop any APK onto the screen to install it immediately.
- **Tool Suite:** One-click execution of advanced testing scripts, bypassing security controls, and runtime analysis.
- **Static Analysis:** Automatic security scoring and report generation for mobile binaries.

**3. 🍎 iOS Bridge (Physical)**
   
NEW in v3.1: Seamless integration with physical iPhone hardware.

- **Hardware Bridge:** Connect your physical iOS device via USB and control it remotely from the dashboard.
- **Live Stream:** View and interact with your iPhone screen in real-time.
- **Hybrid Connectivity:** Automatically manages complex tunnel connections to support modern iOS versions.

**4. 🧠 P.E.A.K. Intelligence (AI Agent)**
   
- **AI Attack Planner**: An embedded AI assistant that analyzes findings and generates actionable attack strategies with PoC scripts
- **Context-Aware**: The agent automatically detects your current workspace (Web vs. Mobile) and tailors its advice to your active mission
- **Per-Category WSTG Analysis:** Generates tests across Information Gathering, Authentication, Authorization, Session Management, Input Validation, Cryptography, Business Logic, and more
- **Technology-Specific Suites**: Detects frameworks (WordPress, Django, React, Angular, etc.) and adds targeted security tests
- **Sector-Specific Tests**: Automatically adds banking, e-commerce, healthcare, or government-specific checks based on application content

**5. RBAC & Admin Panel `NEW in v3.1`**

- **Role-Based Access Control** — Admin and User roles with appropriate permissions
- **User Management** — Create, edit, disable, and manage team member accounts
- **Audit Logging** — Track login attempts, user changes, and data imports
- **Session Tracking** — Last login timestamps and active session management
---
## Architecture
 
```
┌─────────────────────────────────────────────────────────┐
│                     PEAK Platform                        │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │  AI      │  │  Burp    │  │  ZAP     │  │  Admin  │ │
│  │  Engine  │  │  Import  │  │  Bridge  │  │  Panel  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│       │              │              │              │      │
│  ┌────┴──────────────┴──────────────┴──────────────┴────┐│
│  │              Flask Backend (app.py)                    ││
│  │         SQLite · Gunicorn/gevent · SSE                ││
│  └───────────────────────┬──────────────────────────────┘│
│                          │                                │
│  ┌───────────────────────┴──────────────────────────────┐│
│  │          Dashboard (Single-Page Application)          ││
│  │    Findings Board · Test Plan · Live Feed · Chat      ││
│  └──────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
          │                    │
    ┌─────┴─────┐        ┌────┴────┐
    │  Ollama   │        │  Burp/  │
    │  (LLM)    │        │  ZAP    │
    └───────────┘        └─────────┘
```
 
---
## Features
 
### AI-Powered Test Plan
 
When you enter a target URL and click **AI ENGAGE**, PEAK:
 
1. **Probes** the target (HTTP headers, cookies, server fingerprint)
2. **Crawls** via ZAP spider (if connected)
3. **Fingerprints** technology stack and application type
4. **Generates** a per-category test plan across 11 WSTG categories:
   - Information Gathering, Configuration & Deployment, Identity Management
   - Authentication, Authorization, Session Management, Input Validation
   - Error Handling, Cryptography, Business Logic, Client-Side Testing
5. **Adds** technology-specific tests for detected frameworks
6. **Adds** sector-specific tests (banking, e-commerce, healthcare, etc.)
 
Each test includes: priority, description, rationale citing evidence, approach with executable commands, and estimated time.
 
### Live Scan Feed
 
Real-time SSE streaming shows progress during AI analysis:
```
🎯 Starting AI threat profiling for https://target.com
📡 Probing target — HTTP headers, server, cookies...
🧪 [1/11] Analysing Information Gathering (10 tests)...
✓ Information Gathering: 10 applicable / 0 N/A
🧪 [2/11] Analysing Configuration & Deployment Management (12 tests)...
✓ Configuration: 6 applicable / 6 N/A
...
✅ Test plan complete — 52 applicable tests
```
 
### Findings Board
 
Consolidated view of all findings from Burp, ZAP, and AI scanning:
- Severity badges (Critical, High, Medium, Low, Info)
- CVSS scores and CWE references
- One-click export to PDF/CSV
- AI interpretation for each finding
- Reproduce via ZAP integration
 
### Admin Panel & RBAC
 
- **Admin** role: full access including user management
- **User** role: standard pentest access
- User management with create/edit/disable/audit log
- Session tracking with last login timestamps
- First user is automatically promoted to Admin
 
---
 

## 📋 Prerequisites

Before installing P.E.A.K, ensure the following are available on your system:

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **Ollama** (Required for AI Attack Planner)
- **OWASP ZAP**(Optional — for active scanning)
- **Burp Suite Professional** (Optional — for scan report import)


---
### Installation
 
```bash
# Clone the repository
git clone https://github.com/nusummit/peak.git
cd peak
 
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
 
# Install dependencies
pip install -r requirements.txt
 
# Configure environment
cp .env.example .env
nano .env   # Update with your settings
 
# Initialize database (auto-created on first run)
mkdir -p data
 
# Start the server
gunicorn -k gevent -w 2 -b 0.0.0.0:5000 app:app --timeout 300
```
 
### First Login
 
1. Navigate to `http://YOUR_IP:5000`
2. On first run, you'll be prompted to create an **Admin** account
3. After login, you land directly on the Dashboard
4. Additional users are created through **Admin Panel → User Management**
 
---
 
## Configuration
 
### AI Backend (Ollama)
 
PEAK uses Ollama as the primary AI backend. Set up your model:
 
```bash
# Install and start Ollama
ollama serve
 
# Pull a model (recommended: llama3.2 or larger)
ollama pull llama3.2
 
# Update .env
OPENAI_API_BASE=http://localhost:11434/v1
CAI_MODEL=llama3.2
```

## Project Structure
 
```
PEAK/
├── app.py                    # Main application (~12,000 lines)
│                              # Flask routes, AI engine, Burp/ZAP parsers,
│                              # RBAC, test plan generator, SSE streaming
├── templates/
│   ├── dashboard.html        # Main dashboard SPA (~6,000 lines)
│   │                          # Findings board, test plan modal, live feed,
│   │                          # AI chat, import/export, admin link
│   ├── login.html            # Login page (NuSummit branding)
│   ├── register.html         # First-user setup only
│   └── admin_users.html      # User management panel
├── data/
│   └── peak.db               # SQLite database (auto-created)
├── .env                      # Environment config (not in repo)
├── .env.example              # Environment template
├── .gitignore
├── requirements.txt
└── README.md
```
 
---
 
## API Endpoints
 
### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | User login |
| GET | `/logout` | User logout |
| GET | `/register` | First-user setup (redirects to admin if users exist) |
 
### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | Main dashboard |
| POST | `/create_project` | Create new pentest project |
 
### AI Engine
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/web/fingerprint/stream` | SSE — AI threat profiling with live progress |
| GET | `/api/web/pentest/stream` | SSE — Pentest execution stream |
| GET | `/api/cai/status` | AI backend health check |
| POST | `/api/cai/config` | Update AI backend config |
 
### Findings
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/import/burp` | Import Burp HTML report |
| POST | `/api/import/zap` | Import ZAP JSON/HTML report |
| POST | `/api/web/findings/save` | Persist findings to database |
| GET | `/api/web/findings/load` | Load previous scan findings |
 
### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/users` | User management panel |
| GET | `/api/admin/users` | List all users |
| POST | `/api/admin/users` | Create user |
| PATCH | `/api/admin/users/<id>` | Update user role/status |
| DELETE | `/api/admin/users/<id>` | Deactivate user |
| GET | `/api/admin/audit` | Audit log |
 
---
 
## Security Considerations
 
- All routes require authentication (except `/login` and first-user `/register`)
- Passwords hashed with Werkzeug's `generate_password_hash` (PBKDF2)
- Session-based auth with Flask's signed cookies
- Admin-only routes protected by `@admin_required` decorator
- Audit logging for login attempts, user changes, and data imports
- No default credentials — first user creates their own admin account
 
---


**📝 Changelog**

v3.1 (Current)

- AI Test Plan Engine — Per-category WSTG analysis (11 categories, 80+ tests) with live SSE progress
- Burp Suite HTML Import — Full Burp Professional report parser with severity, description, remediation extraction
- OWASP ZAP Import — JSON and HTML report import with finding deduplication
- Findings Board — Consolidated view with severity filtering, AI interpretation, and auto-save
- RBAC & Admin Panel — Role-based access, user management, audit logging
- Live Scan Feed — Real-time category-by-category progress during AI analysis
- Stop Scan — Abort running AI Engage or Launch Scan at any time
- Login → Dashboard — Direct navigation, no hub page
- Professional UI — Redesigned login page

v3.0

- Initial release with Web Operations, Android Laboratory, iOS Bridge
- AI Attack Planner with context-aware workspace detection
- Mobile static analysis and security scoring

---


**🙏 Acknowledgements & Credits**

Special thanks to OWASP VISTO for the foundational concepts and inspiration behind this project. The architecture of PEAK builds upon the ideas pioneered by the VISTO framework to make security orchestration accessible and visual.

---

**⚠️ Legal Disclaimer**

FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY.

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
