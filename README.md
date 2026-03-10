<div align="center">

# 🛡️ SafeWeb AI

### Enterprise-Grade Web Application Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.0+-092E20?style=for-the-badge&logo=django&logoColor=white)](https://djangoproject.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![License](https://img.shields.io/badge/License-University_Project-orange?style=for-the-badge)]()

**A professional cybersecurity SaaS platform that combines 60+ security tools, 87+ vulnerability testers, 37 reconnaissance modules, and AI-powered analysis into a unified scanning engine with real-time results.**

[Features](#-features) • [Architecture](#-architecture) • [Installation](#-installation) • [API Reference](#-api-reference) • [Scanning Engine](#-scanning-engine) • [Screenshots](#-screenshots)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Project Structure](#-project-structure)
- [Scanning Engine](#-scanning-engine)
- [AI Chatbot Assistant](#-ai-chatbot-assistant)
- [API Reference](#-api-reference)
- [Frontend Pages](#-frontend-pages)
- [Component Library](#-component-library)
- [Security Tools](#-security-tools)
- [Deployment](#-deployment)
- [Design System](#-design-system)
- [Team](#-team)

---

## ✨ Features

### Core Scanning
- **87+ Vulnerability Testers** — SQL injection, XSS, SSRF, SSTI, command injection, IDOR, JWT attacks, GraphQL exploitation, and 80+ more
- **37 Reconnaissance Modules** — DNS enumeration, subdomain discovery, technology fingerprinting, WAF detection, cloud storage scanning, threat intelligence
- **60+ Integrated Security Tools** — Nmap, Nuclei, SQLMap, FFUF, Subfinder, Amass, WhatWeb, and more with custom wrappers
- **Real-Time SSE Streaming** — Live scan progress updates via Server-Sent Events
- **Multi-Scope Scanning** — Single domain, wildcard, and wide-scope modes
- **3 Scan Depths** — Shallow, medium, and deep analysis levels
- **Scan Comparison** — Side-by-side diff of two scans to track remediation progress

### AI-Powered Intelligence
- **LLM Chat Assistant** — OpenRouter-powered chatbot (Gemini 2.0 Flash) with 36-entry knowledge base
- **7 Action Tools** — Start scans, check status, export reports, navigate — all from chat
- **Scan-Aware Context** — Auto-detects scan context from URL, provides vulnerability-specific advice
- **ML Models** — Malware detection, phishing analysis, and anomaly detection with confidence scoring
- **LLM Attack Strategy** — AI-generated testing strategies based on reconnaissance findings

### Platform Features
- **JWT Authentication** — Email/password + Google OAuth + 2FA (TOTP with QR code)
- **Role-Based Access** — User, Admin roles with plan-based feature gating
- **Subscription Tiers** — Free (5 scans/month), Pro, Enterprise with graduated feature access
- **Scheduled Scans** — Hourly, daily, weekly, monthly, or custom cron scheduling
- **Webhook Notifications** — Real-time alerts on scan completion to external services
- **Asset Inventory** — Automatic tracking of discovered assets across scans
- **Export Formats** — PDF, CSV, JSON, SARIF, HTML report generation
- **Nuclei Templates** — Custom and community template management
- **Admin Dashboard** — User management, system stats, scan analytics, ML model monitoring, chat analytics
- **Learning Center** — 9-category cybersecurity article library

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (React 18)                   │
│  Vite + TypeScript + TailwindCSS + React Router v6      │
│  28 pages · 30+ components · SSE streaming · JWT auth   │
├─────────────────────────────────────────────────────────┤
│                         ↕ REST API (Axios)              │
├─────────────────────────────────────────────────────────┤
│                  BACKEND (Django 5 + DRF)                │
│  6 Django apps · JWT auth · Rate limiting · CORS        │
├──────────┬──────────┬───────────┬───────────┬───────────┤
│ accounts │ scanning │  chatbot  │    ml     │   learn   │
│  (auth)  │ (engine) │   (AI)    │ (models)  │ (articles)│
├──────────┴──────────┴───────────┴───────────┴───────────┤
│                    TASK QUEUE (Celery)                   │
│  Redis broker · Async scan execution · Tool registry    │
├─────────────────────────────────────────────────────────┤
│               SCANNING ENGINE (7 Phases)                │
│  37 recon modules → crawler → 87+ testers → ML verify  │
│  60+ tool wrappers · SecLists payloads · Nuclei engine  │
├─────────────────────────────────────────────────────────┤
│                  AI / ML LAYER                          │
│  OpenRouter LLM · scikit-learn · XGBoost · Function     │
│  calling · Knowledge base · Action registry             │
├─────────────────────────────────────────────────────────┤
│              INFRASTRUCTURE                             │
│  PostgreSQL (prod) · SQLite (dev) · Redis · Railway     │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠 Tech Stack

### Backend
| Technology | Purpose |
|:-----------|:--------|
| **Python 3.11+** | Core language |
| **Django 5.0** | Web framework |
| **Django REST Framework** | API layer |
| **Celery 5.3** | Async task queue |
| **Redis** | Message broker & cache |
| **PostgreSQL** | Production database |
| **SimpleJWT** | JWT authentication |
| **OpenAI SDK** | LLM integration (OpenRouter) |
| **scikit-learn / XGBoost** | ML models |
| **Playwright** | Browser automation for JS-heavy targets |
| **BeautifulSoup4 / lxml** | HTML parsing |
| **ReportLab** | PDF report generation |
| **Gunicorn** | WSGI HTTP server |

### Frontend
| Technology | Purpose |
|:-----------|:--------|
| **React 18** | UI framework |
| **TypeScript 5** | Type safety |
| **Vite** | Build tool & dev server |
| **TailwindCSS 3.4** | Utility-first styling |
| **React Router v6** | Client-side routing |
| **Axios** | HTTP client |
| **react-markdown** | Markdown rendering (chatbot) |
| **remark-gfm** | GitHub Flavored Markdown |
| **rehype-highlight** | Code syntax highlighting |

### DevOps
| Technology | Purpose |
|:-----------|:--------|
| **Railway** | Backend hosting |
| **Vercel** | Frontend hosting |
| **Nixpacks** | Backend build system |
| **GitHub Actions** | CI/CD |

---

## 📦 Installation

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Redis** (for Celery task queue)
- **Git**

### 1. Clone & Setup

```bash
git clone https://github.com/0xN0RMXL/safeweb-ai.git
cd safeweb-ai
```

### 2. Backend Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source .venv/bin/activate

# Install Python dependencies
pip install -r backend/requirements.txt

# Run migrations
cd backend
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser

# Start Django server
python manage.py runserver 8000
```

### 3. Frontend Setup

```bash
# From project root
npm install

# Start Vite dev server
npm run dev
```

### 4. Celery Worker (for async scanning)

```bash
cd backend
celery -A celery_app worker --loglevel=info
```

### 5. Security Tools (Optional)

Install 60+ bug bounty tools for full scanning capability:

```powershell
# Windows — PowerShell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\install-tools.ps1

# Selective installation
.\scripts\install-tools.ps1 -SkipRuby -SkipRust
```

**Skip flags:** `-SkipGo`, `-SkipPython`, `-SkipRuby`, `-SkipRust`, `-SkipNode`, `-SkipNmap`, `-SkipSecLists`

### Environment Variables

Create a `.env` file in `backend/`:

```env
SECRET_KEY=your-django-secret-key
DEBUG=True
DATABASE_URL=sqlite:///db.sqlite3
REDIS_URL=redis://localhost:6379/0
OPENROUTER_API_KEY=your-openrouter-api-key
OPENROUTER_MODEL=google/gemini-2.0-flash-001
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

---

## 📁 Project Structure

```
safeweb-ai/
├── backend/                          # Django backend
│   ├── manage.py                     # Django management
│   ├── celery_app.py                 # Celery configuration
│   ├── Procfile                      # Railway process config
│   ├── requirements.txt              # Python dependencies
│   ├── apps/
│   │   ├── accounts/                 # User auth & management
│   │   │   ├── models.py            # User, APIKey, UserSession, ContactMessage
│   │   │   ├── views.py             # Auth views (register, login, 2FA, OAuth)
│   │   │   ├── serializers.py       # DRF serializers
│   │   │   └── urls.py              # Auth + user API routes
│   │   ├── scanning/                 # Core scanning engine
│   │   │   ├── models.py            # Scan, Vulnerability, AuthConfig, ScheduledScan
│   │   │   ├── views.py             # Scan CRUD, SSE stream, export, compare
│   │   │   ├── tasks.py             # Celery scan tasks
│   │   │   └── engine/              # The scanning engine
│   │   │       ├── orchestrator.py  # 7-phase scan pipeline
│   │   │       ├── crawler.py       # Web crawler with form interaction
│   │   │       ├── recon/           # 37 reconnaissance modules
│   │   │       ├── testers/         # 87+ vulnerability testers
│   │   │       ├── tools/           # 61 external tool wrappers
│   │   │       │   ├── base.py      # ExternalTool base class
│   │   │       │   ├── registry.py  # Tool registration system
│   │   │       │   └── wrappers/    # Individual tool wrappers
│   │   │       └── payloads/        # Attack payloads + SecLists
│   │   ├── chatbot/                  # AI chat assistant
│   │   │   ├── engine.py            # LLM engine + KB + function calling
│   │   │   ├── actions.py           # 7 action handlers
│   │   │   ├── models.py            # ChatSession, ChatMessage
│   │   │   └── views.py             # Chat, suggestions, analytics views
│   │   ├── ml/                       # Machine learning models
│   │   │   └── models.py            # MLModel, MLPrediction
│   │   ├── admin_panel/              # Admin dashboard backend
│   │   │   ├── models.py            # SystemAlert, SystemSettings
│   │   │   └── views.py             # Admin stats, user mgmt, settings
│   │   └── learn/                    # Learning center
│   │       └── models.py            # Article model (9 categories)
│   └── config/
│       ├── urls.py                   # Root URL configuration
│       └── settings/
│           ├── base.py               # Shared settings
│           └── development.py        # Dev overrides
├── src/                              # React frontend
│   ├── App.tsx                       # Routes & app shell
│   ├── main.tsx                      # Entry point
│   ├── index.css                     # Global styles + Tailwind
│   ├── components/
│   │   ├── layout/                   # Navbar, Footer, ChatbotWidget
│   │   ├── home/                     # Landing page sections
│   │   ├── scan/                     # Scan result tabs
│   │   └── ui/                       # 14 reusable UI components
│   ├── contexts/                     # React context providers
│   ├── hooks/                        # Custom hooks (useSSE, useScanTimer)
│   ├── pages/                        # 28 page components
│   │   └── admin/                    # 7 admin pages
│   ├── services/
│   │   └── api.ts                    # 16 API service modules
│   ├── types/
│   │   └── index.ts                  # TypeScript type definitions
│   └── utils/                        # Utility functions
├── tools/                            # Installed security tools
│   └── bin/                          # 55+ tool binaries & scripts
├── scripts/                          # Setup & utility scripts
│   └── install-tools.ps1            # Bug bounty tool installer
├── vite.config.ts                    # Vite configuration
├── tailwind.config.js                # Tailwind theme config
├── railway.toml                      # Railway deployment config
├── nixpacks.toml                     # Build system config
└── vercel.json                       # Vercel frontend config
```

---

## 🔍 Scanning Engine

The scanning engine is a 7-phase automated pipeline that orchestrates reconnaissance, crawling, vulnerability testing, and verification.

### Phase Pipeline

```
Phase 0     Reconnaissance          37 modules in 4 async waves
Phase 0.5   Auth Setup              Form / OAuth / JWT / cookie analysis
Phase 1     Crawling                Web crawler + form interaction + seed injection
Phase 1.5   Attack Surface Model    LLM-generated testing strategy
Phase 2–4   Analysis                Headers, SSL/TLS, cookies, technologies
Phase 5     Vulnerability Testing   87+ testers, ML-prioritized execution
Phase 5.1   OOB Callback Polling    Out-of-band interaction verification
Phase 5b    Nuclei Engine           Template-based vulnerability scanning
Phase 5c    Secret Scanning         API keys, tokens, credentials in source
Phase 5.5   Evidence Verification   Confirm exploitability with proof
Phase 5.7   Exploit Generation      PoC code + bug bounty report drafting
Phase 6     Vulnerability Chaining  Multi-step attack path discovery
Phase 6.5   False Positive Reduction  5-component ensemble verification
Phase 7     Learning & Update       Knowledge base refinement
```

### Reconnaissance Modules (37)

Organized into 4 concurrent async waves for maximum speed:

| Wave | Modules | Purpose |
|:-----|:--------|:--------|
| **0a — Network** | DNS enumeration, WHOIS, port scanning, subdomain discovery, ASN mapping | Network topology & infrastructure |
| **0b — Response** | Technology fingerprinting, header analysis, cookie audit, SSL/TLS check, WAF detection, CORS testing | Server configuration & defenses |
| **0c — Content** | Parameter fuzzing, directory brute-force, API discovery, JS analysis, cloud bucket detection, CMS fingerprint, email enumeration, social recon | Application surface mapping |
| **0d — Analytics** | Attack surface scoring, threat intelligence (abuse.ch, OTX), risk scoring, vulnerability correlation | Prioritization & strategy |

### Vulnerability Testers (87+)

Detailed testers across Injection, Authentication, API, Network, File Upload, Business Logic, Data Exposure, App-specific, and Advanced categories.

### Scan Modes

| Mode | Description |
|:-----|:------------|
| **Standard** | Full pipeline execution, single target |
| **Continuous** | Recurring scheduled scans with change detection |
| **Hunting** | Bug bounty mode — wide scope, maximum depth, exploit generation |

### Scan Scopes

| Scope | Example | Coverage |
|:------|:--------|:---------|
| **Single Domain** | `example.com` | One domain only |
| **Wildcard** | `*.example.com` | All subdomains |
| **Wide Scope** | Multiple targets | Multi-domain, IP ranges, CIDR blocks |

### Scan Depth

| Depth | Recon | Testers |
|:------|:------|:--------|
| **Shallow** | Basic (DNS, tech fingerprint) | Top 20 common tests |
| **Medium** | Standard (full recon waves) | 50+ targeted tests |
| **Deep** | Comprehensive (all 37 modules) | All 87+ testers + Nuclei |

---

## 🤖 AI Chatbot Assistant

A context-aware AI assistant powered by OpenRouter LLM (Gemini 2.0 Flash) with function calling capabilities.

### Features

- **36-Entry Knowledge Base** — App features, cybersecurity topics, conversational flows
- **7 Action Tools** — Execute platform actions directly from chat
- **Scan-Aware Context** — Auto-detects scan ID from URL, links conversations to scans
- **Rich Markdown** — Code blocks, tables, lists with syntax highlighting
- **Feedback System** — Thumbs up/down per message for quality tracking
- **Token Tracking** — Per-message token usage monitoring
- **Admin Analytics** — Sessions, messages, satisfaction rate, top topics

### Action Tools

| Tool | Parameters | Action |
|:-----|:-----------|:-------|
| `start_scan` | target, scan_type, depth | Launch a new security scan |
| `get_recent_scans` | count | Retrieve user's recent scan history |
| `get_scan_status` | scan_id | Check live scan progress & phase |
| `export_scan` | scan_id, format | Generate download link (PDF/CSV/JSON/SARIF/HTML) |
| `get_subscription_info` | — | Show plan details & usage limits |
| `get_vulnerability_details` | vuln_id | Full vulnerability data with remediation |
| `navigate_to` | destination | Navigate to dashboard, scans, settings |

---

## 📡 API Reference

**Base URL:** `http://localhost:8000/api/`

**Authentication:** JWT Bearer token (access + refresh tokens)

**Rate Limits:** 30 req/min (anonymous) · 120 req/min (authenticated)

### Authentication (`/api/auth/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/auth/register/` | Create account (email, password, name) | — |
| POST | `/auth/login/` | Login (returns JWT pair) | — |
| POST | `/auth/logout/` | Blacklist refresh token | ✅ |
| GET | `/auth/verify/` | Validate current JWT | ✅ |
| POST | `/auth/refresh/` | Refresh access token | — |
| POST | `/auth/google/` | Google OAuth login | — |
| POST | `/auth/forgot-password/` | Request reset email | — |
| POST | `/auth/reset-password/` | Complete password reset | — |
| POST | `/auth/change-password/` | Change current password | ✅ |

### User (`/api/user/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| GET | `/user/` | Get profile | ✅ |
| PUT | `/user/` | Update profile | ✅ |

### Scanning (`/api/scan/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/scan/website/` | Create new scan | ✅ |
| GET | `/scan/<id>/` | Get scan details | ✅ |
| DELETE | `/scan/<id>/` | Delete scan | ✅ |
| POST | `/scan/<id>/rescan/` | Re-scan target | ✅ |
| GET | `/scan/<id>/stream/` | SSE live progress stream | ✅ |
| GET | `/scan/<id>/findings/` | Paginated vulnerability list | ✅ |
| GET | `/scan/<id>/export/<fmt>/` | Export (pdf/csv/json/sarif/html) | ✅ |
| GET | `/scan/compare/<id1>/<id2>/` | Compare two scans | ✅ |
| POST/GET | `/scan/scheduled/` | Manage scheduled scans | ✅ |
| POST/GET | `/scan/scopes/` | Manage scan scopes | ✅ |
| GET | `/scan/assets/` | Asset inventory | ✅ |
| POST/GET | `/scan/webhooks/` | Manage webhooks | ✅ |
| POST | `/scan/auth-configs/` | Configure authenticated scanning | ✅ |
| GET/POST | `/scan/nuclei-templates/` | Nuclei template management | ✅ |

### AI Chatbot (`/api/chat/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/chat/` | Send message, get AI response | ✅ |
| GET | `/chat/sessions/` | List user chat sessions | ✅ |
| GET | `/chat/sessions/<id>/` | Get session with message history | ✅ |
| GET | `/chat/suggestions/` | Contextual AI suggestions | ✅ |
| GET | `/chat/analytics/` | Chat analytics (admin only) | ✅ 👑 |

### Admin (`/api/admin/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| GET | `/admin/dashboard/` | System-wide statistics | ✅ 👑 |
| GET | `/admin/users/` | List all users | ✅ 👑 |
| GET/PUT | `/admin/users/<id>/` | User detail & management | ✅ 👑 |
| GET | `/admin/scans/` | Scan statistics | ✅ 👑 |
| GET | `/admin/ml/` | ML model stats | ✅ 👑 |
| GET/PUT | `/admin/settings/` | System settings | ✅ 👑 |
| GET | `/admin/contacts/` | Contact submissions | ✅ 👑 |
| GET | `/admin/applications/` | Job applications | ✅ 👑 |

### Learning (`/api/learn/`)

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| GET | `/learn/articles/` | List articles (9 categories) | — |
| GET | `/learn/articles/<slug>/` | Article detail | — |

### Other

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| POST | `/contact/` | Submit contact form | — |
| POST/GET | `/careers/` | Job applications | — |

---

## 🖥 Frontend Pages

(omitted here for brevity — see top sections for full list)

---

## 🔧 Security Tools

(omitted here for brevity — full tool catalog available in top sections)

---

## 🚀 Deployment

### Railway (Backend)

The backend deploys to Railway using Nixpacks:

**`railway.toml`:**
```toml
[build]
builder = "nixpacks"

[deploy]
startCommand = "cd backend && python manage.py migrate && gunicorn config.wsgi:application --bind 0.0.0.0:$PORT"
```

**`nixpacks.toml`:**
Configures Python with system packages (libmagic, nmap, etc.)

### Vercel (Frontend)

**`vercel.json`:**
```json
{
  "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
}
```

### Build Commands

```bash
# Frontend production build
npm run build

# Backend static files
cd backend && python manage.py collectstatic --noinput
```

---

## 🎨 Design System

(omitted here for brevity — full design tokens and typography in top sections)

---

## 🔐 Security Features

(omitted here for brevity — see above)

---

## 👥 Team

**SafeWeb AI** — University Graduation Project

---

<div align="center">

Built with 🛡️ for web security

**[⬆ Back to Top](#-safeweb-ai)**

</div>
