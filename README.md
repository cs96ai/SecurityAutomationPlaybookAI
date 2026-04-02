# SecurityAutomationPlaybookAI

A proof-of-concept security operations platform built to demonstrate end-to-end security automation and AI-assisted operations. The platform simulates two healthcare systems (HSPS and STAR), monitors them for security events in real time, and provides playbook-driven incident response through a modern Vue 3 SPA.

**Deployed on Fly.io** - Runs in a single low-cost container using supervisord to manage both the API and UI services.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Vue 3 SPA (Port 3000)                             │
│  Dashboard · Playbooks · ChatOps · Kubernetes Monitor · CI/CD · ...  │
└────────────────────────────┬─────────────────────────────────────────┘
                             │  REST / Bearer Token
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   FastAPI Backend (Port 8000)                         │
│           Simulated infrastructure data · OpenAI ChatOps agent       │
│                    Security event simulator                          │
└────────────┬─────────────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────┐
│     OpenAI GPT-4 API       │
│  Natural language queries  │
│  with security guardrails  │
└────────────────────────────┘

                    ┌─────────────────────────────────────┐
                    │  Simulated Healthcare Systems       │
                    │  ┌─────────────┐ ┌─────────────┐   │
                    │  │    HSPS     │ │    STAR     │   │
                    │  ├─────────────┤ ├─────────────┤   │
                    │  │ Database    │ │ Database    │   │
                    │  │ API         │ │ API         │   │
                    │  │ Web UI      │ │ Web UI      │   │
                    │  └─────────────┘ └─────────────┘   │
                    │  (Security events generated         │
                    │   in-process by simulator)          │
                    └─────────────────────────────────────┘
```

---

## What This Demonstrates

| Skill Area | Implementation |
|---|---|
| **Security Orchestration** | 12 automated playbooks (endpoint remediation, phishing response, SIEM enrichment, DLP, malware analysis, etc.) with execution tracking and success metrics |
| **Security Event Simulation** | Python simulators generating realistic security events (SQLi, XSS, privilege escalation, PHI exfiltration, prescription fraud) for HSPS and STAR healthcare systems |
| **AI-Assisted SecOps (ChatOps)** | GPT-4 integration with security guardrails: client-side pattern detection, system prompt constraints, backend auth. Violation counter auto-resets the session after 3 attempts |
| **Backend API Design** | FastAPI with simulated infrastructure endpoints, bearer token auth, real-time event generation |
| **Deployment** | Single-container deployment using Docker and supervisord, optimized for Fly.io |
| **Frontend Engineering** | Vue 3 + Composition API, Pinia state management, TailwindCSS, real-time event streaming, dark mode |

---

## Key Components

### Security Automation UI (`SecurityAutomation_UI/`)

Vue 3 single-page application with 9 views:

- **Dashboard** -- KPIs, toil reduction metrics, quarterly objectives, automation roadmap
- **Playbooks** -- 12 security playbooks with execution history, success rates, and simulated runs
- **Self-Service** -- CLI simulator, ChatOps AI interface, quick actions (triage, isolate, scan)
- **Kubernetes Monitor** -- Live event stream from HSPS/STAR pods with auto-refresh, pod health, and resource metrics
- **Integrations** -- 15 security tool connections (Splunk, CrowdStrike, ServiceNow, SentinelOne, etc.)
- **CI/CD** -- Pipeline management, deployment tracking, secrets rotation
- **Observability** -- Metrics, distributed tracing, alerting, error budgets
- **Collaboration** -- Team coordination and knowledge base
- **Settings** -- User profile, preferences, dark mode

### Backend API (`SecurityAutomation_API/`)

Python FastAPI server providing:

- **14 read-only Azure endpoints** -- AKS status, pod listing, deployments, services, logs, resource groups, app services, node pools, subscription info
- **OpenAI agent endpoint** -- `/api/agent/chat` for natural language infrastructure queries
- **Authentication** -- Bearer token verification on all endpoints
- **Azure SDK integration** -- `azure-identity`, `azure-mgmt-resource`, `azure-mgmt-containerservice`, `kubernetes` client

> **Note:** This platform runs entirely in simulation mode, generating realistic security events and infrastructure data for demonstration purposes. No actual cloud resources are required.

### Simulated Healthcare Systems (`SimulatedApplications/`)

Two Dockerized systems deployed to AKS, each with 4 microservices:

**HSPS (Healthcare Provider System)** -- Generates security events: auth failures, SQL injection, privilege escalation, data exfiltration, brute force attacks

**STAR (Pharmacy System)** -- Generates healthcare-specific events: prescription fraud, DEA verification failures, controlled substance access, insurance claim manipulation, PHI violations

Each system simulates:
- Database events (connection monitoring, query analysis)
- API events (request rate tracking, injection detection)
- Web UI events (session tracking, XSS/CSRF/bot detection)
- Security metrics (event aggregation, real-time statistics)

### ChatOps Security Model

```
┌──────────────────────────────────────────────────────┐
│  Layer 1: Client-Side Pattern Detection              │
│  Regex matching for destructive commands & creds     │
│  Hidden violation counter (max 3, then auto-reset)   │
├──────────────────────────────────────────────────────┤
│  Layer 2: OpenAI System Prompt Guardrails            │
│  Strict read-only instructions in system message     │
│  Forbidden action categories in prompt engineering   │
├──────────────────────────────────────────────────────┤
│  Layer 3: Backend API Authentication                 │
│  Bearer token required on every request              │
│  Server-side Azure calls (no creds in browser)       │
├──────────────────────────────────────────────────────┤
│  Layer 4: Azure RBAC (Reader Role)                   │
│  Service principal physically cannot write/delete    │
│  Enforced at the Azure platform level                │
└──────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | Vue 3, Vite, TailwindCSS, Pinia, Vue Router, Chart.js |
| **Backend API** | Python, FastAPI, Uvicorn |
| **Simulators** | Python (in-process event generation) |
| **Deployment** | Docker, supervisord, Fly.io |
| **AI** | OpenAI GPT-4 API |
| **Process Management** | supervisord |

---

## Project Structure

```
SecurityAutomationPlaybookAI/
├── SecurityAutomation_UI/       # Vue 3 SPA
│   └── src/
│       ├── views/                        # 9 page components
│       ├── stores/                       # Pinia state (6 stores)
│       ├── services/                     # API clients
│       └── config/                       # Environment management
│
├── SecurityAutomation_API/      # FastAPI backend
│   ├── main.py                           # API endpoints + agent
│   ├── simulator.py                      # Event generator
│   ├── simulated_azure_data.json         # Mock infrastructure data
│   └── requirements.txt
│
├── Dockerfile                            # Multi-stage Docker build
├── supervisord.conf                      # Process manager config
├── fly.toml                              # Fly.io deployment config
└── .env.example                          # Environment variables template
```

---

## Running Locally

**Prerequisites**: Node.js 18+, Python 3.11+

### Development Mode (separate processes)

```bash
# Terminal 1: Backend API
cd SecurityAutomation_API
pip install -r requirements.txt
cp ../.env.example .env
python -m uvicorn main:app --port 8000 --reload

# Terminal 2: Frontend
cd SecurityAutomation_UI
npm install
npm run dev            # http://localhost:5173
```

### Production Mode (Docker with supervisord)

```bash
# Build and run with Docker
docker build -t security-automation .
docker run -p 8000:8000 -p 3000:3000 \
  -e BEARER_TOKEN=your-secret-token \
  -e OPENAI_API_KEY=your-openai-key \
  security-automation

# Access the application
# UI: http://localhost:3000
# API: http://localhost:8000
# API Health: http://localhost:8000/health
```

---

## Deployment to Fly.io

```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Login to Fly.io
fly auth login

# Launch the app (first time)
fly launch

# Set environment variables
fly secrets set BEARER_TOKEN=your-secret-token-123
fly secrets set OPENAI_API_KEY=your-openai-api-key

# Deploy
fly deploy

# View logs
fly logs

# Open the app
fly open
```

## Environment Variables

- `BEARER_TOKEN` - API authentication token (required)
- `OPENAI_API_KEY` - OpenAI API key for ChatOps agent (optional)

## Features

- **Single Container Deployment** - Both API and UI run in one container using supervisord
- **Low Cost** - Optimized for Fly.io's free tier with auto-stop/start
- **No External Dependencies** - All data is simulated in-process
- **Real-time Events** - Security event simulator generates realistic healthcare security incidents
- **AI ChatOps** - Optional OpenAI integration for natural language infrastructure queries
