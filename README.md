# PS-8: AI-Assisted Security Monitoring & Risk Analysis Platform

PS-8 is a lightweight, explainable cybersecurity monitoring and multi-step risk correlation platform. Instead of treating isolated security signals as unrelated alerts, PS-8 correlates multi-event sequences across users, devices, authentication/logins, APIs, AI agents, agent tools, and sensitive databases into unified security incidents with explainable risk assessments.

---

## 1. Project Overview

Modern systems monitor discrete components in isolation. An anomaly detector might notice a new device; an API gateway might notice an export endpoint; an LLM orchestrator might record a tool invocation. The meaningful threat, however, emerges from the **relationship and sequence** across these components:

$$\text{User Login} \longrightarrow \text{Unknown Device} \longrightarrow \text{Sensitive API} \longrightarrow \text{AI Agent Invocation} \longrightarrow \text{Restricted Tool} \longrightarrow \text{Database Dump}$$

PS-8 unifies these 6 discrete events into a single high-context incident and answers:
- **What happened?** (Connected 7-node attack chain timeline)
- **Why is it suspicious?** (Transparent rule signals & Cognee baseline deviations)
- **How risky is it?** (Risk score 0–100, confidence rating, severity level)
- **What actions are recommended?** (Automated containment & n8n human-in-the-loop approvals)

---

## 2. Architecture

```text
       ┌─────────────────────────────────────────────────────────┐
       │                n8n Workflow Automation                  │
       │   (Triggers, Webhooks, Escalations, Human Approval)     │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │                 FastAPI Security Core                   │
       │                                                         │
       │   1. Event Validation & Schema Normalization            │
       │   2. Detection Engine (8+ Rule-based Signals)           │
       │   3. Correlation Engine (Sliding Time-Window & Entities)│
       │   4. Cognee Knowledge Service (Historical Baselines)    │
       │   5. Risk Scoring & Explanation Engine                  │
       │   6. Alert Generator & Recommended Actions Mapping      │
       └──────────────┬───────────────────────────┬──────────────┘
                      │                           │
                      ▼                           ▼
       ┌─────────────────────────┐   ┌───────────────────────────┐
       │    Supabase Postgres    │   │      React Dashboard      │
       │ (Events, Incidents,     │   │ (Vite + Tailwind CSS +    │
       │  Alerts, Audit Trails)  │   │  Real-Time Attack Graph)  │
       └─────────────────────────┘   └───────────────────────────┘
```

---

## 3. Technology Stack

### Backend
- **FastAPI** (Python 3.10+): High-performance asynchronous API framework
- **Pydantic v2**: Strict schema validation, ID generation, and data normalization
- **Uvicorn**: ASGI web server
- **Pytest & Starlette TestClient**: Automated testing suite (50/50 passing tests)

### Intelligence & Context
- **Rule-Based Detection Engine**: Modular, transparent signal evaluation
- **Sliding-Window Correlation Engine**: Groups entity chains (`user`, `session`, `device`, `agent`)
- **Cognee Service**: Graph-based memory baselines for agent-tool permissions and user-device affinities, with offline fallback

### Data & Automation
- **Supabase (PostgreSQL)**: Persistent relational store with in-memory fallback
- **n8n Webhook Integration**: Automated event processing, triage, and human-in-the-loop alerts

### Frontend
- **React 19**: Modern component architecture
- **Vite 8**: Rapid development and production bundling
- **Tailwind CSS v4**: High-density cybersecurity dark theme (`@tailwindcss/vite`)
- **Lucide Icons & Axios**: Visual indicators and centralized API service

---

## 4. Environment Variables

### Backend Configuration (`.env`)
Create `.env` in the repository root:
```env
# Application
ENVIRONMENT=development
PORT=8000
HOST=0.0.0.0

# Supabase Configuration (Optional: In-memory repository fallback active if omitted)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key

# Cognee Knowledge Graph (Optional: Local baseline fallback active if omitted)
COGNEE_API_KEY=your-cognee-api-key
COGNEE_API_URL=https://api.cognee.ai

# n8n Webhook Configuration (Optional: Simulated response active if omitted)
N8N_WEBHOOK_URL=http://localhost:5678/webhook/security-alerts

# Detection & Risk Parameters
CORRELATION_WINDOW_MINUTES=30
ALERT_RISK_THRESHOLD=70
```

### Frontend Configuration (`frontend/.env`)
Create `.env` in the `frontend/` directory:
```env
# Backend API Base URL (Do NOT hardcode in components)
VITE_API_URL=http://localhost:8000
```

---

## 5. Supabase Setup

Run the SQL script [`supabase_schema.sql`](./supabase_schema.sql) in your **Supabase SQL Editor**:

```sql
-- 1. Security Events Table
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    device_id TEXT,
    session_id TEXT,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resource TEXT,
    agent_id TEXT,
    tool_name TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- 2. Correlated Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    primary_entity TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    event_ids JSONB DEFAULT '[]'::jsonb,
    signals_detected JSONB DEFAULT '[]'::jsonb,
    risk_assessment JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Security Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents(id) ON DELETE CASCADE,
    event_id TEXT REFERENCES events(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    risk_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    reasons JSONB DEFAULT '[]'::jsonb,
    recommended_action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb
);
```

> **Note**: If Supabase credentials are not provided, the backend automatically uses an in-memory repository cache so all features remain functional for local evaluations and demonstrations.

---

## 6. Quick Start (Run Whole Project)

You can launch both the backend and frontend simultaneously with automated browser launch using any of the following:

- **Windows (Double-click or CMD)**:
  ```cmd
  run.bat
  ```
- **PowerShell**:
  ```powershell
  .\run.ps1
  ```
- **Cross-Platform (Python)**:
  ```bash
  python run.py
  ```

This runner will:
1. Verify and install dependencies automatically.
2. Initialize `.env` from `.env.example` if needed.
3. Start the FastAPI backend on `http://127.0.0.1:8000`.
4. Start the Vite React frontend on `http://localhost:3000`.
5. Automatically open `http://localhost:3000` in your default web browser.
6. Cleanly terminate all background processes on `Ctrl+C`.

---

## 7. Backend Setup (Manual)

```bash
# 1. Clone repository and navigate to root
cd BINARY-HACKS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the FastAPI backend
python -m uvicorn app.main:app --reload --port 8000
```
- **Backend API Base**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **Health Diagnostic**: `http://localhost:8000/health`

---

## 7. Cognee Setup

PS-8 uses Cognee to verify behavioral baselines (e.g. which tools an AI agent typically executes, and which devices a user normally uses).

1. To use hosted Cognee, set `COGNEE_API_KEY` and `COGNEE_API_URL` in `.env`.
2. If offline or without an API key, `CogneeService` activates local relationship baseline models without interrupting the pipeline.

---

## 8. n8n Setup

PS-8 provides a dedicated automation endpoint for n8n orchestrators:
`POST http://localhost:8000/api/n8n/process-event`

### Example Workflow Setup in n8n
1. **Webhook Node**: Receives external security event (e.g. from cloud logs or agents).
2. **HTTP Request Node**:
   - Method: `POST`
   - URL: `http://localhost:8000/api/n8n/process-event`
   - Body: pass event JSON payload.
3. **IF Node**:
   - Condition: `{{ $json.should_escalate }}` equals `true`.
4. **Action Node**:
   - Send `{{ $json.notification_summary }}` to Slack, Discord, or Email.

---

## 9. Frontend Setup

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install npm dependencies
npm install

# 3. Start the development server
npm run dev
```
- **Frontend URL**: `http://localhost:3000` (or `http://localhost:5173`)
- **Production Build Check**: `npm run build`

---

## 10. API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Operational health and integration statuses |
| `POST` | `/api/events` | Ingests, normalizes, detects signals, correlates, and scores risk |
| `GET` | `/api/events` | Lists security events with search and filtering |
| `GET` | `/api/events/{id}` | Retrieves a single security event |
| `GET` | `/api/incidents` | Lists correlated multi-event security incidents |
| `GET` | `/api/incidents/{id}` | Retrieves full incident detail with attack sequence chain |
| `POST` | `/api/analyze` | On-demand intelligence analysis for payload or `event_id` |
| `GET` | `/api/alerts` | Lists security alerts with status and risk level filters |
| `GET` | `/api/alerts/{id}` | Retrieves a specific security alert |
| `PATCH`| `/api/alerts/{id}` | Updates alert status (`acknowledged`, `resolved`) |
| `POST` | `/api/n8n/process-event` | n8n orchestration entrypoint returning branching flags |
| `GET` | `/api/users` | Lists tracked users with event counts and risk levels |
| `GET` | `/api/users/{user_id}/activity-graph` | Retrieves connected user activity graph, chronology, and incident links |

---

## 11. Demo Scenarios

### Option A: Via the React Dashboard
1. Open `http://localhost:3000`.
2. Click the **"Run Attack Demo"** button in the top navigation header.
3. The dashboard injects the 6-step attack sequence into the live backend, correlates the incident, and opens the incident detail view showing the connected 7-step attack chain:
   $$\text{USER} \longrightarrow \text{DEVICE} \longrightarrow \text{LOGIN} \longrightarrow \text{API} \longrightarrow \text{AI AGENT} \longrightarrow \text{TOOL} \longrightarrow \text{RESOURCE/DATABASE}$$
4. Navigate to **Risk Analysis** to test custom payloads, or **Alerts** to acknowledge and resolve active security warnings.

### Option B: Via Command-Line Script
```bash
python demo_scenario.py
```
This runs the 6-step sequence in the terminal with colored status reports.

### Option C: Complete Automated Verification Suite
```bash
python verify_e2e_scenario.py
```
Executes the synthetic attack chain, normal scenario, and 6 failure resilience tests.

---

## 12. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| `uvicorn: command not found` | Python Scripts directory not in system PATH | Use `python -m uvicorn app.main:app --port 8000` |
| `Supabase credentials not configured` warning in logs | Missing `SUPABASE_URL` in `.env` | Normal for local runs; in-memory cache handles all requests seamlessly. To persist to Supabase, fill in `.env`. |
| `Cognee remote service error (falling back to baseline)` | No internet or invalid `COGNEE_API_KEY` | Normal behavior; local baseline fallback is active and operational. |
| Port 8000 or 3000 already in use | Another process is occupying the port | Change `--port 8001` or set `PORT=3001` in `.env` |
| CORS errors in browser console | Frontend origin blocked | FastAPI backend has CORS enabled with `allow_origins=["*"]` by default. |
