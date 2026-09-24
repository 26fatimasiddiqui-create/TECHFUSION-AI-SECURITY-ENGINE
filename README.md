# 🛡️ ThreatFusion AI Security Engine
### *INSIGHT Threat Monitor & Autonomous Multi-Step Risk Correlation Platform (PS-8)*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19.2+-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://react.dev/)
[![Tailwind CSS v4](https://img.shields.io/badge/Tailwind_CSS-v4.0-38B2AC.svg?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E.svg?style=flat&logo=supabase&logoColor=white)](https://supabase.com/)
[![Leaflet](https://img.shields.io/badge/Leaflet-Geo--Mapping-199900.svg?style=flat&logo=leaflet&logoColor=white)](https://leafletjs.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Executive Summary

Traditional SIEM and anomaly detectors treat discrete security events in isolation. A login from a new laptop, an export API call, or an AI agent invoking a database tool might each look harmless alone. However, the true threat emerges from the **multi-step relationship and sequence across these layers**:

$$\text{User Login} \longrightarrow \text{Unknown Device} \longrightarrow \text{Sensitive API} \longrightarrow \text{AI Agent Invocation} \longrightarrow \text{Restricted SQL Tool} \longrightarrow \text{Data Exfiltration}$$

**ThreatFusion AI Security Engine (INSIGHT Threat Monitor)** is an enterprise-grade, explainable security platform designed to detect, track, and remediate multi-stage insider threats, external breaches, and autonomous AI agent anomalies in real time. It monitors **1,000 enterprise employees**, correlates **10,000+ access logs**, plots **interactive geolocation tracks**, and provides **human-in-the-loop SOC approval workflows** with **autonomous synthetic voice dispatch**.

---

## 🚀 5-Minute Prototype Demo Script (For Judges & Evaluators)

When presenting this prototype, follow this step-by-step walkthrough to demonstrate the full platform capabilities:

```
[1. INSIGHT Dashboard] ──> [2. Employee Map View] ──> [3. SOC Action Center] ──> [4. Alerts & Voice] ──> [5. Security Graph] ──> [6. Executive Easy Mode]
```

### Step 1: INSIGHT Threat Monitor (SOC Command Center)
- **What to show:** Open `http://localhost:3000`. You land on the **INSIGHT Threat Monitor**.
- **What to say:** *"Here we monitor 1,000 enterprise employees and 10,000+ access logs in real time via live Supabase PostgreSQL streaming. The KPI strip displays our Active Alert count, Critical Threats, Total Risk Events, and Monitored Headcount."*
- **Key Highlights:** Real-time risk distribution bar (Critical, High, Moderate, Low), Top Risk Employees list, and live threat feed.

### Step 2: Employee Geolocation Track & Map View
- **What to show:** In the **Monitored Employees Table**, locate any high-risk employee (e.g. *Aditya Joshi* or *Rajesh Kumar*) and click the **🗺️ Map Icon**.
- **What to say:** *"ThreatFusion analyzes IP access logs and correlates geo-velocity. Clicking the Map View opens an interactive Leaflet dark-mode world map plotting the employee's chronological access sequence across cities (e.g. Bangalore -> Pune -> Mumbai) and flags impossible travel or foreign IP anomalies (e.g. Singapore/Dubai)."*
- **Key Highlights:** Color-coded polylines by risk level, clickable waypoint markers, and an interactive timestamped audit timeline.

### Step 3: SOC Action Center & Two-Person Rule Approval
- **What to show:** Click the **⚡ Action Center** button on a critical employee row.
- **What to say:** *"When a critical anomaly occurs, our engine generates explainable threat indicators (e.g., Off-hours access, Bulk data exfiltration, Shadow AI tool usage). To prevent catastrophic accidents or unauthorized lockdowns, we enforce the Two-Person Rule. The SOC analyst reviews the threat analysis and clicks **Approve Threat & Clear Risk**."*
- **What to observe:**
  - The employee's risk score drops immediately from **CRITICAL (e.g. 92)** to **LOW / CLEARED (15)**.
  - The status updates to **CLEARED**, and the action is recorded in the Supabase `approvals` audit table.
  - **Strict User Isolation:** Only the selected employee is cleared; all other monitored employees remain unaffected.

### Step 4: Real-Time Alerts Console & Autonomous Voice Dispatch
- **What to show:** Click on the **Alerts** tab in the sidebar.
- **What to say:** *"The Alerts console tracks all active alerts with live count badges (`ACTIVE (187)`, `CRITICAL`, `APPROVED`). Critical incidents trigger synthetic Text-to-Speech (TTS) voice announcements to immediately alert on-duty SOC analysts."*
- **Key Highlights:**
  - Click **"Test Audio"** or **"Listen"** to hear the autonomous voice synthesis.
  - Inline **Approve** button clears the alert and immediately decrements the live sidebar badge.
  - Expand any alert row to view the full JSON audit payload and recommended mitigation steps.

### Step 5: Live Security & User Activity Graph
- **What to show:** Click on the **Activity Graph** tab.
- **What to say:** *"Our 7-node entity correlation graph maps the full anatomy of an attack: `USER -> DEVICE -> LOGIN -> API -> AI AGENT -> TOOL -> DATABASE`. Analysts can inspect exact relationships, payload sizes, and agent tool invocations."*
- **Key Highlights:** Top Risk Employees quick-selector pill bar, chronological event timeline, and graph node inspection panel.

### Step 6: Easy Dashboard Mode (Executive View)
- **What to show:** Click the **"Easy Mode" / "Pro Mode"** toggle in the top-right header (or click **Easy View** in sidebar).
- **What to say:** *"Cybersecurity data shouldn't require a master's degree to understand. Easy Mode translates technical jargon into plain-English executive summaries for C-suite executives and managers, displaying friendly status cards, plain-language risk ratings, and simplified action items."*

---

## 🏗️ System Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                         n8n Workflow Automation                         │
 │        (Webhook Triggers, Slack/Discord Dispatch, SOC Approvals)        │
 └────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                       FastAPI Security Core (Python)                    │
 │                                                                         │
 │  1. Ingestion & Validation    ──> Pydantic v2 strict schemas            │
 │  2. Rule-Based Detection      ──> 8+ Multi-layer signal detectors       │
 │  3. Sliding Correlation Engine──> Entity graphs & time-window grouping  │
 │  4. Cognee Baseline Service   ──> Graph memory for agent/tool baselines │
 │  5. Risk Scoring & Scoring    ──> Dynamic 0-100 severity modeling       │
 │  6. Threat Mitigation Engine  ──> Two-person rule & containment mapping │
 └─────────────────┬─────────────────────────────────────┬─────────────────┘
                   │                                     │
                   ▼                                     ▼
 ┌───────────────────────────────────┐ ┌───────────────────────────────────┐
 │      Supabase Cloud PostgreSQL    │ │       React 19 SOC Frontend       │
 │                                   │ │                                   │
 │ • 1,000 Monitored Employees       │ │ • INSIGHT Pro Dashboard           │
 │ • 10,000+ Access & Telemetry Logs │ │ • Easy Dashboard (Executive Mode) │
 │ • Real-Time Risk Events & Alerts  │ │ • Leaflet Dark Geolocation Map    │
 │ • Immutable Approvals Audit Trail │ │ • Web Speech API Voice Dispatch   │
 │ • PostgreSQL Change Subscriptions │ │ • D3 / SVG Entity Security Graph  │
 └───────────────────────────────────┘ └───────────────────────────────────┘
```

---

## ✨ Core Platform Modules

| Module | Technologies | Key Capabilities |
| :--- | :--- | :--- |
| **INSIGHT Threat Monitor** | React 19, Supabase Realtime, Tailwind CSS | Real-time monitoring of 1,000 employees, live risk score distribution, search & filter by department, threat overview feed. |
| **Interactive Map View** | Leaflet.js, React-Leaflet, Carto Dark Matter | Visualizes employee travel patterns, IP geolocations, impossible travel alerts, and suspicious foreign connections. |
| **SOC Action Center** | React Modal, Supabase PostgreSQL, FastAPI | Threat forensic breakdown, Two-Person Rule governance, one-click mitigation, automated score reduction from Critical to Low. |
| **Live Security Graph** | SVG / Canvas Graph Engine, Lucide Icons | 7-tier correlation graph connecting User, Device, Authentication, API, Agent, Tool, and Storage entities. |
| **Alerts & Voice Engine** | Web Speech API, VoiceAlertService | Speech synthesis for critical threat dispatch, dynamic filter tabs with live counters, 1-click approvals. |
| **Executive Easy Mode** | ModeContext, Plain-Language Engine | Translates technical CVEs, hashes, and tool invocations into clear, actionable business summaries. |
| **n8n Orchestration** | REST Webhooks, JSON Payloads | Bidirectional communication for automated alerts, Slack notifications, and external SOC escalation. |

---

## ⚡ Quick Start (One-Click Launch)

You can launch both the **FastAPI backend** and the **React Vite frontend** simultaneously with automated port verification and browser launch:

### Option 1: Python Runner (Recommended - Cross Platform)
```bash
python run.py
```

### Option 2: Windows Batch
Double-click `run.bat` or run in CMD:
```cmd
run.bat
```

### Option 3: PowerShell
```powershell
.\run.ps1
```

**What the runner script does automatically:**
1. Verifies Python virtual environment and installs dependencies from `requirements.txt`.
2. Checks `frontend/node_modules` and executes `npm install` if needed.
3. Spawns the FastAPI backend on `http://127.0.0.1:8000`.
4. Spawns the Vite development server on `http://localhost:3000`.
5. Automatically opens your default browser to `http://localhost:3000`.
6. Handles graceful shutdown of both servers on `Ctrl+C`.

---

## 🔧 Manual Setup & Configuration

### Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher

### 1. Backend Setup
```bash
# Navigate to repository root
cd BINARY-HACKS

# Create & activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend
python -m uvicorn app.main:app --reload --port 8000
```
- **Backend API**: `http://localhost:8000`
- **Swagger Documentation**: `http://localhost:8000/docs`
- **Health Endpoint**: `http://localhost:8000/health`

### 2. Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```
- **Frontend URL**: `http://localhost:3000`

---

## 🔐 Environment Variables

### Backend Configuration (`.env`)
Create `.env` in the repository root:
```env
# Application
ENVIRONMENT=development
PORT=8000
HOST=0.0.0.0

# Supabase Configuration (Optional: In-memory fallback active if omitted)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key

# Cognee Baseline Intelligence (Optional: Local baseline fallback active if omitted)
COGNEE_API_KEY=your-cognee-api-key
COGNEE_API_URL=https://api.cognee.ai

# n8n Webhook Configuration
N8N_WEBHOOK_URL=http://localhost:5678/webhook/security-alerts

# Security Engine Thresholds
CORRELATION_WINDOW_MINUTES=30
ALERT_RISK_THRESHOLD=70
```

### Frontend Configuration (`frontend/.env`)
Create `.env` in `frontend/`:
```env
# FastAPI Backend URL
VITE_API_URL=http://localhost:8000

# Supabase Client Configuration
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
```

---

## 🗄️ Database Schema & Supabase Architecture

The platform uses two SQL schemas for enterprise threat telemetry:

1. [`supabase_insider_threat_schema.sql`](./supabase_insider_threat_schema.sql):
   - **`employees`**: 1,000 enterprise staff profiles with departments, role clearances, and risk baselines.
   - **`access_logs`**: 10,000+ detailed IP, device, and API access events.
   - **`risk_events`**: High-fidelity anomaly detections flagged by the engine.
   - **`alerts`**: Live actionable security alerts (187+ records).
   - **`approvals`**: Audit trail of SOC analyst approvals, Two-Person Rule signatures, and risk score adjustments.

2. [`supabase_schema.sql`](./supabase_schema.sql):
   - Multi-event sequence correlation tables (`events`, `incidents`, `alerts`).

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System health diagnostic and integration statuses |
| `POST` | `/api/events` | Ingests raw telemetry event, normalizes, detects signals, correlates, and scores risk |
| `GET` | `/api/events` | Retrieves ingested events with pagination and filtering |
| `GET` | `/api/events/{id}` | Retrieves single event payload |
| `GET` | `/api/incidents` | Lists correlated multi-event security incidents |
| `GET` | `/api/incidents/{id}` | Retrieves full incident attack chain with entity nodes |
| `POST` | `/api/analyze` | On-demand targeted risk analysis for arbitrary payloads |
| `GET` | `/api/alerts` | Lists security alerts with risk level filters |
| `PATCH`| `/api/alerts/{id}` | Acknowledges, approves, or resolves security alerts |
| `POST` | `/api/n8n/process-event` | n8n automation entrypoint returning branching flags and notification summaries |
| `GET` | `/api/users` | Lists tracked users with event counts and risk levels |
| `GET` | `/api/users/{id}/activity-graph` | Retrieves 7-node entity correlation graph for a user |

---

## 🧪 Testing & Verification

The platform includes an extensive test suite covering unit detection, sliding-window correlation, Two-Person Rule validation, and live thread state isolation:

```bash
# Run pytest verification suite
pytest tests/ -v
```

**Key Test Coverage:**
- `test_incident_alert_graph_sync.py`: Verifies synchronization between incidents, alerts, and graphs.
- `test_approver_and_two_person_rule.py`: Validates authorization safeguards and approval workflows.
- `test_resolved_graph_state.py`: Confirms risk score reductions upon approval.
- `test_live_thread_state_isolation.py`: Guarantees single-user approval isolation.

---

## 👥 Team & Hackathon Submission

- **Problem Statement**: PS-8 (AI-Assisted Security Monitoring & Multi-Step Risk Correlation Engine)
- **Developed for**: Hackathon 2026

*ThreatFusion: Empowering modern SOC teams with explainable AI, human-in-the-loop governance, and autonomous threat correlation.*
