# NETSENTINEL AI
### Autonomous Enterprise Network Discovery, Intelligence & Security Monitoring Platform

**Product Creator & Developer:** Sinan Mohammed  
**Specification:** [PRD.md](./PRD.md)

---

## Overview

**NETSENTINEL AI** transforms network scanning from a manual technical activity into a continuously updated, explainable, and intelligent enterprise security operation following the autonomous loop:

$$\text{Discover} \rightarrow \text{Identify} \rightarrow \text{Understand} \rightarrow \text{Analyze} \rightarrow \text{Prioritize} \rightarrow \text{Monitor} \rightarrow \text{Report}$$

### Three Independent Intelligence Layers
1. **Discovery Intelligence:** Authorized CIDR scope validator, Nmap execution engine (supporting both real Nmap binary and a deterministic multi-scenario Safe Lab Simulator), XML parser, and asset/port inventory.
2. **Statistical Security Intelligence (100% Independent of AI):** Port-to-Application intelligence (distinguishing conventional port expectations from actual Nmap service detections), state-aware change detection (`closed` vs. `filtered` vs. `unreachable` vs. `not_observed`), explainable `0–100` multi-factor risk engine, and statistical volatility prediction.
3. **Pluggable Hybrid AI Intelligence:** Evidence-linked security explanations supporting **Offline Deterministic Statistical Synthesis** (always available), **Local Ollama**, and **Cloud Gemini / OpenAI** with strict prompt-injection sanitization and zero shell execution.

---

## Quickstart (Local Windows / Linux / macOS)

### 1. Start the FastAPI Backend (Port `8000`)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\uvicorn app.main:app --reload --port 8000
```
*On first startup, the backend automatically seeds the 5 RBAC roles, authorized CIDR enclaves (`192.168.56.0/24` and `10.20.30.0/24`), a baseline scan, and an enterprise drift scan.*

- **Interactive OpenAPI Docs:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/api/v1/health

### 2. Start the Next.js Command Center (Port `3000`)
```powershell
cd frontend
npm install
npm run dev
```
- **Command Center UI:** http://localhost:3000

### 3. Run the Automated Test Suite
```powershell
cd backend
.\.venv\Scripts\pytest -v
```

