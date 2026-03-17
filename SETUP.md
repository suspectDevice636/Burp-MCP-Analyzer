# Burp MCP Analyzer - Setup Documentation

## Project Overview

**Local offline pentest assistant** combining MCP (Model Context Protocol) server, Ollama LLM inference, and Burp Suite integration. Zero cloud exposure, fully private pentesting lab.

**Target Response Time:** < 3 seconds per analysis  
**Architecture:** Mac Mini #1 (8GB) = MCP router | Mac Mini #2 (32GB) = Ollama inference | Synology NAS = persistence

---

## System Requirements

### Mac Mini #1 (8GB) - MCP Server
- Python 3.10+
- ~2GB available RAM (FastAPI is lightweight)
- Network access to Mac Mini #2 (Ollama) on port 11434
- Network access to NAS (SMB/NFS mount)

### Mac Mini #2 (32GB) - Ollama
- Ollama installed and running
- Model loaded (Mistral 7B or Llama2 13B recommended)
- Listening on `localhost:11434` (or accessible IP)

### Synology NAS
- Shared folder accessible via SMB/NFS
- Mounted at `/mnt/pentest-lab/` on Mac Mini #1

---

## Phase 1: Environment Setup

### 1.1 Python Environment (Mac Mini #1)

```bash
# Create project directory
mkdir -p ~/projects/burp-mcp-analyzer
cd ~/projects/burp-mcp-analyzer

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### 1.2 Install Dependencies

```bash
# FastAPI + Uvicorn server
pip install fastapi uvicorn

# HTTP client for Ollama
pip install requests httpx

# Async utilities
pip install aiofiles asyncio-contextmanager

# Logging & config
pip install python-dotenv pydantic

# Optional: Better debugging
pip install python-multipart
```

**requirements.txt** (for version control):
```bash
fastapi==0.104.1
uvicorn==0.24.0
requests==2.31.0
httpx==0.25.1
python-dotenv==1.0.0
pydantic==2.5.0
aiofiles==23.2.1
```

Save with:
```bash
pip freeze > requirements.txt
```

---

## Phase 2: FastAPI Server Skeleton

### 2.1 Project Structure

```
burp-mcp-analyzer/
├── venv/                    # Python virtual environment
├── config/
│   └── config.py           # Configuration & constants
├── services/
│   ├── ollama_client.py    # Ollama integration
│   └── findings_store.py   # NAS persistence
├── routes/
│   ├── analyze.py          # POST /analyze endpoint
│   ├── findings.py         # POST /finding endpoint
│   └── health.py           # GET /health endpoint
├── main.py                 # FastAPI app entry point
├── .env                    # Local config (not in git)
├── .env.example            # Template
├── requirements.txt        # Dependencies
└── README.md               # Setup instructions
```

### 2.2 Configuration (config/config.py)

```python
import os
from dotenv import load_dotenv

load_dotenv()

# Server
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5000))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Ollama
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://192.168.1.100:11434")  # Mac Mini #2 IP
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", 30))  # seconds

# NAS
NAS_MOUNT_PATH = os.getenv("NAS_MOUNT_PATH", "/mnt/pentest-lab")
FINDINGS_DIR = os.path.join(NAS_MOUNT_PATH, "findings")
CACHE_DIR = os.path.join(NAS_MOUNT_PATH, "cache")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
```

### 2.3 Environment Variables (.env.example)

```bash
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
DEBUG=false

# Ollama (Mac Mini #2 IP address)
OLLAMA_HOST=http://192.168.1.100:11434
OLLAMA_MODEL=mistral:7b
OLLAMA_TIMEOUT=30

# NAS
NAS_MOUNT_PATH=/mnt/pentest-lab
NAS_USERNAME=admin
NAS_PASSWORD=your_password

# Logging
LOG_LEVEL=INFO
```

### 2.4 FastAPI Main Server (main.py)

```python
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import logging
import uvicorn
from config.config import SERVER_HOST, SERVER_PORT, DEBUG, LOG_LEVEL
from routes import health, analyze, findings

# Configure logging
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Burp MCP Analyzer",
    description="Offline pentest analysis server",
    version="0.1.0"
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(analyze.router, prefix="/api", tags=["Analysis"])
app.include_router(findings.router, prefix="/api", tags=["Findings"])

@app.on_event("startup")
async def startup_event():
    logger.info("Starting Burp MCP Analyzer...")
    # Initialize NAS mounts, verify Ollama connectivity
    
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Burp MCP Analyzer...")

@app.get("/")
async def root():
    return {"status": "Burp MCP Analyzer running"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=DEBUG,
        log_level=LOG_LEVEL.lower()
    )
```

---

## Phase 3: Core Endpoints

### 3.1 Health Check (routes/health.py)

```python
from fastapi import APIRouter, HTTPException
import httpx
from config.config import OLLAMA_HOST, OLLAMA_TIMEOUT
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/health")
async def health_check():
    """
    Burp plugin calls this to verify MCP server is alive.
    Checks Ollama connectivity.
    """
    try:
        # Verify Ollama is reachable
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            if response.status_code != 200:
                raise HTTPException(status_code=503, detail="Ollama unavailable")
        
        return {
            "status": "healthy",
            "ollama": "connected",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")
```

### 3.2 Analysis Endpoint (routes/analyze.py)

```python
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging
from services.ollama_client import analyze_request

logger = logging.getLogger(__name__)
router = APIRouter()

class BurpRequest(BaseModel):
    method: str
    url: str
    headers: dict
    body: str = ""
    response_body: str = ""

@router.post("/analyze")
async def analyze(request: BurpRequest):
    """
    Receive HTTP request from Burp, send to Ollama for analysis.
    
    Returns vulnerability assessment and recommendations.
    """
    try:
        logger.info(f"Analyzing: {request.method} {request.url}")
        
        # Format request for Ollama analysis
        analysis = await analyze_request(request)
        
        return {
            "status": "success",
            "request_url": request.url,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
```

### 3.3 Findings Storage (routes/findings.py)

```python
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging
from services.findings_store import save_finding

logger = logging.getLogger(__name__)
router = APIRouter()

class Finding(BaseModel):
    title: str
    severity: str  # Low, Medium, High, Critical
    description: str
    affected_url: str
    remediation: str
    tags: list = []

@router.post("/finding")
async def store_finding(finding: Finding):
    """
    Save finding to NAS persistent storage.
    """
    try:
        result = await save_finding(finding)
        return {
            "status": "success",
            "finding_id": result["id"],
            "saved_to": result["path"]
        }
    except Exception as e:
        logger.error(f"Finding storage failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/findings")
async def list_findings():
    """
    List all stored findings.
    """
    try:
        findings = await list_findings()
        return {
            "status": "success",
            "count": len(findings),
            "findings": findings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

---

## Phase 4: Ollama Integration

### 4.1 Ollama Client (services/ollama_client.py)

```python
import httpx
import logging
from config.config import OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_TIMEOUT
from typing import Dict

logger = logging.getLogger(__name__)

async def analyze_request(burp_request) -> Dict:
    """
    Send HTTP request to Ollama for security analysis.
    """
    # Format the request as a prompt for Ollama
    prompt = f"""Analyze this HTTP request for security vulnerabilities:

Method: {burp_request.method}
URL: {burp_request.url}
Headers: {burp_request.headers}
Body: {burp_request.body}

Response: {burp_request.response_body}

Identify:
1. Potential vulnerabilities
2. Security headers (present/missing)
3. Authentication/authorization issues
4. Input validation concerns
5. Risk level (Low/Medium/High/Critical)

Respond in JSON format with keys: vulnerabilities, headers, auth, input_validation, risk_level"""

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3  # Lower temp for consistency
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama error: {response.text}")
            
            result = response.json()
            return parse_analysis(result["response"])
    
    except Exception as e:
        logger.error(f"Ollama request failed: {e}")
        raise

def parse_analysis(response_text: str) -> Dict:
    """
    Parse Ollama response into structured JSON.
    """
    # Extract JSON from response (Ollama may wrap in markdown)
    import json
    import re
    
    try:
        # Try to extract JSON block
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        else:
            return {"raw_response": response_text}
    except json.JSONDecodeError:
        return {"raw_response": response_text}
```

---

## Phase 5: NAS Persistence

### 5.1 Findings Storage (services/findings_store.py)

```python
import os
import json
import logging
from pathlib import Path
from datetime import datetime
from config.config import FINDINGS_DIR, CACHE_DIR

logger = logging.getLogger(__name__)

async def save_finding(finding) -> Dict:
    """
    Save finding to NAS with unique ID.
    """
    # Create finding ID from timestamp
    finding_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Ensure directory exists
    Path(FINDINGS_DIR).mkdir(parents=True, exist_ok=True)
    
    # Build finding document
    finding_doc = {
        "id": finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "description": finding.description,
        "affected_url": finding.affected_url,
        "remediation": finding.remediation,
        "tags": finding.tags,
        "created_at": datetime.now().isoformat()
    }
    
    # Write to NAS
    file_path = os.path.join(FINDINGS_DIR, f"{finding_id}.json")
    try:
        with open(file_path, "w") as f:
            json.dump(finding_doc, f, indent=2)
        
        logger.info(f"Finding saved: {file_path}")
        return {
            "id": finding_id,
            "path": file_path
        }
    except Exception as e:
        logger.error(f"Failed to save finding: {e}")
        raise

async def list_findings():
    """
    List all findings from NAS.
    """
    findings = []
    
    if not os.path.exists(FINDINGS_DIR):
        return findings
    
    try:
        for filename in os.listdir(FINDINGS_DIR):
            if filename.endswith(".json"):
                file_path = os.path.join(FINDINGS_DIR, filename)
                with open(file_path, "r") as f:
                    finding = json.load(f)
                    findings.append(finding)
        
        return sorted(findings, key=lambda x: x["created_at"], reverse=True)
    except Exception as e:
        logger.error(f"Failed to list findings: {e}")
        return []
```

---

## Phase 6: Running the Server

### 6.1 Start MCP Server

```bash
cd ~/projects/burp-mcp-analyzer
source venv/bin/activate

# Run with default config
python main.py

# Output:
# INFO:     Started server process [12345]
# INFO:     Uvicorn running on http://0.0.0.0:5000 (Press CTRL+C to quit)
```

### 6.2 Test Server

```bash
# In another terminal:

# Health check
curl http://localhost:5000/api/health

# Analyze request
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://example.com/api/users",
    "headers": {"Authorization": "Bearer token123"},
    "body": ""
  }'

# Save finding
curl -X POST http://localhost:5000/api/finding \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Missing Security Header",
    "severity": "Medium",
    "description": "X-Frame-Options header missing",
    "affected_url": "https://example.com",
    "remediation": "Add X-Frame-Options: DENY header"
  }'
```

---

## Phase 7: NAS Mount Setup

### 7.1 Mount Synology NAS (Mac Mini #1)

```bash
# Create mount point
sudo mkdir -p /mnt/pentest-lab

# Mount via SMB (adjust IP & share name)
sudo mount -t smbfs //admin:password@192.168.1.50/pentest-lab /mnt/pentest-lab

# Verify mount
ls -la /mnt/pentest-lab

# Create required directories
mkdir -p /mnt/pentest-lab/{findings,cache,models}
```

### 7.2 Auto-mount at Startup

Add to `/etc/fstab`:
```
//192.168.1.50/pentest-lab /mnt/pentest-lab smbfs credentials=/etc/smb-credentials,uid=501,gid=20,file_mode=0755,dir_mode=0755 0 0
```

Create `/etc/smb-credentials`:
```
username=admin
password=your_password
```

Protect credentials:
```bash
sudo chmod 600 /etc/smb-credentials
```

---

## Phase 8: Burp Integration (Placeholder)

### 8.1 Burp Extension Concept

Simple HTTP POST to send intercepted requests:

```python
# Burp extension would:
# 1. Intercept request in Burp
# 2. POST to http://localhost:5000/api/analyze
# 3. Display analysis in Burp UI
# 4. Option to save as finding
```

---

## Deployment Checklist

- [ ] Python 3.10+ installed on Mac Mini #1
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (requirements.txt)
- [ ] `.env` file configured with correct IPs
- [ ] NAS mounted and verified accessible
- [ ] Ollama running on Mac Mini #2 (port 11434)
- [ ] FastAPI server starts without errors
- [ ] Health check passes
- [ ] Ollama connectivity confirmed
- [ ] Can POST to /analyze endpoint
- [ ] Findings save to NAS

---

## Troubleshooting

### Ollama Connection Failed
```bash
# On Mac Mini #2, verify Ollama is running
curl http://localhost:11434/api/tags

# On Mac Mini #1, check network connectivity
ping 192.168.1.100  # Adjust IP
```

### NAS Mount Issues
```bash
# Check mount status
mount | grep pentest-lab

# Remount if needed
sudo umount /mnt/pentest-lab
sudo mount -t smbfs //admin:password@192.168.1.50/pentest-lab /mnt/pentest-lab
```

### FastAPI Won't Start
```bash
# Check port availability
lsof -i :5000

# Verify dependencies
pip list | grep fastapi
```

---

## Next Steps

1. Deploy this skeleton on Mac Mini #1
2. Test Ollama integration
3. Develop Burp extension/plugin for HTTP POST
4. Iterate analysis prompts for better results
5. Build UI dashboard (optional)

---

**Version:** 0.1.0  
**Last Updated:** 2026-03-16  
**Status:** Ready for implementation
