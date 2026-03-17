# Burp MCP Analyzer

**Local offline pentest assistant** combining MCP (Model Context Protocol) server, Ollama LLM inference, and Burp Suite integration. Zero cloud exposure, fully private pentesting lab.

## Overview

- **Target Response Time:** < 3 seconds per analysis
- **Architecture:** Mac Mini #1 (8GB) = MCP router | Mac Mini #2 (32GB) = Ollama inference | Synology NAS = persistence
- **Tech Stack:** FastAPI, Ollama, Burp Suite, NAS storage

## Quick Start

See [SETUP.md](SETUP.md) for comprehensive setup documentation covering:

1. Environment setup (Python venv, dependencies)
2. FastAPI server skeleton & configuration
3. Core endpoints (health, analyze, findings)
4. Ollama integration
5. NAS persistence
6. Running the server
7. Burp integration
8. Deployment checklist & troubleshooting

## Architecture

```
┌─────────────────────┐
│  Burp Suite         │ (macOS)
│  (Security Testing) │
└──────────┬──────────┘
           │ HTTP POST
           ▼
┌─────────────────────────────────────────┐
│ Mac Mini #1 (8GB) - MCP Router          │
│ FastAPI Server (localhost:5000)         │
│ • Health check endpoint                 │
│ • Analysis endpoint (routes to Ollama)  │
│ • Findings storage endpoint             │
└────────┬────────────────────────┬───────┘
         │                        │
         │ HTTP                   │ SMB
         │ (Ollama)               │ (NAS)
         ▼                        ▼
┌──────────────────┐   ┌──────────────────┐
│ Mac Mini #2      │   │ Synology NAS     │
│ (32GB)           │   │ (6TB)            │
│ • Ollama Server  │   │ • Findings       │
│ • Model: Mistral │   │ • Cache          │
│   or Llama2      │   │ • Models         │
└──────────────────┘   └──────────────────┘
```

## Project Status

- [x] Architecture designed
- [x] Setup documentation complete
- [ ] FastAPI skeleton implementation
- [ ] Ollama integration testing
- [ ] Burp extension development
- [ ] NAS persistence testing
- [ ] Performance tuning

## Dependencies

- Python 3.10+
- FastAPI + Uvicorn
- HTTPX (async HTTP client)
- Python-dotenv (configuration)
- Ollama (running on Mac Mini #2)
- Synology NAS (or SMB-accessible storage)

See `requirements.txt` in [SETUP.md](SETUP.md) for full list.

## Getting Started

1. Clone this repo to Mac Mini #1
2. Follow [SETUP.md](SETUP.md) Phase 1-2 for environment setup
3. Configure `.env` with your IPs and NAS details
4. Start the FastAPI server
5. Test health endpoint
6. Develop Burp extension for HTTP POST

## Files

- **SETUP.md** — Comprehensive setup & implementation guide
- **requirements.txt** — Python dependencies (see SETUP.md)
- **config/** — Configuration templates
- **routes/** — API endpoint definitions
- **services/** — Ollama client & findings storage

## License

Private project.

---

**Version:** 0.1.0  
**Status:** Ready for implementation  
**Last Updated:** 2026-03-16
