# Burp MCP Analyzer

A local, offline assistant for reviewing Burp Suite traffic. It pulls proxy history from Burp's
MCP extension, runs deterministic checks, asks a local Ollama model to triage what's left, and
tracks each finding from **candidate → confirmed → reported** so only things you've verified reach
the report.

> ## ⚠ Authorized use only
>
> This tool analyzes HTTP traffic captured in Burp Suite. **Use it only on systems and applications you
> own or have explicit, written permission to test**: a signed engagement or rules of engagement for a
> client, or the published scope of a bug bounty or vulnerability disclosure program. Testing anything
> else may be illegal (for example under the US CFAA, the UK Computer Misuse Act or equivalent laws
> elsewhere) regardless of your intent.
>
> - **Stay in scope.** Set each engagement's scope and keep to it, including the program's own rules
>   on rate limits, prohibited techniques, excluded assets and what data you may access or keep. This tool
>   only reads what Burp has captured; it sends nothing to the target. The testing that generates that
>   traffic is yours, and so is the responsibility for it.
> - **Handle client data with care.** Captured traffic can contain credentials, tokens and personal data.
>   It is stored unencrypted in `data/` on the machine running this service and sent only to the Ollama
>   host you configure. Protect that disk and network, set `API_TOKEN`, and delete engagement data when
>   your agreement says to.
> - **AI output is unreliable.** The model and the automated checks produce *leads*, not verdicts. They
>   miss things and can be wrong or invent details. Verify every finding yourself before you report it.
> - **No warranty.** This software is provided "as is", without warranty of any kind, and the authors
>   accept no liability for its use or misuse. Nothing here is legal advice. You are responsible for
>   complying with the law, your contracts and the program rules that apply to you.

```
Burp (VM) ──MCP──▶  this service  ──▶ Ollama (local model)
 proxy history        checks + triage      JSON-schema output, evidence must be quoted
                          │
                          ▼
                   SQLite (local disk)  ──▶ Markdown report
```

**What to expect:** it is a second pair of eyes and a drafting aid, not a scanner replacement. It
will surface things worth a look (exposed data, error leaks, IDOR candidates); you confirm them.
Logic and authorization flaws mostly still need you.

**Features:** a separate workspace per client engagement (pentest or bug bounty), one-shot and live
scans with pause/resume/stop, evidence-checked model findings, OWASP WSTG v4.2 tagging and coverage,
a review UI, and Markdown reports.

## Quick start

Needs Python 3.10+ (3.12 recommended), Burp Suite with the **MCP Server** extension, and an Ollama
server.

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env      # then edit it: see Configuration below
.venv/bin/python main.py
```

1. **Burp:** install **MCP Server** from the BApp Store and enable it in Burp's **MCP** tab. Approve
   the history request when Burp asks (or enable auto-approve for history). The extension has **no
   authentication**, so keep it on loopback or restrict who can reach it.
2. **Ollama:** `ollama pull mistral` (or a larger model) on the machine running Ollama.
3. **Open** `http://localhost:8765/ui/`, enter your API token, create an **engagement** (name, type,
   and the hosts you are authorized to test), click **Scan Burp…**, review the findings, then
   **Report…**.

More detail, including port forwards and 403 errors, is in
[setup and troubleshooting](docs/setup-and-troubleshooting.md).

## Configuration

Settings live in `.env` (copy `.env.example`; every option is commented there). The ones you will
touch first:

| Setting | What it is |
|---|---|
| `API_TOKEN` | Shared key for the UI and API. **Required** if `SERVER_HOST` is not loopback. |
| `SERVER_HOST` / `SERVER_PORT` | Where this service listens. Default `127.0.0.1:8765`. Use `0.0.0.0` for LAN access. |
| `BURP_MCP_URL` | Burp's MCP endpoint, e.g. `http://127.0.0.1:9876/mcp`. |
| `BURP_HOST_HEADER` | Set to `127.0.0.1:9876` if you reach Burp through a port forward and get 403s. |
| `OLLAMA_HOST` / `OLLAMA_MODEL` | Where Ollama runs and which model to use. |

Scope, client name and engagement type are set per engagement in the UI, not in `.env`.

## Documentation

- [How it works](docs/how-it-works.md): how a finding is produced, the quality gate, safety.
- [Engagements and reports](docs/engagements-and-reports.md): per-client workspaces, pentest vs bug bounty reports.
- [Scanning](docs/scanning.md): once vs live, pause/resume/stop, speed and the model queue.
- [OWASP WSTG coverage](docs/wstg.md): test tagging and the coverage view.
- [Using the UI and API](docs/usage.md): the review page and `curl` examples.
- [Setup details and troubleshooting](docs/setup-and-troubleshooting.md): Burp/Ollama setup, logs, known limitations.

## Tests

```bash
.venv/bin/python -m pytest
```

## License

MIT, see [LICENSE](LICENSE). The authorized-use notice at the top of this file is a request and a
reminder, not a license condition: you remain responsible for how you use the software.
