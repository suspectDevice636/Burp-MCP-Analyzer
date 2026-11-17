"""Runtime configuration, loaded from environment / .env."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

APP_NAME = "Burp MCP Analyzer"
APP_VERSION = "0.3.0"
APP_DESCRIPTION = (
    "Local, offline assistant that pulls traffic from Burp Suite (via its MCP "
    "extension), runs deterministic checks plus local-LLM triage, and tracks "
    "findings through to a report."
)

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # Server
    server_host: str = field(default_factory=lambda: os.getenv("SERVER_HOST", "127.0.0.1"))
    server_port: int = field(default_factory=lambda: int(os.getenv("SERVER_PORT", "8765")))
    api_token: str = field(default_factory=lambda: os.getenv("API_TOKEN", ""))
    debug: bool = field(default_factory=lambda: _bool("DEBUG", False))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    # Rotating log file for service events. Empty = <DATA_DIR>/analyzer.log; "off" disables it.
    log_file: str = field(default_factory=lambda: os.getenv("LOG_FILE", ""))

    # Ollama
    ollama_host: str = field(default_factory=lambda: os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "mistral"))
    ollama_timeout: float = field(default_factory=lambda: float(os.getenv("OLLAMA_TIMEOUT", "180")))
    ollama_keep_alive: str = field(default_factory=lambda: os.getenv("OLLAMA_KEEP_ALIVE", "30m"))
    ollama_num_ctx: int = field(default_factory=lambda: int(os.getenv("OLLAMA_NUM_CTX", "8192")))
    # Cap on tokens generated per triage call (0 = no cap). Stops a small model rambling until the timeout.
    ollama_num_predict: int = field(default_factory=lambda: int(os.getenv("OLLAMA_NUM_PREDICT", "1024")))
    ollama_temperature: float = field(default_factory=lambda: float(os.getenv("OLLAMA_TEMPERATURE", "0.1")))

    # Burp MCP extension
    burp_mcp_url: str = field(default_factory=lambda: os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876/mcp"))
    burp_mcp_transport: str = field(default_factory=lambda: os.getenv("BURP_MCP_TRANSPORT", "http").lower())  # http | sse
    # Some MCP servers only accept a loopback Host header. Set this to
    # "127.0.0.1:9876" if you connect through a port forward and get 403s.
    burp_host_header: str = field(default_factory=lambda: os.getenv("BURP_HOST_HEADER", ""))
    burp_timeout: float = field(default_factory=lambda: float(os.getenv("BURP_TIMEOUT", "60")))
    history_page_size: int = field(default_factory=lambda: int(os.getenv("HISTORY_PAGE_SIZE", "50")))

    # Scope: only traffic whose host (or host:port) matches is ever analyzed.
    scope_hosts: list[str] = field(default_factory=lambda: _list("SCOPE_HOSTS"))

    # Analysis
    llm_enabled: bool = field(default_factory=lambda: _bool("LLM_ENABLED", True))
    llm_skip_js: bool = field(default_factory=lambda: _bool("LLM_SKIP_JS", True))
    max_body_chars: int = field(default_factory=lambda: int(os.getenv("MAX_BODY_CHARS", "4000")))
    # Highest severity the model may assign (only when it reports high confidence;
    # otherwise capped at "low"). You raise severity yourself when you confirm.
    llm_severity_cap: str = field(default_factory=lambda: os.getenv("LLM_SEVERITY_CAP", "medium").lower())
    # Near-duplicate endpoints (same method, host, path template and status, e.g.
    # /api/products/1 and /api/products/2) are model-reviewed at most this many times.
    # 0 = review every one. The deterministic checks always run on everything.
    llm_max_per_endpoint: int = field(default_factory=lambda: int(os.getenv("LLM_MAX_PER_ENDPOINT", "3")))
    # Paths (substring match) never sent to the model: plumbing with nothing to find.
    llm_skip_paths: list[str] = field(
        default_factory=lambda: [p.lower() for p in _list(
            "LLM_SKIP_PATHS", "/socket.io/,/health,/ping,/favicon,/manifest.json")]
    )

    # Storage
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("DATA_DIR", "./data")))
    backup_dir: str = field(default_factory=lambda: os.getenv("BACKUP_DIR", ""))

    @property
    def log_file_path(self) -> str | None:
        if self.log_file.strip().lower() in ("off", "none", "false", "0"):
            return None
        return self.log_file.strip() or str(self.data_dir / "analyzer.log")

    @property
    def legacy_db_path(self) -> Path:
        """Where the single pre-engagements database used to live (imported once, then renamed)."""
        return self.data_dir / "analyzer.db"

    def validate(self) -> None:
        if self.server_host not in LOOPBACK_HOSTS and not self.api_token:
            raise RuntimeError(
                "API_TOKEN must be set when SERVER_HOST is not a loopback address."
            )
        if self.llm_severity_cap not in {"low", "medium", "high"}:
            raise RuntimeError("LLM_SEVERITY_CAP must be low, medium or high.")
        if self.burp_mcp_transport not in {"http", "sse"}:
            raise RuntimeError("BURP_MCP_TRANSPORT must be 'http' or 'sse'.")


settings = Settings()
