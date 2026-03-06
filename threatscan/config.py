"""
ThreatScan Configuration
========================
Loads .env (or environment variables), validates them, and exposes a typed
Settings object consumed by every agent and integration module.

Usage:
    from threatscan.config import settings
    if settings.enable_llm_analysis and settings.anthropic_api_key:
        # use real LLM
"""

import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# Load .env if present
try:
    from dotenv import load_dotenv
    # Walk up to find .env relative to this file
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
    else:
        load_dotenv()  # try cwd
except ImportError:
    pass  # dotenv not installed; rely on real env vars

logger = logging.getLogger("threatscan.config")


def _bool(key: str, default: bool = False) -> bool:
    val = os.getenv(key, str(default)).strip().lower()
    return val in ("1", "true", "yes", "on")


def _int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except (ValueError, TypeError):
        return default


def _str(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def _list(key: str, default: list = None) -> list:
    raw = os.getenv(key, "")
    if not raw:
        return default or []
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass
class Settings:
    # ── LLM ──────────────────────────────────────────────────
    anthropic_api_key: Optional[str] = field(default_factory=lambda: _str("ANTHROPIC_API_KEY") or None)
    anthropic_model: str = field(default_factory=lambda: _str("ANTHROPIC_MODEL", "claude-opus-4-6"))
    anthropic_fast_model: str = field(default_factory=lambda: _str("ANTHROPIC_FAST_MODEL", "claude-haiku-4-5-20251001"))
    anthropic_max_tokens: int = field(default_factory=lambda: _int("ANTHROPIC_MAX_TOKENS", 4096))

    # ── Recon ─────────────────────────────────────────────────
    shodan_api_key: Optional[str] = field(default_factory=lambda: _str("SHODAN_API_KEY") or None)
    securitytrails_api_key: Optional[str] = field(default_factory=lambda: _str("SECURITYTRAILS_API_KEY") or None)
    virustotal_api_key: Optional[str] = field(default_factory=lambda: _str("VIRUSTOTAL_API_KEY") or None)
    ct_log_url: str = field(default_factory=lambda: _str("CT_LOG_URL", "https://crt.sh"))
    http_probe_timeout: int = field(default_factory=lambda: _int("HTTP_PROBE_TIMEOUT", 10))
    http_probe_concurrency: int = field(default_factory=lambda: _int("HTTP_PROBE_CONCURRENCY", 20))
    http_user_agent: str = field(default_factory=lambda: _str("HTTP_USER_AGENT", "ThreatScan/2.0 Security Scanner"))

    # ── Vuln intel ────────────────────────────────────────────
    nvd_api_key: Optional[str] = field(default_factory=lambda: _str("NVD_API_KEY") or None)
    osv_api_url: str = field(default_factory=lambda: _str("OSV_API_URL", "https://api.osv.dev"))
    snyk_api_token: Optional[str] = field(default_factory=lambda: _str("SNYK_API_TOKEN") or None)
    github_token: Optional[str] = field(default_factory=lambda: _str("GITHUB_TOKEN") or None)

    # ── Threat intel ──────────────────────────────────────────
    cisa_kev_url: str = field(default_factory=lambda: _str("CISA_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    greynoise_api_key: Optional[str] = field(default_factory=lambda: _str("GREYNOISE_API_KEY") or None)
    otx_api_key: Optional[str] = field(default_factory=lambda: _str("OTX_API_KEY") or None)

    # ── Vector memory ─────────────────────────────────────────
    qdrant_url: str = field(default_factory=lambda: _str("QDRANT_URL", "http://localhost:6333"))
    qdrant_api_key: Optional[str] = field(default_factory=lambda: _str("QDRANT_API_KEY") or None)
    qdrant_collection: str = field(default_factory=lambda: _str("QDRANT_COLLECTION", "threatscan_memory"))
    embedding_provider: str = field(default_factory=lambda: _str("EMBEDDING_PROVIDER", "anthropic"))

    # ── Static tools ──────────────────────────────────────────
    semgrep_app_token: Optional[str] = field(default_factory=lambda: _str("SEMGREP_APP_TOKEN") or None)
    semgrep_bin: str = field(default_factory=lambda: _str("SEMGREP_BIN", "semgrep"))
    bandit_bin: str = field(default_factory=lambda: _str("BANDIT_BIN", "bandit"))

    # ── Feature flags ─────────────────────────────────────────
    enable_real_http_probing: bool = field(default_factory=lambda: _bool("ENABLE_REAL_HTTP_PROBING", False))
    enable_llm_analysis: bool = field(default_factory=lambda: _bool("ENABLE_LLM_ANALYSIS", True))
    enable_threat_intel: bool = field(default_factory=lambda: _bool("ENABLE_THREAT_INTEL", True))
    enable_vector_memory: bool = field(default_factory=lambda: _bool("ENABLE_VECTOR_MEMORY", False))
    enable_static_tools: bool = field(default_factory=lambda: _bool("ENABLE_STATIC_TOOLS", False))

    # ── Runtime ───────────────────────────────────────────────
    log_level: str = field(default_factory=lambda: _str("LOG_LEVEL", "INFO").upper())
    log_file: Optional[str] = field(default_factory=lambda: _str("LOG_FILE") or None)
    max_parallel_tasks: int = field(default_factory=lambda: _int("MAX_PARALLEL_TASKS", 10))
    scan_timeout: int = field(default_factory=lambda: _int("SCAN_TIMEOUT", 300))
    output_dir: str = field(default_factory=lambda: _str("OUTPUT_DIR", "./scan_output"))
    report_formats: list = field(default_factory=lambda: _list("REPORT_FORMATS", ["json", "html"]))

    def __post_init__(self):
        # Logging setup
        logging.basicConfig(
            level=getattr(logging, self.log_level, logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            filename=self.log_file or None,
        )
        if not self.log_file:
            logging.getLogger().addHandler(logging.StreamHandler())

        os.makedirs(self.output_dir, exist_ok=True)

    # ── Convenience properties ─────────────────────────────────

    @property
    def has_llm(self) -> bool:
        """True if LLM calls are both enabled and have a key."""
        key = self.anthropic_api_key or ""
        return (
            self.enable_llm_analysis
            and bool(key)
            and key != "your_anthropic_api_key_here"
        )

    @property
    def has_shodan(self) -> bool:
        key = self.shodan_api_key or ""
        return bool(key) and key != "your_shodan_api_key_here"

    @property
    def has_virustotal(self) -> bool:
        key = self.virustotal_api_key or ""
        return bool(key) and key != "your_virustotal_api_key_here"

    @property
    def has_nvd_key(self) -> bool:
        key = self.nvd_api_key or ""
        return bool(key) and key != "your_nvd_api_key_here"

    @property
    def has_greynoise(self) -> bool:
        key = self.greynoise_api_key or ""
        return bool(key) and key != "your_greynoise_api_key_here"

    @property
    def has_qdrant(self) -> bool:
        return self.enable_vector_memory

    @property
    def has_static_tools(self) -> bool:
        return self.enable_static_tools

    def print_status(self):
        """Print a nice summary of which integrations are active."""
        def status(active): return "✓ ACTIVE" if active else "○ SIMULATION"
        print("\n┌─ ThreatScan Integration Status ─────────────────────┐")
        print(f"│  LLM Analysis (Anthropic)     {status(self.has_llm):<20}│")
        print(f"│  Real HTTP Probing            {status(self.enable_real_http_probing):<20}│")
        print(f"│  Shodan Recon                 {status(self.has_shodan):<20}│")
        print(f"│  VirusTotal Intel             {status(self.has_virustotal):<20}│")
        print(f"│  NVD Vuln Database            {status(self.has_nvd_key):<20}│")
        print(f"│  Threat Intel (GreyNoise/OTX) {status(self.has_greynoise):<20}│")
        print(f"│  Vector Memory (Qdrant)       {status(self.has_qdrant):<20}│")
        print(f"│  Static Tools (Semgrep/Bandit){status(self.has_static_tools):<20}│")
        print("└──────────────────────────────────────────────────────┘\n")


# Singleton — import this everywhere
settings = Settings()
