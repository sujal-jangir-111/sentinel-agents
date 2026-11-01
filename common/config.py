"""Single source of configuration. Loads .env and exposes typed settings."""
import os
from dataclasses import dataclass, field
from typing import List, Set

from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_float(name: str, default: float) -> float:
    try:
        return float(_get(name, str(default)))
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    try:
        return int(_get(name, str(default)))
    except ValueError:
        return default


def _get_list(name: str) -> List[str]:
    return [p.strip() for p in _get(name).split(",") if p.strip()]


GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
ASI1_BASE_URL = "https://api.asi1.ai/v1/chat/completions"
GROQ_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"


def _default_provider() -> str:
    return "gemini" if _get("GEMINI_API_KEY") else "groq" if _get("GROQ_API_KEY") else "asi1"


@dataclass(frozen=True)
class Settings:
    # LLM used inside the agents and by the web assistant: "groq", "gemini" (default when GEMINI_API_KEY is set) or "asi1".
    # All are called through the same OpenAI-compatible chat-completions format.
    llm_provider: str = field(default_factory=lambda: _get("LLM_PROVIDER", _default_provider()).lower())
    gemini_api_key: str = field(default_factory=lambda: _get("GEMINI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: _get("GEMINI_MODEL", "gemini-3.5-flash"))
    # The chat assistant only routes requests, so it uses the much faster lite model (about 1.4 s vs 8-14 s)
    gemini_assistant_model: str = field(default_factory=lambda: _get("GEMINI_ASSISTANT_MODEL", "gemini-3.5-flash-lite"))
    # Tried once when the main model is overloaded, unreachable or retired
    gemini_fallback_model: str = field(default_factory=lambda: _get("GEMINI_FALLBACK_MODEL", "gemini-flash-lite-latest"))
    groq_api_key: str = field(default_factory=lambda: _get("GROQ_API_KEY"))
    groq_model: str = field(default_factory=lambda: _get("GROQ_MODEL", "openai/gpt-oss-20b"))
    groq_assistant_model: str = field(default_factory=lambda: _get("GROQ_ASSISTANT_MODEL"))     # default: GROQ_MODEL
    groq_fallback_model: str = field(default_factory=lambda: _get("GROQ_FALLBACK_MODEL"))
    asi1_api_key: str = field(default_factory=lambda: _get("ASI1_API_KEY"))
    asi1_model: str = field(default_factory=lambda: _get("ASI1_MODEL", "asi1-mini"))
    asi1_base_url: str = ASI1_BASE_URL
    # Code the Detective may send in one prompt. Groq's free plan refuses anything over 8,000 tokens a minute.
    llm_context_override: int = field(default_factory=lambda: _get_int("LLM_CONTEXT_CHARS", 0))

    def _by_provider(self, gemini: str, groq: str, asi1: str) -> str:
        return {"gemini": gemini, "groq": groq}.get(self.llm_provider, asi1)

    @property
    def llm_api_key(self) -> str:
        return self._by_provider(self.gemini_api_key, self.groq_api_key, self.asi1_api_key)

    @property
    def llm_model(self) -> str:
        return self._by_provider(self.gemini_model, self.groq_model, self.asi1_model)

    @property
    def llm_assistant_model(self) -> str:
        return self._by_provider(self.gemini_assistant_model, self.groq_assistant_model or self.groq_model, self.asi1_model)

    @property
    def llm_fallback_model(self) -> str:
        return self._by_provider(self.gemini_fallback_model, self.groq_fallback_model, "")

    @property
    def llm_base_url(self) -> str:
        return self._by_provider(GEMINI_BASE_URL, GROQ_BASE_URL, self.asi1_base_url)

    @property
    def writable_repos(self) -> Set[str]:
        """Repositories Sentinel may open pull requests on (CLAUDE.md §15), lower-cased."""
        return {r.lower() for r in (self.demo_repo_full_name, *self.github_write_allowlist) if r}

    @property
    def llm_context_chars(self) -> int:
        return self.llm_context_override or (6_000 if self.llm_provider == "groq" else 40_000)

    @property
    def llm_key_env(self) -> str:
        return self._by_provider("GEMINI_API_KEY", "GROQ_API_KEY", "ASI1_API_KEY")

    # GitHub / demo target
    github_token: str = field(default_factory=lambda: _get("GITHUB_TOKEN"))
    demo_repo_full_name: str = field(default_factory=lambda: _get("DEMO_REPO_FULL_NAME"))
    demo_service_url: str = field(default_factory=lambda: _get("DEMO_SERVICE_URL"))
    demo_admin_token: str = field(default_factory=lambda: _get("DEMO_ADMIN_TOKEN"))
    # Extra repos the executor may write to (in addition to DEMO_REPO_FULL_NAME)
    github_write_allowlist: List[str] = field(default_factory=lambda: _get_list("GITHUB_WRITE_ALLOWLIST"))

    # Agent seeds
    orchestrator_seed: str = field(default_factory=lambda: _get("ORCHESTRATOR_SEED"))
    watchdog_seed: str = field(default_factory=lambda: _get("WATCHDOG_SEED"))
    detective_seed: str = field(default_factory=lambda: _get("DETECTIVE_SEED"))
    scanner_seed: str = field(default_factory=lambda: _get("SCANNER_SEED"))
    executor_seed: str = field(default_factory=lambda: _get("EXECUTOR_SEED"))

    # Payment / chain
    orchestrator_wallet_address: str = field(default_factory=lambda: _get("ORCHESTRATOR_WALLET_ADDRESS"))
    remediation_price_atestfet: int = field(
        default_factory=lambda: _get_int("REMEDIATION_PRICE_ATESTFET", 100_000_000_000_000_000)
    )
    dorado_explorer_base: str = field(
        default_factory=lambda: _get("DORADO_EXPLORER_BASE", "https://explore-dorado.fetch.ai/transactions")
    )
    skip_payment: bool = field(default_factory=lambda: _get("SKIP_PAYMENT", "false").lower() == "true")

    # Remediation
    patch_max_attempts: int = field(default_factory=lambda: _get_int("PATCH_MAX_ATTEMPTS", 3))

    # Watchdog
    watchdog_targets: List[str] = field(default_factory=lambda: _get_list("WATCHDOG_TARGETS"))
    watchdog_interval_seconds: int = field(default_factory=lambda: _get_int("WATCHDOG_INTERVAL_SECONDS", 60))

    # Blast radius assumptions
    traffic_rpm: float = field(default_factory=lambda: _get_float("TRAFFIC_RPM", 120))
    avg_order_value_usd: float = field(default_factory=lambda: _get_float("AVG_ORDER_VALUE_USD", 40))
    conversion_rate: float = field(default_factory=lambda: _get_float("CONVERSION_RATE", 0.03))
    sla_target: float = field(default_factory=lambda: _get_float("SLA_TARGET", 0.999))


def get_settings() -> Settings:
    """Build settings from the current environment (re-read on each call)."""
    return Settings()


settings = get_settings()
