# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Configuration for K9X Sentinel.

`.env` says *where* and *which* (Ollama host, models, Kafka, GitHub);
`config.yaml` says *how* (sources, triage thresholds). `config.yaml` is read
through the framework's `load_yaml`, which expands ``${VAR:-default}``."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

from k9_aif_abb.k9_utils.config_loader import load_yaml

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

SEVERITIES = ["low", "medium", "high", "critical"]
REPO_URL = "https://github.com/k9aif/k9x-sentinel"


def load_config() -> Dict[str, Any]:
    cfg = load_yaml(ROOT / "config.yaml")
    # Granite Guardian is mandatory here: whatever config.yaml says, it is on
    # and fails closed.
    guardian = cfg.setdefault("governance", {}).setdefault("guardian", {})
    guardian["enabled"] = True
    guardian["on_unavailable"] = "fail_closed"
    guardian.setdefault("model", "granite4.1-guardian:8b")
    cfg.setdefault("ollama", {})["base_url"] = ollama_base_url()
    hil = cfg.setdefault("hil", {})
    hil["db_path"] = str(_under_root(hil.get("db_path") or "./runtime/hil_pending.db"))
    Path(hil["db_path"]).parent.mkdir(parents=True, exist_ok=True)
    cfg["inference"] = inference_config()
    return cfg


def _under_root(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


def ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")


def analysis_model() -> str:
    return os.environ.get("SENTINEL_MODEL", "qwen3.8:27b").strip()


def inference_config() -> Dict[str, Any]:
    """One catalog entry: the analysis model, for every agent call."""
    return {
        "router": {
            "type": "k9_model_router",
            "default_model": "analyst",
            "learning": {"enabled": False},
            "persistence": {"enabled": True, "provider": "sqlite",
                            "sqlite": {"db_path": str(ROOT / "runtime" / "k9_model_router.db")}},
        },
        "llm_factory": {
            "backend": "ollama", "provider": "ollama", "base_url": ollama_base_url(),
            "models": {"analyst": {"model": analysis_model(), "temperature": 0.1, "max_tokens": 4096}},
        },
        "model_catalog": {
            "default_model": "analyst",
            "models": {"analyst": {"provider": "ollama", "llm_ref": "analyst",
                                   "capabilities": ["analysis", "reasoning", "general"]}},
        },
    }


def kafka_broker() -> str:
    return os.environ.get("KAFKA_BROKER", "").strip()


def hil_detail() -> str:
    return "full" if os.environ.get("SENTINEL_HIL_DETAIL", "minimal").strip().lower() == "full" else "minimal"


def hil_approvers() -> List[str]:
    """k9x-hil users whose decisions Sentinel acts on (lower-case emails).
    Empty = any decision is accepted (preflight warns)."""
    raw = os.environ.get("SENTINEL_HIL_APPROVERS", "")
    return [a.strip().lower() for a in raw.split(",") if a.strip()]


def hil_overdue_days() -> float:
    """A case waiting longer than this is flagged overdue in HIL History."""
    try:
        return float(os.environ.get("SENTINEL_HIL_OVERDUE_DAYS", "7"))
    except ValueError:
        return 7.0


def public_url() -> str:
    return os.environ.get("SENTINEL_PUBLIC_URL", f"http://localhost:{port()}").rstrip("/")


def port() -> int:
    return int(os.environ.get("SENTINEL_PORT", "8114"))


def run_at() -> str:
    return os.environ.get("SENTINEL_RUN_AT", "06:00").strip()


def github() -> Dict[str, str]:
    mode = os.environ.get("SENTINEL_GITHUB_MODE", "dry_run").strip().lower()
    return {"mode": "live" if mode == "live" else "dry_run",
            "repo": os.environ.get("SENTINEL_GITHUB_REPO", "k9aif/k9-aif-framework").strip(),
            "token": os.environ.get("SENTINEL_GITHUB_TOKEN", "").strip()}


def catalog_path() -> str:
    return os.environ.get("SENTINEL_CATALOG_PATH", "").strip()


def credentials() -> Dict[str, str]:
    """Single login. No password configured = UI disabled (health only)."""
    return {"user": os.environ.get("SENTINEL_USER", "admin"),
            "password": os.environ.get("SENTINEL_PASSWORD", "")}


def db_mode() -> str:
    """SENTINEL_DB=postgres uses PostgreSQL (POSTGRES_* settings, schema
    SENTINEL_DB_SCHEMA); anything else is a local SQLite file (zero setup)."""
    return "postgres" if os.environ.get("SENTINEL_DB", "sqlite").strip().lower() in ("postgres", "postgresql") else "sqlite"


def postgres() -> Dict[str, Any]:
    return {"host": os.environ.get("POSTGRES_HOST", "localhost"), "port": int(os.environ.get("POSTGRES_PORT", "5432")),
            "user": os.environ.get("POSTGRES_USER", "postgres"), "database": os.environ.get("POSTGRES_DB", "k9x"),
            "schema": db_schema()}


def db_schema() -> str:
    return os.environ.get("SENTINEL_DB_SCHEMA", "k9sentinel").strip() or "k9sentinel"


def database_url() -> str:
    if db_mode() == "postgres":
        from sqlalchemy.engine import URL
        pg = postgres()
        return URL.create("postgresql+psycopg2", username=pg["user"], password=os.environ.get("POSTGRES_PASSWORD", ""),
                          host=pg["host"], port=pg["port"], database=pg["database"]).render_as_string(hide_password=False)
    return f"sqlite:///{db_path()}"


def db_path() -> Path:
    p = _under_root(os.environ.get("SENTINEL_DB_PATH", "./runtime/sentinel.db"))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def severity_at_least(value: str, floor: str) -> bool:
    try:
        return SEVERITIES.index(value) >= SEVERITIES.index(floor)
    except ValueError:
        return False


def sources(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(cfg.get("sentinel", {}).get("sources", []))
