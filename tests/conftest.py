# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Every test gets its own SQLite files and no network-dependent governance."""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Pinned before sentinel.settings loads the developer's .env (load_dotenv never
# overrides a variable that is already set), so tests don't depend on it.
os.environ["K9_ENV"] = "development"
os.environ["KAFKA_BROKER"] = ""
os.environ["SENTINEL_GITHUB_MODE"] = "dry_run"
os.environ["SENTINEL_GITHUB_TOKEN"] = ""
os.environ["SENTINEL_HIL_DETAIL"] = "minimal"
os.environ["SENTINEL_HIL_APPROVERS"] = ""
os.environ["SENTINEL_PASSWORD"] = ""
os.environ["SENTINEL_CATALOG_PATH"] = ""
os.environ["SENTINEL_PUBLIC_URL"] = "http://localhost:8114"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "sentinel.db"))
    monkeypatch.setenv("SENTINEL_HIL_DB_PATH", str(tmp_path / "hil_pending.db"))
    from sentinel import store
    store.init()
    yield tmp_path


@pytest.fixture
def shield_only(monkeypatch):
    """Agents screen with Shield only (no Ollama/Guardian in unit tests)."""
    from k9_aif_abb.k9_security.vulnerability.shield_governance import ShieldGovernance
    from sentinel.agents import common
    monkeypatch.setattr(common, "build_governance", lambda cfg: ShieldGovernance(config=cfg))
