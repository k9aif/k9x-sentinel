# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Shared base for Sentinel agents plus the agent-YAML config loader.

Every agent runs with real governance: k9x Shield chained with Granite
Guardian. Every model call goes through the framework's llm_invoke."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from k9_aif_abb.k9_core.agent.base_agent import BaseAgent
from k9_aif_abb.k9_governance.chained_governance import ChainedGovernance
from k9_aif_abb.k9_governance.guardian_governance import GuardianGovernance
from k9_aif_abb.k9_inference.models.inference_request import InferenceRequest
from k9_aif_abb.k9_security.vulnerability.shield_governance import ShieldGovernance
from k9_aif_abb.k9_utils.llm_invoke import llm_invoke

_YAML_DIR = Path(__file__).resolve().parent / "yaml"


def _snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def agent_config(agent_name: str, global_config: Dict[str, Any]) -> Dict[str, Any]:
    """agents/yaml/<snake>.yaml (role/goal) merged over the app config."""
    path = _YAML_DIR / f"{_snake(agent_name)}.yaml"
    local = yaml.safe_load(path.read_text()) if path.exists() else {}
    return {**global_config, **(local or {})}


def build_governance(config: Dict[str, Any]) -> ChainedGovernance:
    """Shield first (cheap, deterministic), then Guardian (semantic)."""
    return ChainedGovernance(ShieldGovernance(config=config), GuardianGovernance(config=config), config=config)


class SentinelAgent(BaseAgent):
    layer = "K9X Sentinel Agent SBB"

    def __init__(self, config: Optional[Dict[str, Any]] = None, monitor=None, **kwargs):
        config = config or {}
        if kwargs.get("governance") is None:
            kwargs["governance"] = build_governance(config)
        super().__init__(config=config, monitor=monitor, **kwargs)

    def ask(self, prompt: str, system_prompt: str, task_type: str = "analysis") -> str:
        """One model call through llm_invoke. Raises RuntimeError on failure."""
        req = InferenceRequest(prompt=prompt, system_prompt=system_prompt, task_type=task_type,
                               temperature=0.1, metadata={"agent": self.__class__.__name__})
        resp = llm_invoke(self.config, req, max_retries=2, retry_delay_s=10)
        return resp.output or ""
