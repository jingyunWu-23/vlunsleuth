from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class LLMConfig:
    provider: str = "placeholder"
    model: str = "fill-your-model"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.2
    timeout_seconds: int = 60

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            provider=os.environ.get("SCG_LLM_PROVIDER", "placeholder"),
            model=os.environ.get("SCG_LLM_MODEL", "fill-your-model"),
            api_key=os.environ.get("SCG_LLM_API_KEY", ""),
            base_url=os.environ.get("SCG_LLM_BASE_URL", ""),
            temperature=float(os.environ.get("SCG_LLM_TEMPERATURE", "0.2")),
            timeout_seconds=int(os.environ.get("SCG_LLM_TIMEOUT", "60")),
        )


class LLMClient:
    def complete_json(self, system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class PlaceholderLLMClient:
    """Deterministic local fallback used until the real LLM API is filled in."""

    def complete_json(self, system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
        target = user_payload.get("target", {})
        risk = user_payload.get("risk", {})
        evidence = user_payload.get("evidence", [])
        knowledge = user_payload.get("knowledge_context", {})
        top_vulnerability = first_vulnerability(evidence)
        return {
            "status": "suspected",
            "candidate_vulnerability": top_vulnerability,
            "summary": (
                f"{target.get('contract_name', 'unknown')}.{target.get('function_name', 'unknown')} "
                f"is selected for reasoning with R_func={risk.get('r_func', 0)}."
            ),
            "reasoning": [
                "This is placeholder reasoning generated without an external LLM API.",
                "Model, static, and knowledge evidence should be reviewed together before verification.",
            ],
            "location": target.get("critical_statements", [])[:5],
            "verification_plan": {
                "goal": "Confirm whether the suspected risk is reachable and exploitable.",
                "static_checks": ["Review guards, external calls, state updates, and function reachability."],
                "dynamic_checks": ["Create a focused test or PoC for the reported path."],
            },
            "repair_suggestion": {
                "strategy": first_repair_strategy(knowledge, top_vulnerability),
                "side_effects": ["Manual review is required before applying any generated patch."],
                "post_fix_checks": ["Re-run the audit and targeted regression tests."],
            },
            "confidence_adjustment": 0.0,
        }


class OpenAICompatibleLLMClient:
    """API hook for the real model.

    Fill this method with your own API call. Keep the return value as a JSON-like
    dict matching the structure used by PlaceholderLLMClient.
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()

    def complete_json(self, system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
        # TODO: Fill this with your preferred large-model API call.
        #
        # Expected behavior:
        # 1. Send system_prompt and json.dumps(user_payload, ensure_ascii=False)
        #    to your model endpoint.
        # 2. Ask the model to return strict JSON.
        # 3. Parse the response into dict and return it.
        #
        # Suggested environment variables:
        #   SCG_LLM_PROVIDER
        #   SCG_LLM_BASE_URL
        #   SCG_LLM_API_KEY
        #   SCG_LLM_MODEL
        #   SCG_LLM_TEMPERATURE
        raise NotImplementedError("Fill OpenAICompatibleLLMClient.complete_json() with your LLM API call.")


def build_llm_client(config: LLMConfig | None = None) -> LLMClient:
    config = config or LLMConfig.from_env()
    if config.provider.lower() in {"openai", "openai_compatible", "custom"}:
        return OpenAICompatibleLLMClient(config)
    return PlaceholderLLMClient()


def first_vulnerability(evidence: list) -> str:
    for item in evidence:
        if item.get("vulnerability_id"):
            return item["vulnerability_id"]
    return "VULN_UNKNOWN_ANOMALY"


def first_repair_strategy(knowledge_context: Dict[str, Any], vulnerability: str = "") -> str:
    defaults = {
        "VULN_REENTRANCY": "Apply checks-effects-interactions, consider nonReentrant, and verify state is updated before external interaction.",
        "VULN_TIMESTAMP": "Avoid using block.timestamp as a critical decision source; use safer time windows or trusted oracle logic where appropriate.",
        "VULN_DELEGATECALL": "Avoid delegatecall to untrusted targets and restrict upgrade or plugin targets through strict access control and allowlists.",
        "VULN_UNCHECKED_LOW_LEVEL_CALLS": "Check low-level call return values and fail closed with require(success).",
        "VULN_CROSS_CONTRACT_RISK": "Review cross-contract trust boundaries, target controllability, and call-chain state dependencies.",
        "VULN_UNKNOWN_ANOMALY": "Manually review anomalous code paths and add targeted regression tests around risky control and asset flows.",
    }
    if vulnerability in defaults:
        return defaults[vulnerability]
    for item in knowledge_context.get("items", []):
        content = item.get("content", {})
        if isinstance(content, dict):
            if content.get("repair_strategy"):
                return str(content["repair_strategy"])
            if content.get("recommendation"):
                return str(content["recommendation"])
    return "Apply the corresponding secure coding pattern and verify behavior with targeted tests."


def dumps_payload(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)
