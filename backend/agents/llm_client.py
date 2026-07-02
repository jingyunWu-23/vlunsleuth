from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
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
                f"已进入推理流程，函数综合风险分 R_func={risk.get('r_func', 0)}。"
            ),
            "reasoning": [
                "当前使用占位推理结果，未调用外部大模型 API。",
                "在进入验证流程前，应结合模型证据、静态特征和知识库证据进行人工复核。",
            ],
            "location": target.get("critical_statements", [])[:5],
            "verification_plan": {
                "goal": "确认该疑似风险是否可达、是否具备可利用条件。",
                "static_checks": ["复核访问控制、外部调用、状态更新顺序和函数可达性。"],
                "dynamic_checks": ["为报告路径构造定向测试或 PoC。"],
            },
            "repair_suggestion": {
                "strategy": first_repair_strategy(knowledge, top_vulnerability),
                "side_effects": ["应用任何自动生成补丁前都需要人工复核。"],
                "post_fix_checks": ["重新执行审计，并运行针对性回归测试。"],
            },
            "confidence_adjustment": 0.0,
        }


class OpenAICompatibleLLMClient:
    """OpenAI-compatible chat completion client for real reasoning calls."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()

    def complete_json(self, system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
        self._validate_config()
        try:
            return self._complete_json(use_response_format=True, system_prompt=system_prompt, user_payload=user_payload)
        except RuntimeError as exc:
            if not is_response_format_error(str(exc)):
                raise
            return self._complete_json(use_response_format=False, system_prompt=system_prompt, user_payload=user_payload)

    def _complete_json(self, use_response_format: bool, system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = chat_completions_endpoint(self.config.base_url)
        request_body = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": (
                        "请返回符合 output_schema 的严格 JSON。不要使用 Markdown 包裹。所有自然语言内容必须使用简体中文。\n\n"
                        + json.dumps(user_payload, ensure_ascii=False)
                    ),
                },
            ],
        }
        if use_response_format:
            request_body["response_format"] = {"type": "json_object"}

        request = urllib.request.Request(
            endpoint,
            data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM API HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM API connection failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError(f"LLM API timed out after {self.config.timeout_seconds}s") from exc

        content = extract_chat_content(response_data)
        return parse_json_object(content)

    def _validate_config(self) -> None:
        missing = []
        if not self.config.base_url:
            missing.append("SCG_LLM_BASE_URL")
        if not self.config.api_key:
            missing.append("SCG_LLM_API_KEY")
        if not self.config.model or self.config.model == "fill-your-model":
            missing.append("SCG_LLM_MODEL")
        if missing:
            raise RuntimeError(f"Missing LLM configuration: {', '.join(missing)}")


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
        "VULN_REENTRANCY": "采用 checks-effects-interactions 模式，必要时加入 nonReentrant，并确保外部调用前已经完成关键状态更新。",
        "VULN_TIMESTAMP": "避免将 block.timestamp 作为关键决策来源；如确需时间条件，应使用更安全的时间窗口或可信预言机。",
        "VULN_DELEGATECALL": "避免对不可信目标执行 delegatecall，并通过严格访问控制和白名单限制升级或插件目标。",
        "VULN_UNCHECKED_LOW_LEVEL_CALLS": "检查低级调用返回值，并使用 require(success) 失败即回滚。",
        "VULN_CROSS_CONTRACT_RISK": "复核跨合约信任边界、目标地址可控性和调用链状态依赖。",
        "VULN_UNKNOWN_ANOMALY": "人工复核异常代码路径，并围绕高风险控制流和资产流添加针对性回归测试。",
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
    return "采用对应的安全编码模式，并通过针对性测试验证修复后的行为。"


def dumps_payload(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def chat_completions_endpoint(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return f"{base}/chat/completions"
    return f"{base}/v1/chat/completions"


def extract_chat_content(response_data: Dict[str, Any]) -> str:
    try:
        content = response_data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Unexpected LLM API response shape: {safe_json(response_data)}") from exc
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        content = "".join(parts)
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("LLM API returned empty content.")
    return content.strip()


def parse_json_object(content: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = json.loads(extract_json_substring(content))
    if not isinstance(parsed, dict):
        raise RuntimeError("LLM response JSON must be an object.")
    return parsed


def extract_json_substring(content: str) -> str:
    stripped = strip_markdown_fence(content)
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end <= start:
        raise RuntimeError(f"LLM response did not contain a JSON object: {content[:500]}")
    return stripped[start : end + 1]


def strip_markdown_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


def is_response_format_error(message: str) -> bool:
    lowered = message.lower()
    return "response_format" in lowered or "json_object" in lowered


def safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)[:1000]
    except Exception:
        return str(value)[:1000]
