from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from backend.function_risk.risk_score import normalize_vulnerability
from backend.schemas import AuditReport


def render_markdown(report: AuditReport) -> str:
    lines = [
        f"# 智能合约安全审计报告 {report.task_id}",
        "",
        f"- 检测模式：`{report.mode}`",
        f"- 参与风险排序的函数数：{len(report.risk_vectors)}",
        f"- 正式漏洞发现数：{len(report.findings)}",
        f"- 范围外风险警告数：{len(report.warnings)}",
        "",
        "## 执行工作流",
        "",
        "```json",
        str(report.workflow),
        "```",
        "",
        "## 函数风险排序",
        "",
        "| 排名 | 合约 | 函数 | 综合风险 | 静态特征 | 异常分 | GCN | 知识库 | 一致性 | 防护 |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for idx, vector in enumerate(report.risk_vectors[:20], 1):
        lines.append(
            f"| {idx} | {vector.contract_name} | `{vector.function_signature}` | "
            f"{vector.r_func:.2f} | {vector.static_score:.2f} | {vector.anomaly_score:.2f} | "
            f"{vector.gcn_score:.2f} | {vector.knowledge_score:.2f} | {vector.consistency_score:.2f} | "
            f"{vector.protection_score:.2f} |"
        )

    lines.extend(["", "## 正式漏洞发现", ""])
    if not report.findings:
        lines.append("未生成正式漏洞发现。")
    for finding in report.findings:
        vuln_label = format_vulnerability_label(finding.vulnerability_id)
        lines.extend([
            f"### {finding.finding_id} {vuln_label}",
            "",
            f"- 目标位置：`{finding.contract_name}.{finding.function_signature}`",
            f"- 状态：`{translate_status(finding.status)}`",
            f"- 风险等级：`{translate_severity(finding.severity)}`",
            f"- 置信度：`{finding.confidence:.2f}`",
            f"- 摘要：{finding.summary}",
        ])
        if finding.recommendation:
            lines.append(f"- 修复建议：{finding.recommendation}")
        append_reasoning(lines, finding)
        append_verification(lines, finding)
        if finding.repair_suggestion:
            strategy = finding.repair_suggestion.get("strategy")
            if strategy:
                lines.append(f"- 修复策略：{strategy}")
        lines.append("")

    lines.extend(["## 范围外风险警告", ""])
    if not report.warnings:
        lines.append("未生成范围外风险警告。")
    for warning in report.warnings:
        vuln_label = format_vulnerability_label(warning.target_vulnerability)
        lines.extend([
            f"### {warning.warning_id} {vuln_label}",
            "",
            f"- 目标位置：`{warning.contract_name}.{warning.function_signature}`",
            f"- 状态：`{translate_status(warning.status)}`",
            f"- 风险分数：`{warning.score:.2f}`",
            f"- 摘要：{warning.summary}",
            f"- 推荐操作：`{translate_action(warning.recommended_action.get('action'))}`",
            "",
        ])
    return "\n".join(lines)


def append_reasoning(lines: list[str], finding) -> None:
    if not finding.reasoning:
        return
    lines.append(f"- 推理状态：`{translate_status(finding.reasoning.get('status', 'unknown'))}`")
    reasoning_steps = finding.reasoning.get("reasoning", [])
    if reasoning_steps:
        lines.append("")
        lines.append("推理过程：")
        for step in reasoning_steps[:5]:
            lines.append(f"- {step}")


def append_verification(lines: list[str], finding) -> None:
    if not finding.verification_plan:
        return
    goal = finding.verification_plan.get("goal")
    if goal:
        lines.append(f"- 验证目标：{goal}")
    slither = finding.verification_plan.get("slither")
    if slither:
        lines.append(f"- Slither 验证：`{translate_verification_status(slither.get('status'))}`")
        if slither.get("summary"):
            lines.append(f"- Slither 结论：{slither.get('summary')}")
        matched = slither.get("matched_detectors") or []
        if matched:
            checks = ", ".join(str(item.get("check")) for item in matched if item.get("check"))
            if checks:
                lines.append(f"- Slither 命中规则：`{checks}`")
    llm_verification = finding.verification_plan.get("llm_verification")
    if llm_verification:
        lines.append(f"- 验证智能体结论：`{translate_verification_status(llm_verification.get('status'))}`")
        if llm_verification.get("summary"):
            lines.append(f"- 验证解释：{llm_verification.get('summary')}")
        if llm_verification.get("evidence_assessment"):
            lines.append(f"- 证据评估：{llm_verification.get('evidence_assessment')}")


def write_markdown(report: AuditReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def report_to_dict(report: AuditReport) -> dict:
    return asdict(report)


def format_vulnerability_label(vulnerability: str | None) -> str:
    canonical = normalize_vulnerability(vulnerability)
    name = translate_vulnerability(canonical)
    if canonical in {"UNKNOWN", ""}:
        return name
    return f"{name} ({canonical})"


def translate_vulnerability(vulnerability: str | None) -> str:
    canonical = normalize_vulnerability(vulnerability)
    mapping = {
        "VULN_REENTRANCY": "重入漏洞",
        "VULN_TIMESTAMP": "时间戳依赖",
        "VULN_DELEGATECALL": "不安全 delegatecall",
        "VULN_UNCHECKED_LOW_LEVEL_CALLS": "未检查低级调用返回值",
        "VULN_CROSS_CONTRACT_RISK": "跨合约调用风险",
        "VULN_UNKNOWN_ANOMALY": "行为异常",
        "GENERAL_RISK": "综合高风险函数",
        "UNKNOWN": "未知风险",
    }
    return mapping.get(canonical, str(vulnerability or "未知风险"))


def translate_status(status: str) -> str:
    mapping = {
        "suspected": "疑似",
        "confirmed": "已确认",
        "inconclusive": "无法确定",
        "rejected": "已排除",
        "in_scope": "范围内",
        "out_of_scope": "范围外",
        "screening_warning": "筛查警告",
        "rejected_false_positive": "已降级为误报",
        "anomaly_warning": "行为异常警告",
        "unknown": "未知",
    }
    return mapping.get(str(status), str(status))


def translate_verification_status(status: str | None) -> str:
    mapping = {
        "confirmed": "已确认",
        "rejected": "已排除",
        "inconclusive": "无法确定",
        "not_confirmed": "未确认",
        "completed": "已完成",
        "unavailable": "工具未安装",
        "timeout": "执行超时",
        "error": "执行失败",
        "unknown": "未知",
    }
    if not status:
        return "未知"
    return mapping.get(str(status), str(status))


def translate_severity(severity: str) -> str:
    mapping = {
        "high": "高危",
        "medium": "中危",
        "low": "低危",
    }
    return mapping.get(str(severity), str(severity))


def translate_action(action: str | None) -> str:
    mapping = {
        "start_new_scan": "发起对应专项检测",
        "review_high_risk_function": "人工复核高风险函数",
        "review_rejected_result": "复核已降级结论",
        "review_anomaly": "复核行为异常信号",
    }
    if not action:
        return "无"
    return mapping.get(str(action), str(action))
