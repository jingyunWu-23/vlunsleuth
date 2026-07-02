from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

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
        lines.extend([
            f"### {finding.finding_id} {finding.vulnerability_id}",
            "",
            f"- 目标位置：`{finding.contract_name}.{finding.function_signature}`",
            f"- 状态：`{translate_status(finding.status)}`",
            f"- 风险等级：`{translate_severity(finding.severity)}`",
            f"- 置信度：`{finding.confidence:.2f}`",
            f"- 摘要：{finding.summary}",
        ])
        if finding.recommendation:
            lines.append(f"- 修复建议：{finding.recommendation}")
        if finding.reasoning:
            lines.append(f"- 推理状态：`{translate_status(finding.reasoning.get('status', 'unknown'))}`")
            reasoning_steps = finding.reasoning.get("reasoning", [])
            if reasoning_steps:
                lines.append("")
                lines.append("推理过程：")
                for step in reasoning_steps[:5]:
                    lines.append(f"- {step}")
        if finding.verification_plan:
            goal = finding.verification_plan.get("goal")
            if goal:
                lines.append(f"- 验证目标：{goal}")
        if finding.repair_suggestion:
            strategy = finding.repair_suggestion.get("strategy")
            if strategy:
                lines.append(f"- 修复策略：{strategy}")
        lines.append("")
    lines.extend(["## 范围外风险警告", ""])
    if not report.warnings:
        lines.append("未生成范围外风险警告。")
    for warning in report.warnings:
        lines.extend([
            f"### {warning.warning_id} {warning.target_vulnerability}",
            "",
            f"- 目标位置：`{warning.contract_name}.{warning.function_signature}`",
            f"- 风险分数：`{warning.score:.2f}`",
            f"- 摘要：{warning.summary}",
            f"- 推荐操作：`{translate_action(warning.recommended_action.get('action'))}`",
            "",
        ])
    return "\n".join(lines)


def write_markdown(report: AuditReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def report_to_dict(report: AuditReport) -> dict:
    return asdict(report)


def translate_status(status: str) -> str:
    mapping = {
        "suspected": "疑似",
        "inconclusive": "无法确定",
        "rejected": "已排除",
        "in_scope": "范围内",
        "out_of_scope": "范围外",
        "screening_warning": "筛查警告",
        "unknown": "未知",
    }
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
    }
    if not action:
        return "无"
    return mapping.get(str(action), str(action))
