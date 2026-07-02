from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from backend.schemas import AuditReport


def render_markdown(report: AuditReport) -> str:
    lines = [
        f"# Audit Report {report.task_id}",
        "",
        f"- Mode: `{report.mode}`",
        f"- Functions ranked: {len(report.risk_vectors)}",
        f"- Findings: {len(report.findings)}",
        f"- Warnings: {len(report.warnings)}",
        "",
        "## Workflow",
        "",
        "```json",
        str(report.workflow),
        "```",
        "",
        "## Risk Ranking",
        "",
        "| Rank | Contract | Function | R_func | Static | Anomaly | GCN | Knowledge | Consistency | Protection |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for idx, vector in enumerate(report.risk_vectors[:20], 1):
        lines.append(
            f"| {idx} | {vector.contract_name} | `{vector.function_signature}` | "
            f"{vector.r_func:.2f} | {vector.static_score:.2f} | {vector.anomaly_score:.2f} | "
            f"{vector.gcn_score:.2f} | {vector.knowledge_score:.2f} | {vector.consistency_score:.2f} | "
            f"{vector.protection_score:.2f} |"
        )
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No in-scope findings were generated.")
    for finding in report.findings:
        lines.extend([
            f"### {finding.finding_id} {finding.vulnerability_id}",
            "",
            f"- Target: `{finding.contract_name}.{finding.function_signature}`",
            f"- Status: `{finding.status}`",
            f"- Severity: `{finding.severity}`",
            f"- Confidence: `{finding.confidence:.2f}`",
            f"- Summary: {finding.summary}",
        ])
        if finding.recommendation:
            lines.append(f"- Recommendation: {finding.recommendation}")
        if finding.reasoning:
            lines.append(f"- Reasoning status: `{finding.reasoning.get('status', 'unknown')}`")
            reasoning_steps = finding.reasoning.get("reasoning", [])
            if reasoning_steps:
                lines.append("")
                lines.append("Reasoning:")
                for step in reasoning_steps[:5]:
                    lines.append(f"- {step}")
        if finding.verification_plan:
            goal = finding.verification_plan.get("goal")
            if goal:
                lines.append(f"- Verification goal: {goal}")
        if finding.repair_suggestion:
            strategy = finding.repair_suggestion.get("strategy")
            if strategy:
                lines.append(f"- Repair strategy: {strategy}")
        lines.append("")
    lines.extend(["## Warnings", ""])
    if not report.warnings:
        lines.append("No out-of-scope warnings were generated.")
    for warning in report.warnings:
        lines.extend([
            f"### {warning.warning_id} {warning.target_vulnerability}",
            "",
            f"- Target: `{warning.contract_name}.{warning.function_signature}`",
            f"- Score: `{warning.score:.2f}`",
            f"- Summary: {warning.summary}",
            f"- Recommended action: `{warning.recommended_action.get('action')}`",
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
