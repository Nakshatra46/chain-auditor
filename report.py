"""
Human-readable + JSON report generation (the "output generation" stage).
"""
import json
from pattern_engine import AnalysisResult

SEVERITY_ICON = {
    "info": "  ",
    "low": " *",
    "medium": " !",
    "high": "!!",
    "critical": "XX",
}


def risk_label(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "MINIMAL"


def render_text(result: AnalysisResult) -> str:
    lines = []
    lines.append("=" * 64)
    lines.append(f" Chain-Mind Auditor — Contract Report")
    lines.append("=" * 64)
    lines.append(f" Address           : {result.address}")
    lines.append(f" Verified source   : {'Yes' if result.verified else 'No'}")
    lines.append(f" Contract name     : {result.contract_name}")
    lines.append(f" Compiler version  : {result.compiler_version}")
    lines.append(f" Risk score        : {result.risk_score}/100 "
                 f"({risk_label(result.risk_score)})")
    lines.append("-" * 64)
    lines.append(" Findings:")
    for f in result.flags:
        icon = SEVERITY_ICON.get(f.severity, "  ")
        lines.append(f"   [{icon}] ({f.severity.upper():<8}) {f.message}")
    lines.append("=" * 64)
    return "\n".join(lines)


def render_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
