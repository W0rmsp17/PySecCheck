# src/tenantsec/core/findings.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Optional, List, Dict, Any

Severity = Literal["info", "low", "medium", "high", "critical"]

@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    summary: str
    remediation: Optional[str] = None
    docs: Optional[str] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    tags: Optional[List[str]] = None
    rule_version: Optional[str] = None
    profile: Optional[str] = None

    def as_text_block(self) -> str:
        lines = [
            f"[{self.severity.upper()}] {self.title}",
            f"  • id: {self.id}",
            f"  • {self.summary}",
        ]
        if self.remediation:
            lines.append(f"  • remediation: {self.remediation}")
        if self.docs:
            lines.append(f"  • docs: {self.docs}")
        if self.evidence:
            lines.append(f"  • evidence: {self.evidence}")
        return "\n".join(lines)
