from __future__ import annotations
from typing import Dict, Any, List, Tuple
from tenantsec.core.findings import Finding
from tenantsec.review.scoring import score_rule
from tenantsec.review.rules import Rule

def run_rules(rules: List[Rule], sheets: Dict[str, Any]) -> Tuple[List[Finding], float]:
    findings: List[Finding] = []
    total = 0.0
    for r in rules:
        evidence = []
        try:
            evidence = r.evaluate(sheets) or []
        except Exception as e:
            evidence = [{"error": str(e)}]
        if evidence:
            total += score_rule(r.weight, r.severity, 1.0)
            findings.append(Finding(
                id=r.id, title=r.title, severity=r.severity,
                summary=r.description, remediation=r.remediation, docs=r.docs,
                evidence=evidence, tags=r.tags
            ))
    return findings, total
