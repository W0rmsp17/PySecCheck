from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Optional, List, Dict, Any

Severity = Literal["info","low","medium","high","critical"]

@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    weight: int
    description: str = ""
    remediation: Optional[str] = None
    docs: Optional[str] = None
    tags: Optional[List[str]] = None

    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []  # override in concrete rules
