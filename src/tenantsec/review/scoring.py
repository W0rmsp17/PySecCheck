def severity_factor(s: str) -> int:
    return {"info":0, "low":1, "medium":2, "high":3, "critical":5}.get(s, 0)

def score_rule(weight: int, severity: str, prevalence: float = 1.0) -> float:
    return max(0.0, weight) * severity_factor(severity) * max(0.0, min(1.0, prevalence))
