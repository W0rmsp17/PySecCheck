from dataclasses import dataclass
from typing import Optional

@dataclass
class UserLite:
    id: str
    upn: str
    display_name: str
    job_title: Optional[str] = None
