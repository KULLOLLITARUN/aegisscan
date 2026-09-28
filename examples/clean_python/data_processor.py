"""
Data processing module with safe data structure manipulations and typed models.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class UserProfile:
    user_id: int
    username: str
    email: str
    tags: List[str] = field(default_factory=list)

    def sanitize_username(self) -> str:
        """Return lowercased trimmed username."""
        return self.username.strip().lower()


class DataProcessor:
    """Processes user profiles and filters dataset records safely."""

    def __init__(self, records: Optional[List[Dict[str, str]]] = None) -> None:
        self.records = records or []

    def filter_active_users(self, min_length: int = 3) -> List[Dict[str, str]]:
        """Filter user records based on valid username length."""
        return [
            record
            for record in self.records
            if len(record.get("username", "")) >= min_length
        ]

    def aggregate_by_domain(self) -> Dict[str, int]:
        """Aggregate user email counts by domain."""
        domain_counts: Dict[str, int] = {}
        for record in self.records:
            email = record.get("email", "")
            if "@" in email:
                domain = email.split("@")[-1].lower()
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        return domain_counts
