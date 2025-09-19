"""
Base verifier class for validating synthetic data.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Tuple
import json

class BaseVerifier(ABC):
    """Base class for all synthetic data verifiers."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def verify(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Verify the synthetic data.

        Args:
            data: The synthetic data to verify

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        pass

    def _log_issue(self, issue: str) -> str:
        """Format an issue with verifier name."""
        return f"[{self.name}] {issue}"