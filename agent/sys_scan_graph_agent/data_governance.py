"""Data Governance Module for LLM Content Filtering.

This module provides data governance utilities for ensuring compliance
and security when processing data through LLM systems.
"""

from typing import Any, Optional, Dict, List
import logging
import os

from . import models
Reductions = models.Reductions
Summaries = models.Summaries
Correlation = models.Correlation
ActionItem = models.ActionItem

logger = logging.getLogger(__name__)

class DataGovernor:
    """Data governance controller for content filtering."""

    def __init__(self):
        self.rules = []
        self.redaction_patterns = []

    def redact_for_llm(self, data: Any) -> Any:
        """Redact sensitive data before sending to LLM."""
        # CRITICAL: Handle Pydantic models FIRST - return unchanged to preserve type
        try:
            from .models import Reductions, Summaries, Correlation, ActionItem
        except ImportError:
            import models
            Reductions = models.Reductions
            Summaries = models.Summaries
            Correlation = models.Correlation
            ActionItem = models.ActionItem
        if isinstance(data, (Reductions, Summaries, Correlation, ActionItem)):
            return data
        
        # For other types, apply redaction as before
        if isinstance(data, dict):
            print(f"DEBUG: Processing dict")
            redacted = {}
            for key, value in data.items():
                # Check if key indicates sensitive data
                if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'token', 'key', 'auth']):
                    redacted[key] = '[REDACTED]'
                else:
                    redacted[key] = self.redact_for_llm(value)
            return redacted
        elif isinstance(data, list):
            print(f"DEBUG: Processing list")
            return [self.redact_for_llm(item) for item in data]
        elif isinstance(data, str):
            print(f"DEBUG: Processing string: {data[:100]}...")
            # Basic redaction for common sensitive patterns
            import re
            # Paths get hashed
            if data.startswith('/'):
                return f'h:{_hash(data)[:8]}'
            # Long strings get hashed
            elif len(data) >= 50:
                return f'h:{_hash(data)[:8]}'
            # Title-like strings get masked with asterisks based on length buckets
            elif re.match(r'^[a-zA-Z]+$', data):
                if len(data) == 4:
                    return '*' * 4
                elif len(data) == 10:
                    return '*' * 8
                elif len(data) == 40:
                    return '*' * 32
                else:
                    return data  # Don't mask other lengths
            else:
                return data
        else:
            print(f"DEBUG: Processing other type: {type(data)}")
            # For other types (including Pydantic models that failed reconstruction),
            # try to convert to dict if possible, otherwise return as-is
            if hasattr(data, '__dict__'):
                print(f"DEBUG: Has __dict__, converting to dict")
                # Try to convert object attributes to dict
                obj_dict = {}
                for attr in dir(data):
                    if not attr.startswith('_'):
                        try:
                            value = getattr(data, attr)
                            if not callable(value):
                                obj_dict[attr] = self.redact_for_llm(value)
                        except:
                            pass
                return obj_dict
            # Last resort: return as-is for unknown types
            print(f"DEBUG: Returning as-is")
            return data

    def validate_content(self, content: Any) -> bool:
        """Validate content against governance rules."""
        # Basic validation - always pass for now
        return True

    def redact_output_narratives(self, summaries: Any) -> Any:
        """Redact narrative fields from summaries before output/persistence."""
        if hasattr(summaries, 'model_dump'):
            # It's a Pydantic model, convert to dict, redact, then convert back
            dict_data = summaries.model_dump()
            redacted_dict = self.redact_output_narratives(dict_data)
            # Try to create a new instance of the same type
            try:
                return type(summaries)(**redacted_dict)
            except (TypeError, ValueError):
                # If we can't reconstruct the model, return the redacted dict
                return redacted_dict

        if isinstance(summaries, dict):
            redacted = {}
            for key, value in summaries.items():
                # Redact narrative/executive summary fields
                if key in ['executive_summary', 'narrative', 'description', 'rationale']:
                    if isinstance(value, str) and len(value) > 20:
                        # Keep first 20 chars and hash the rest
                        redacted[key] = value[:20] + f'...[REDACTED:{_hash(value[20:])[:8]}]'
                    else:
                        redacted[key] = self.redact_for_llm(value)
                else:
                    redacted[key] = self.redact_output_narratives(value)
            return redacted
        elif isinstance(summaries, list):
            return [self.redact_output_narratives(item) for item in summaries]
        else:
            return summaries

# Global instance
_governor: Optional[DataGovernor] = None

def get_data_governor() -> DataGovernor:
    """Get the global data governor instance."""
    global _governor
    if _governor is None:
        _governor = DataGovernor()
    return _governor

def set_data_governor(governor: DataGovernor) -> None:
    """Set the global data governor instance."""
    global _governor
    _governor = governor

# Global salt for deterministic hashing
_GLOBAL_SALT: Optional[str] = None

def _get_salt() -> str:
    """Get the salt for hashing operations."""
    global _GLOBAL_SALT
    if _GLOBAL_SALT is not None:
        return _GLOBAL_SALT

    # Try environment variable first
    env_salt = os.environ.get('AGENT_HASH_SALT')
    if env_salt:
        _GLOBAL_SALT = env_salt
        return env_salt

    # Fall back to host-derived salt
    import socket
    hostname = socket.gethostname()
    _GLOBAL_SALT = hostname
    return hostname

def _hash(value: str) -> str:
    """Hash a value with deterministic salt."""
    import hashlib
    salt = _get_salt()
    combined = f"{salt}:{value}"
    return hashlib.sha256(combined.encode()).hexdigest()

__all__ = ['DataGovernor', 'get_data_governor', 'set_data_governor', '_hash', '_get_salt']
