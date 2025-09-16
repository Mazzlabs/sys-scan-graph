"""
Stable hash utility for consistent caching and deduplication.

This module provides deterministic hashing functions that produce consistent
results across Python sessions and environments.
"""

import hashlib
import json
from typing import Any


def stable_hash(obj: Any, prefix: str = "") -> str:
    """
    Generate a stable hash for any object using canonical JSON.

    This provides consistent hashing across Python sessions and environments
    by using sorted keys and deterministic JSON encoding.

    Args:
        obj: The object to hash (must be JSON serializable)
        prefix: Optional prefix for the hash key

    Returns:
        A string hash suitable for caching keys
    """
    try:
        # Convert to canonical JSON with sorted keys and compact separators
        canonical = json.dumps(obj, sort_keys=True, separators=(',', ':'))
        # Use SHA256 for collision resistance
        h = hashlib.sha256(canonical.encode()).hexdigest()
        if prefix:
            return f"{prefix}:{h}"
        return h
    except Exception:
        # Fallback to simple hash if JSON serialization fails
        return f"fallback:{hash(str(obj))}"