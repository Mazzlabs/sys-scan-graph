"""Canonicalization utilities for deterministic output ordering."""

import json
from typing import Dict, Any

def canonicalize_enriched_output_dict(output_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Canonicalize an enriched output dictionary for deterministic ordering.

    This function ensures that lists and other collections in the output
    are sorted deterministically to produce consistent results.
    """
    # Create a copy to avoid modifying the original
    canonical = output_dict.copy()

    # Sort correlations by id if they exist
    if 'correlations' in canonical and isinstance(canonical['correlations'], list):
        canonical['correlations'] = sorted(
            canonical['correlations'],
            key=lambda x: x.get('id', '') if isinstance(x, dict) else str(x)
        )

    # Sort actions by priority if they exist
    if 'actions' in canonical and isinstance(canonical['actions'], list):
        canonical['actions'] = sorted(
            canonical['actions'],
            key=lambda x: x.get('priority', 0) if isinstance(x, dict) else 0,
            reverse=True  # Higher priority first
        )

    # Sort followups by finding_id if they exist
    if 'followups' in canonical and isinstance(canonical['followups'], list):
        canonical['followups'] = sorted(
            canonical['followups'],
            key=lambda x: x.get('finding_id', '') if isinstance(x, dict) else str(x)
        )

    # Sort multi_host_correlation by key if they exist
    if 'multi_host_correlation' in canonical and isinstance(canonical['multi_host_correlation'], list):
        canonical['multi_host_correlation'] = sorted(
            canonical['multi_host_correlation'],
            key=lambda x: x.get('key', '') if isinstance(x, dict) else str(x)
        )

    return canonical

__all__ = ['canonicalize_enriched_output_dict']
