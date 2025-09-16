"""
Normalization utilities for consistent state management.

This module provides functions to normalize and unify state structures
across different graph node implementations.
"""

from typing import Dict, Any


def normalize_rule_suggestions(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize rule suggestions field names for consistency.

    Ensures both 'rule_suggestions' and 'suggested_rules' fields
    contain the same data for backward compatibility.

    Args:
        state: The state dictionary to normalize

    Returns:
        The normalized state dictionary
    """
    rs = state.get('rule_suggestions')
    sr = state.get('suggested_rules')

    if rs and not sr:
        state['suggested_rules'] = rs
    elif sr and not rs:
        state['rule_suggestions'] = sr
    # If both exist and are different, prefer 'suggested_rules' as canonical

    return state


def unify_risk_assessment(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Unify risk assessment field names and structure.

    Standardizes risk assessment fields across different implementations
    to ensure consistent schema.

    Args:
        state: The state dictionary to normalize

    Returns:
        The normalized state dictionary
    """
    ra = state.get('risk_assessment') or {}

    # Map alternate keys to canonical - ensure both fields exist and are unified
    if 'overall_risk_level' in ra and 'overall_risk' not in ra:
        ra['overall_risk'] = ra['overall_risk_level']
    elif 'overall_risk' in ra and 'overall_risk_level' not in ra:
        ra['overall_risk_level'] = ra['overall_risk']
    elif 'overall_risk_level' in ra and 'overall_risk' in ra:
        # Both exist - prefer overall_risk_level as canonical
        ra['overall_risk'] = ra['overall_risk_level']

    # Ensure required fields exist with defaults
    ra.setdefault('risk_factors', [])
    ra.setdefault('recommendations', [])
    ra.setdefault('confidence_score', ra.get('confidence', 0.0))
    ra.setdefault('counts', {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0})
    ra.setdefault('total_risk_score', 0)
    ra.setdefault('average_risk_score', 0.0)
    ra.setdefault('finding_count', 0)
    ra.setdefault('top_findings', [])

    state['risk_assessment'] = ra
    return state


def unify_compliance_check(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Unify compliance check structure.

    Standardizes compliance check fields to ensure consistent schema:
    {
        standards: { <std>: {finding_ids:[], count:int} },
        total_compliance_findings:int
    }

    Args:
        state: The state dictionary to normalize

    Returns:
        The normalized state dictionary
    """
    cc = state.get('compliance_check') or {}

    # Ensure standards structure
    standards = cc.get('standards', {})

    # Handle enhanced format: convert individual standard keys to unified format
    enhanced_keys = ['pci_dss', 'hipaa', 'nist_csf', 'nist', 'sox', 'gdpr', 'ccpa']
    for key in enhanced_keys:
        if key in cc and key not in standards:
            std_data = cc[key]
            if isinstance(std_data, dict) and 'violations' in std_data:
                # Convert enhanced format to unified format
                standards[key] = {
                    'finding_ids': std_data['violations'],
                    'count': len(std_data['violations'])
                }

    # Normalize each standard entry
    for std_name, std_data in standards.items():
        if isinstance(std_data, dict):
            # Ensure finding_ids is a list
            if 'finding_ids' not in std_data:
                std_data['finding_ids'] = []
            elif not isinstance(std_data['finding_ids'], list):
                std_data['finding_ids'] = [std_data['finding_ids']]

            # Ensure count matches finding_ids length
            std_data['count'] = len(std_data['finding_ids'])
        else:
            # Convert non-dict entries to proper structure
            standards[std_name] = {'finding_ids': [], 'count': 0}

    cc['standards'] = standards

    # Calculate total compliance findings
    total = sum(std_data.get('count', 0) for std_data in standards.values())
    cc['total_compliance_findings'] = total

    state['compliance_check'] = cc
    return state


def ensure_monotonic_timing(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure monotonic timing is captured for accurate duration calculations.

    Adds monotonic_start field if not present, preserving existing start_time.

    Args:
        state: The state dictionary to update

    Returns:
        The updated state dictionary
    """
    import time

    if 'monotonic_start' not in state:
        state['monotonic_start'] = time.monotonic()

    return state


def add_metrics_version(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add metrics version for schema evolution tracking.

    Args:
        state: The state dictionary to update

    Returns:
        The updated state dictionary
    """
    metrics = state.setdefault('metrics', {})
    if 'version' not in metrics:
        metrics['version'] = '1.0'
    state['metrics'] = metrics
    return state