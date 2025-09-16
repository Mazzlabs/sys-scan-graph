"""LLM-related Pydantic models for structured data validation.

This module defines the data models used by LLM providers for
consistent input/output validation and type safety.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ConsistencyIssue(BaseModel):
    """Represents a consistency issue found during analysis."""
    issue: str = Field(..., description="Type of consistency issue")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details about the issue")


class PromptAOutput(BaseModel):
    """Output from Prompt A consistency analysis."""
    findings: List[ConsistencyIssue] = Field(default_factory=list, description="List of consistency issues found")


class TriageFinding(BaseModel):
    """Represents a triaged finding with priority information."""
    id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = None
    priority: Optional[str] = None


class PromptBOutput(BaseModel):
    """Output from Prompt B triage analysis."""
    top_findings: List[TriageFinding] = Field(default_factory=list, description="Top priority findings")
    correlation_count: int = Field(default=0, description="Number of correlations found")


class PromptCOutput(BaseModel):
    """Output from Prompt C action generation."""
    action_lines: List[str] = Field(default_factory=list, description="Individual action lines")
    narrative: str = Field(default="", description="Complete action narrative")


class GuardrailError(Exception):
    """Exception raised when LLM guardrails are triggered."""
    pass


__all__ = [
    'ConsistencyIssue',
    'PromptAOutput',
    'TriageFinding',
    'PromptBOutput',
    'PromptCOutput',
    'GuardrailError'
]