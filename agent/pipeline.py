"""
Pipeline module - imports functions from legacy pipeline for backward compatibility.
"""
from legacy.pipeline import (
    load_report,
    augment,
    correlate,
    baseline_rarity,
    process_novelty,
    sequence_correlation,
    reduce,
    summarize,
    actions,
    build_output,
    run_pipeline
)
import models
AgentState = models.AgentState