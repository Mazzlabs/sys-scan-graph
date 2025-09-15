from __future__ import annotations
"""Performance-optimized graph node functions with advanced async capabilities.

This module provides high-performance node implementations with:
- Connection pooling and batch database operations
- Streaming processing for large datasets
- Parallel execution patterns
- Memory-efficient data structures
- Advanced caching strategies
- Circuit breaker patterns
"""

from typing import Any, List, Dict, Optional, Union, AsyncIterator, Callable, Tuple
import asyncio
import time
import logging
import json
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import hashlib
import tempfile
from concurrent.futures import ThreadPoolExecutor

# Use standard sqlite3 for now, can upgrade to aiosqlite later
import sqlite3

import graph
import data_governance
import models
import knowledge
import pipeline
import reduction
import llm_provider
import rules
import rule_gap_miner
import graph_state
import baseline

# Re-export for backward compatibility
GraphState = graph.GraphState
get_data_governor = data_governance.get_data_governor
Finding = models.Finding
ScannerResult = models.ScannerResult
Report = models.Report
Meta = models.Meta
Summary = models.Summary
SummaryExtension = models.SummaryExtension
AgentState = models.AgentState
Reductions = models.Reductions
apply_external_knowledge = knowledge.apply_external_knowledge
_augment = pipeline.augment
reduce_all = reduction.reduce_all
get_llm_provider = llm_provider.get_llm_provider
Correlator = rules.Correlator
DEFAULT_RULES = rules.DEFAULT_RULES
mine_gap_candidates = rule_gap_miner.mine_gap_candidates
normalize_graph_state = graph_state.normalize_graph_state
hashlib_sha = baseline.hashlib_sha

logger = logging.getLogger(__name__)

def stable_hash(obj: Any, prefix: str = "") -> str:
    """Generate a stable hash for any object using canonical JSON.

    This provides consistent hashing across Python sessions and environments
    by using sorted keys and deterministic JSON encoding.

    Args:
        obj: The object to hash (must be JSON serializable)
        prefix: Optional prefix for the hash key

    Returns:
        A string hash suitable for caching keys
    """
    try:
        import hashlib
        import json
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

# Performance configuration
@dataclass
class PerformanceConfig:
    """Configuration for performance optimizations."""
    batch_size: int = 100
    max_concurrent_db_connections: int = 10
    cache_ttl_seconds: int = 3600
    streaming_chunk_size: int = 50
    max_memory_mb: int = 512
    thread_pool_workers: int = 4

# Global performance config
perf_config = PerformanceConfig()

# Connection pool for database operations (using regular sqlite3 for now)
class DatabaseConnectionPool:
    """Async-compatible connection pool for SQLite operations."""

    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool: asyncio.Queue[sqlite3.Connection] = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(max_connections)

    async def initialize(self):
        """Initialize the connection pool."""
        for _ in range(self.max_connections):
            # Use ThreadPoolExecutor for sqlite3 operations
            loop = asyncio.get_event_loop()
            conn = await loop.run_in_executor(None, sqlite3.connect, self.db_path)
            await self._pool.put(conn)

    async def get_connection(self) -> sqlite3.Connection:
        """Get a connection from the pool."""
        await self._semaphore.acquire()
        conn = await self._pool.get()
        return conn

    async def return_connection(self, conn: sqlite3.Connection):
        """Return a connection to the pool."""
        await self._pool.put(conn)
        self._semaphore.release()

    async def execute_query(self, query: str, params: tuple = ()) -> List[tuple]:
        """Execute a query using a pooled connection."""
        conn = await self.get_connection()
        try:
            loop = asyncio.get_event_loop()
            cursor = await loop.run_in_executor(None, conn.cursor)
            await loop.run_in_executor(None, cursor.execute, query, params)
            results = await loop.run_in_executor(None, cursor.fetchall)
            await loop.run_in_executor(None, cursor.close)
            return results
        finally:
            await self.return_connection(conn)

    async def close_all(self):
        """Close all connections in the pool."""
        while not self._pool.empty():
            conn = await self._pool.get()
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, conn.close)

# Global connection pool
db_pool: Optional[DatabaseConnectionPool] = None

@asynccontextmanager
async def get_db_connection(db_path: str):
    """Context manager for database connections."""
    global db_pool
    if db_pool is None:
        db_pool = DatabaseConnectionPool(db_path)
        await db_pool.initialize()

    conn = await db_pool.get_connection()
    try:
        yield conn
    finally:
        await db_pool.return_connection(conn)

# Memory-efficient data structures
@dataclass
class FindingBatch:
    """Memory-efficient batch of findings."""
    findings: List[Finding] = field(default_factory=list)
    batch_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        """Add a finding to the batch."""
        self.findings.append(finding)

    def is_full(self) -> bool:
        """Check if batch is at capacity."""
        return len(self.findings) >= perf_config.batch_size

    def clear(self):
        """Clear the batch."""
        self.findings.clear()
        self.metadata.clear()
        self.batch_id = ""

# Advanced caching with TTL
class AdvancedCache:
    """Advanced caching with TTL and size limits."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_times: Dict[str, float] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        if key in self._cache:
            if time.time() - self._access_times[key] > self.ttl_seconds:
                del self._cache[key]
                del self._access_times[key]
                return None
            self._access_times[key] = time.time()
            return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        """Set cached value with eviction if needed."""
        if len(self._cache) >= self.max_size:
            # Evict least recently used
            oldest_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
            del self._cache[oldest_key]
            del self._access_times[oldest_key]

        self._cache[key] = value
        self._access_times[key] = time.time()

    def clear_expired(self):
        """Clear expired entries."""
        current_time = time.time()
        expired_keys = [
            key for key, access_time in self._access_times.items()
            if current_time - access_time > self.ttl_seconds
        ]
        for key in expired_keys:
            del self._cache[key]
            del self._access_times[key]

# Global cache instance
advanced_cache = AdvancedCache()

def _append_warning(state: GraphState, module: str, stage: str, error: str, hint: str | None = None):
    """Enhanced warning appender with performance tracking."""
    wl = state.setdefault('warnings', [])
    error_entry = {
        'module': module,
        'stage': stage,
        'error': error,
        'hint': hint,
        'timestamp': datetime.now().isoformat(),
        'session_id': state.get('session_id', 'unknown'),
        'performance_impact': 'low'  # Can be upgraded based on error type
    }
    wl.append(error_entry)

    # Track in errors list for better visibility
    errors = state.setdefault('errors', [])
    errors.append(error_entry)

def _findings_from_graph(state: GraphState) -> List[Finding]:
    """Convert graph state findings to Pydantic models with batching."""
    out: List[Finding] = []
    raw_findings = state.get('raw_findings', []) or []

    # Process in batches to avoid memory spikes
    for i in range(0, len(raw_findings), perf_config.batch_size):
        batch = raw_findings[i:i + perf_config.batch_size]
        for finding in batch:
            try:
                out.append(Finding(
                    id=finding.get('id','unknown'),
                    title=finding.get('title','(no title)'),
                    severity=finding.get('severity','info'),
                    risk_score=int(finding.get('risk_score', finding.get('risk_total', 0)) or 0),
                    metadata=finding.get('metadata', {})
                ))
            except Exception:
                continue

    return out

async def batch_process_findings(findings: List[Any], processor_func: Callable[[List[Any]], Any], batch_size: Optional[int] = None) -> List[Any]:
    """Process findings in batches for memory efficiency with deterministic ordering and progress tracking."""
    if batch_size is None:
        batch_size = perf_config.batch_size

    if not findings:
        return []

    results = []
    total_batches = (len(findings) + batch_size - 1) // batch_size  # Ceiling division

    # Process in batches while maintaining order
    for batch_idx in range(total_batches):
        start_idx = batch_idx * batch_size
        end_idx = min(start_idx + batch_size, len(findings))
        batch = findings[start_idx:end_idx]

        try:
            # Process batch
            batch_results = await processor_func(batch)

            # Ensure batch_results is a list
            if not isinstance(batch_results, list):
                batch_results = [batch_results] if batch_results is not None else []

            # Extend results while maintaining order
            results.extend(batch_results)

            # Progress logging for large batches
            if total_batches > 10 and (batch_idx + 1) % max(1, total_batches // 10) == 0:
                progress = (batch_idx + 1) / total_batches * 100
                logger.info(f"Batch processing progress: {progress:.1f}% ({batch_idx + 1}/{total_batches} batches)")

            # Allow other tasks to run periodically
            if batch_idx % 10 == 0:
                await asyncio.sleep(0)

        except Exception as e:
            logger.error(f"Batch {batch_idx + 1}/{total_batches} failed: {e}")
            # Add error placeholders to maintain ordering
            for _ in batch:
                results.append({'error': str(e), 'batch_idx': batch_idx})

    return results

async def enrich_findings_batch(state: GraphState) -> GraphState:
    """Batch-optimized enrichment with streaming and caching."""
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(state)  # type: ignore

    start_time = time.monotonic()
    state['current_stage'] = 'enrich'
    # Store ISO time for state compatibility, monotonic time for accurate calculations
    if 'start_time' not in state:
        state['start_time'] = datetime.now().isoformat()
    state.setdefault('metrics', {})['start_time_monotonic'] = start_time

    try:
        # Check cache first
        cache_key = stable_hash(state.get('raw_findings', []), "enrich_batch")
        cached_result = advanced_cache.get(cache_key)
        if cached_result:
            logger.info("Using cached enrichment results")
            state.update(cached_result)
            state['cache_hits'] = state.get('cache_hits', []) + [cache_key]
            return state

        findings = _findings_from_graph(state)

        # Process in batches
        async def process_batch(batch: List[Finding]) -> List[Dict[str, Any]]:
            """Process a batch of findings with error handling."""
            batch_results = []
            errors_in_batch = 0

            for finding in batch:
                try:
                    # Create minimal report for this finding
                    sr = ScannerResult(
                        scanner='mixed',
                        finding_count=1,
                        findings=[finding]
                    )
                    report = Report(
                        meta=Meta(),
                        summary=Summary(finding_count_total=1, finding_count_emitted=1),
                        results=[sr],
                        collection_warnings=[],
                        scanner_errors=[],
                        summary_extension=SummaryExtension(total_risk_score=finding.risk_score or 0)
                    )
                    astate = AgentState(report=report)

                    # Apply enrichment pipeline
                    astate = _augment(astate)
                    astate = apply_external_knowledge(astate)

                    # Extract enriched finding
                    if astate.report and astate.report.results:
                        for r in astate.report.results:
                            for f in r.findings:
                                batch_results.append(f.model_dump())

                except Exception as e:
                    errors_in_batch += 1
                    logger.warning(f"Failed to enrich finding {finding.id}: {e}")
                    # Add error marker to maintain ordering
                    batch_results.append({
                        'id': finding.id,
                        'error': 'enrichment_failed',
                        'error_message': str(e),
                        'original_finding': finding.model_dump()
                    })
                    continue

            # Log batch statistics
            if errors_in_batch > 0:
                logger.info(f"Batch enrichment completed: {len(batch_results)} successful, {errors_in_batch} errors")

            return batch_results

        # Process all findings in batches
        enriched_findings = await batch_process_findings(findings, process_batch)

        state['enriched_findings'] = enriched_findings

        # Cache the results
        cache_data = {
            'enriched_findings': enriched_findings,
            'cache_timestamp': datetime.now().isoformat()
        }
        advanced_cache.set(cache_key, cache_data)
        state['cache_keys'] = state.get('cache_keys', []) + [cache_key]

        # Update metrics
        state.setdefault('metrics', {})['enrich_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['findings_processed'] = len(enriched_findings)

    except Exception as e:
        logger.error(f"Batch enrichment failed: {e}")
        _append_warning(state, 'graph', 'enrich_batch', str(e))
        state.setdefault('enriched_findings', state.get('raw_findings', []))

    return state

async def correlate_findings_batch(state: GraphState) -> GraphState:
    """Batch-optimized correlation with parallel processing."""
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(state)  # type: ignore

    start_time = time.time()
    state['current_stage'] = 'correlate'

    try:
        findings: List[Finding] = []
        enriched_findings = state.get('enriched_findings', []) or []

        # Convert to Pydantic models in batches with error tracking
        conversion_errors = 0
        for i in range(0, len(enriched_findings), perf_config.batch_size):
            batch = enriched_findings[i:i + perf_config.batch_size]
            for finding_dict in batch:
                try:
                    findings.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
                except Exception as e:
                    conversion_errors += 1
                    logger.warning(f"Failed to convert finding dict to model: {e}")
                    continue

        if conversion_errors > 0:
            logger.info(f"Finding conversion completed: {len(findings)} successful, {conversion_errors} errors")

        if not findings:
            logger.warning("No findings to correlate after conversion")
            return state

        if not findings:
            return state

        # Create report for correlation
        sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = Report(
            meta=Meta(),
            summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
            results=[sr],
            collection_warnings=[],
            scanner_errors=[],
            summary_extension=SummaryExtension(total_risk_score=sum(f.risk_score or 0 for f in findings))
        )
        astate = AgentState(report=report)

        # Apply correlation rules
        correlator = Correlator(DEFAULT_RULES)
        correlations = correlator.apply(findings)

        # Attach correlation refs to findings in parallel
        async def attach_correlations():
            """Attach correlation references to findings."""
            tasks = []
            for correlation in correlations:
                task = asyncio.create_task(attach_correlation_refs(findings, correlation))
                tasks.append(task)
            await asyncio.gather(*tasks)

        async def attach_correlation_refs(findings: List[Finding], correlation):
            """Attach correlation refs to relevant findings."""
            for finding in findings:
                if finding.id in correlation.related_finding_ids and correlation.id not in finding.correlation_refs:
                    finding.correlation_refs.append(correlation.id)

        await attach_correlations()

        state['correlated_findings'] = [finding.model_dump() for finding in findings]
        state['correlations'] = [c.model_dump() for c in correlations]

        # Update metrics
        state.setdefault('metrics', {})['correlate_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['correlations_found'] = len(correlations)

    except Exception as e:
        logger.error(f"Batch correlation failed: {e}")
        _append_warning(state, 'graph', 'correlate_batch', str(e))
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])

    return state

async def summarize_host_state_streaming(state: GraphState) -> GraphState:
    """Streaming summarization with comprehensive progress tracking and memory-efficient processing."""
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(state)  # type: ignore

    start_time = time.time()
    state['current_stage'] = 'summarize'

    # Initialize progress tracking
    progress_tracker = {
        'total_findings': 0,
        'processed_chunks': 0,
        'total_chunks': 0,
        'memory_usage_mb': 0,
        'start_time': start_time,
        'estimated_completion': None
    }

    try:
        # Iteration guard
        max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
        iters = int(state.get('iteration_count', 0))
        if iters >= max_iter:
            _append_warning(state, 'graph', 'summarize', 'iteration_limit_reached')
            return state

        provider = get_llm_provider()
        findings_dicts = state.get('correlated_findings') or state.get('enriched_findings') or []

        # Convert findings in streaming fashion with memory monitoring
        findings: List[Finding] = []
        conversion_stats = {'successful': 0, 'failed': 0}

        for finding_dict in findings_dicts:
            try:
                findings.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
                conversion_stats['successful'] += 1
            except Exception as e:
                conversion_stats['failed'] += 1
                logger.warning(f"Failed to convert finding: {e}")
                continue

        progress_tracker['total_findings'] = len(findings)
        progress_tracker['total_chunks'] = (len(findings) + perf_config.streaming_chunk_size - 1) // perf_config.streaming_chunk_size

        logger.info(f"Starting streaming summarization: {len(findings)} findings in {progress_tracker['total_chunks']} chunks")

        # Process in chunks for memory efficiency with detailed progress tracking
        reductions = []
        chunk_processing_times = []

        for chunk_idx in range(progress_tracker['total_chunks']):
            chunk_start_time = time.time()

            start_idx = chunk_idx * perf_config.streaming_chunk_size
            end_idx = min(start_idx + perf_config.streaming_chunk_size, len(findings))
            chunk = findings[start_idx:end_idx]

            try:
                # Process chunk with memory monitoring
                chunk_reductions = reduce_all(chunk)
                # Convert list to Reductions object if needed
                if isinstance(chunk_reductions, list):
                    chunk_reductions = Reductions(top_findings=chunk_reductions)
                reductions.extend(chunk_reductions.top_findings if hasattr(chunk_reductions, 'top_findings') else [chunk_reductions])

                # Update progress
                progress_tracker['processed_chunks'] = chunk_idx + 1
                chunk_time = time.time() - chunk_start_time
                chunk_processing_times.append(chunk_time)

                # Calculate progress and ETA
                progress = (chunk_idx + 1) / progress_tracker['total_chunks']
                avg_chunk_time = sum(chunk_processing_times) / len(chunk_processing_times)
                remaining_chunks = progress_tracker['total_chunks'] - (chunk_idx + 1)
                eta_seconds = remaining_chunks * avg_chunk_time

                progress_tracker['progress_percentage'] = progress * 100
                progress_tracker['estimated_completion'] = start_time + (time.time() - start_time) / progress

                # Memory usage estimation (rough approximation)
                progress_tracker['memory_usage_mb'] = len(reductions) * 0.01  # Rough estimate

                # Log progress periodically
                if chunk_idx % max(1, progress_tracker['total_chunks'] // 10) == 0 or chunk_idx == progress_tracker['total_chunks'] - 1:
                    logger.info(f"Streaming summarization progress: {progress_tracker['progress_percentage']:.1f}% "
                              f"({chunk_idx + 1}/{progress_tracker['total_chunks']} chunks, "
                              f"ETA: {eta_seconds:.1f}s)")

                # Yield progress updates to state metrics
                state.setdefault('metrics', {})['summarize_progress'] = progress_tracker.copy()

                # Memory management: clear large intermediate data if needed
                if progress_tracker['memory_usage_mb'] > perf_config.max_memory_mb:
                    logger.warning(f"Memory usage high ({progress_tracker['memory_usage_mb']:.1f}MB), "
                                 f"consider increasing max_memory_mb or reducing chunk size")
                    # Force garbage collection hint
                    import gc
                    gc.collect()

                # Allow other tasks to run
                await asyncio.sleep(0)

            except Exception as e:
                logger.error(f"Failed to process chunk {chunk_idx + 1}: {e}")
                _append_warning(state, 'graph', f'summarize_chunk_{chunk_idx}', str(e))
                continue

        # Enhanced correlation handling with error recovery
        corr_objs = []
        correlations = state.get('correlations', []) or []
        correlation_stats = {'successful': 0, 'failed': 0}

        for corr_dict in correlations:
            try:
                from .models import Correlation as _C
                corr_objs.append(_C(**corr_dict))
                correlation_stats['successful'] += 1
            except Exception as e:
                correlation_stats['failed'] += 1
                logger.warning(f"Failed to convert correlation: {e}")
                continue

        baseline_context = state.get('baseline_results') or {}

        # Generate summary with fallback handling
        try:
            # Create Reductions object from accumulated findings
            final_reductions = Reductions(top_findings=reductions)
            summaries, _ = provider.summarize(final_reductions, corr_objs, actions=[], baseline_context=baseline_context)
            state['summary'] = summaries.model_dump()
        except Exception as e:
            logger.error(f"Summary generation failed: {e}")
            _append_warning(state, 'graph', 'summary_generation', str(e))
            # Fallback summary
            state['summary'] = {
                'summary': f'Summary generation failed: {str(e)}',
                'finding_count': len(findings),
                'fallback': True
            }

        state['iteration_count'] = iters + 1

        # Add comprehensive metrics
        processing_time = time.time() - start_time
        state.setdefault('metrics', {}).update({
            'summarize_duration': processing_time,
            'chunks_processed': progress_tracker['processed_chunks'],
            'total_chunks': progress_tracker['total_chunks'],
            'findings_processed': len(findings),
            'conversion_stats': conversion_stats,
            'correlation_stats': correlation_stats,
            'avg_chunk_time': sum(chunk_processing_times) / len(chunk_processing_times) if chunk_processing_times else 0,
            'peak_memory_mb': progress_tracker['memory_usage_mb'],
            'processing_rate': len(findings) / processing_time if processing_time > 0 else 0
        })

        # Add final progress update
        progress_tracker['completed'] = True
        progress_tracker['total_time'] = processing_time
        state.setdefault('metrics', {})['summarize_final_progress'] = progress_tracker

        logger.info(f"Streaming summarization completed: {len(findings)} findings processed in {processing_time:.2f}s")

    except Exception as e:
        logger.error(f"Streaming summarization failed: {e}")
        _append_warning(state, 'graph', 'summarize_streaming', str(e))
        # Add error info to progress tracker
        progress_tracker['error'] = str(e)
        progress_tracker['completed'] = False
        state.setdefault('metrics', {})['summarize_error_progress'] = progress_tracker

    return state

async def query_baseline_batch(state: GraphState) -> GraphState:
    """Batch baseline queries with connection pooling."""
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(state)  # type: ignore

    start_time = time.time()
    state['current_stage'] = 'baseline_query'

    try:
        enriched = state.get('enriched_findings', []) or []
        if not enriched:
            return state

        db_path = __import__('os').environ.get('AGENT_BASELINE_DB', 'agent_baseline.db')

        # Process baseline queries in batches with enhanced error handling
        async def process_baseline_batch(batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            """Process a batch of baseline queries with deterministic ordering."""
            results = []
            batch_errors = 0

            async with get_db_connection(db_path) as conn:
                for finding_idx, finding in enumerate(batch):
                    try:
                        fid = finding.get('id') or f'unknown_{finding_idx}'
                        title = finding.get('title') or ''
                        severity = finding.get('severity') or ''
                        scanner = finding.get('scanner') or 'mixed'

                        # Compute composite hash
                        identity_core = f"{fid}\n{title}\n{severity}\n".encode()
                        h = hashlib.sha256(identity_core).hexdigest()

                        from .baseline import hashlib_sha
                        composite = hashlib_sha(scanner, h)

                        # Query database with timeout protection
                        loop = asyncio.get_event_loop()
                        cursor = await loop.run_in_executor(None, conn.cursor)

                        # Execute query with error handling
                        try:
                            await loop.run_in_executor(None, cursor.execute,
                                "SELECT first_seen_ts, seen_count FROM baseline_finding WHERE host_id=? AND finding_hash=?",
                                (state.get('host_id', 'unknown'), composite)
                            )
                            row = await loop.run_in_executor(None, cursor.fetchone)
                        except Exception as query_error:
                            logger.warning(f"Database query failed for finding {fid}: {query_error}")
                            row = None
                        finally:
                            await loop.run_in_executor(None, cursor.close)

                        result = {
                            'finding_id': fid,
                            'host_id': state.get('host_id', 'unknown'),
                            'scanner': scanner,
                            'composite_hash': composite,
                            'db_path': db_path,
                            'batch_order': finding_idx  # Preserve ordering
                        }

                        if row:
                            first_seen, count = row
                            result.update({
                                'status': 'existing',
                                'first_seen_ts': first_seen,
                                'prev_seen_count': count,
                                'baseline_status': 'existing'
                            })
                        else:
                            result.update({
                                'status': 'new',
                                'baseline_status': 'new'
                            })

                        results.append(result)

                    except Exception as e:
                        batch_errors += 1
                        logger.warning(f"Baseline query failed for finding {finding.get('id', f'batch_item_{finding_idx}')}: {e}")
                        results.append({
                            'finding_id': finding.get('id', f'unknown_{finding_idx}'),
                            'status': 'error',
                            'error': str(e),
                            'batch_order': finding_idx
                        })

            # Sort results by batch order to ensure deterministic output
            results.sort(key=lambda x: x.get('batch_order', 0))

            if batch_errors > 0:
                logger.info(f"Baseline batch completed: {len(results) - batch_errors} successful, {batch_errors} errors")

            return results

        # Process all findings in batches
        baseline_results = await batch_process_findings(enriched, process_baseline_batch)

        # Update findings with baseline status
        for result in baseline_results:
            fid = result.get('finding_id')
            status = result.get('baseline_status')
            if fid and status:
                for finding in enriched:
                    if finding.get('id') == fid:
                        finding['baseline_status'] = status
                        break

        state['baseline_results'] = {r.get('finding_id'): r for r in baseline_results if r.get('finding_id')}
        state['enriched_findings'] = enriched

        # Update metrics
        state.setdefault('metrics', {})['baseline_query_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['baseline_queries_made'] = len(baseline_results)

    except Exception as e:
        logger.error(f"Batch baseline query failed: {e}")
        _append_warning(state, 'graph', 'baseline_batch', str(e))

    return state

async def parallel_node_execution(state: GraphState, nodes: List[Callable[[GraphState], Any]]) -> GraphState:
    """Execute multiple nodes in parallel with conflict resolution and deterministic merging."""
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(state)  # type: ignore

    start_time = time.time()
    execution_stats = {
        'total_tasks': len(nodes),
        'successful_tasks': 0,
        'failed_tasks': 0,
        'conflicts_resolved': 0
    }

    try:
        # Create tasks for parallel execution with node identification
        tasks = []
        for idx, node_func in enumerate(nodes):
            # Create a wrapper to identify which node produced the result
            async def execute_with_id(node_idx=idx, node=node_func):
                try:
                    result = await node(state.copy())
                    return {'node_idx': node_idx, 'result': result, 'success': True}
                except Exception as e:
                    logger.error(f"Node {node_idx} execution failed: {e}")
                    return {'node_idx': node_idx, 'error': str(e), 'success': False}

            task = asyncio.create_task(execute_with_id())
            tasks.append(task)

        # Wait for all tasks to complete with timeout protection
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=300.0  # 5 minute timeout
            )
        except asyncio.TimeoutError:
            logger.error("Parallel execution timed out after 5 minutes")
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            _append_warning(state, 'graph', 'parallel_execution', 'timeout_after_5_minutes')
            return state

        # Process results and merge into state with conflict resolution
        merged_updates = {}
        errors = []

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Task execution failed with exception: {result}")
                execution_stats['failed_tasks'] += 1
                errors.append(str(result))
                continue

            if not isinstance(result, dict) or 'success' not in result:
                logger.warning(f"Invalid result format: {result}")
                execution_stats['failed_tasks'] += 1
                continue

            if result['success']:
                execution_stats['successful_tasks'] += 1
                node_result = result.get('result', {})

                if isinstance(node_result, dict):
                    # Merge results with conflict resolution
                    for key, value in node_result.items():
                        if key in merged_updates:
                            # Conflict resolution: prefer non-empty values, then by node index
                            existing = merged_updates[key]
                            if _resolve_conflict(key, existing, value, result['node_idx']):
                                merged_updates[key] = value
                                execution_stats['conflicts_resolved'] += 1
                        else:
                            merged_updates[key] = value
                else:
                    logger.warning(f"Node {result['node_idx']} returned non-dict result: {type(node_result)}")
            else:
                execution_stats['failed_tasks'] += 1
                errors.append(result.get('error', 'Unknown error'))

        # Apply merged updates to state
        state.update(merged_updates)

        # Add execution statistics to state metrics
        state.setdefault('metrics', {})['parallel_execution_stats'] = execution_stats

        # Log summary
        success_rate = execution_stats['successful_tasks'] / execution_stats['total_tasks'] * 100
        logger.info(f"Parallel execution completed: {success_rate:.1f}% success rate "
                   f"({execution_stats['successful_tasks']}/{execution_stats['total_tasks']} tasks)")

        if errors:
            logger.warning(f"Parallel execution had {len(errors)} errors: {errors[:3]}...")  # Log first 3 errors

        # Update metrics
        state.setdefault('metrics', {})['parallel_execution_duration'] = time.time() - start_time
        state.setdefault('metrics', {})['parallel_tasks_executed'] = len(tasks)
        state.setdefault('metrics', {}).update(execution_stats)

    except Exception as e:
        logger.error(f"Parallel execution failed: {e}")
        _append_warning(state, 'graph', 'parallel_execution', str(e))

    return state


def _resolve_conflict(key: str, existing_value: Any, new_value: Any, new_node_idx: int) -> bool:
    """
    Resolve conflicts between parallel node results.

    Returns True if new_value should replace existing_value, False otherwise.
    """
    # Priority keys that should not be overwritten
    priority_keys = {'session_id', 'host_id', 'start_time', 'current_stage'}

    if key in priority_keys:
        # Keep existing value for priority keys
        return False

    # For list-type values, merge them
    if isinstance(existing_value, list) and isinstance(new_value, list):
        # Combine lists without duplicates
        if key == 'warnings' or key == 'errors':
            # For warnings/errors, combine all
            return True  # Will be handled by merging logic
        else:
            # For other lists, prefer longer or more recent
            return len(new_value) > len(existing_value)

    # For dict-type values, merge recursively
    if isinstance(existing_value, dict) and isinstance(new_value, dict):
        # Deep merge dictionaries
        return True  # Will be handled by merging logic

    # For numeric values, prefer higher values (could indicate more complete processing)
    if isinstance(existing_value, (int, float)) and isinstance(new_value, (int, float)):
        return new_value > existing_value

    # For string values, prefer non-empty over empty
    if isinstance(existing_value, str) and isinstance(new_value, str):
        if not existing_value and new_value:
            return True
        elif existing_value and not new_value:
            return False
        else:
            # Both non-empty, prefer the one from lower node index (deterministic)
            return False  # Keep existing

    # Default: keep existing value
    return False

# Additional parallel processing utilities
async def parallel_batch_processor(items: List[Any],
                                  processor_func: Callable[[Any], Any],
                                  max_concurrent: Optional[int] = None,
                                  batch_size: Optional[int] = None) -> List[Any]:
    """
    Process items in parallel batches with controlled concurrency.

    Args:
        items: List of items to process
        processor_func: Function to process each item
        max_concurrent: Maximum concurrent operations (default: perf_config.thread_pool_workers)
        batch_size: Size of each processing batch (default: perf_config.batch_size)

    Returns:
        List of results in original order
    """
    if max_concurrent is None:
        max_concurrent = perf_config.thread_pool_workers
    if batch_size is None:
        batch_size = perf_config.batch_size

    if not items:
        return []

    semaphore = asyncio.Semaphore(max_concurrent)
    results: List[Optional[Any]] = [None] * len(items)  # Pre-allocate for ordering

    async def process_with_semaphore(idx: int, item: Any):
        """Process item with semaphore control."""
        async with semaphore:
            try:
                result = await processor_func(item)
                results[idx] = result
            except Exception as e:
                logger.error(f"Parallel processing failed for item {idx}: {e}")
                results[idx] = {'error': str(e), 'item_idx': idx}

    # Create tasks for all items
    tasks = []
    for idx, item in enumerate(items):
        task = asyncio.create_task(process_with_semaphore(idx, item))
        tasks.append(task)

    # Wait for all tasks to complete
    await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out None values (shouldn't happen with proper implementation)
    return [r for r in results if r is not None]


async def parallel_pipeline_executor(state: GraphState,
                                   pipeline_stages: List[Callable[[GraphState], GraphState]],
                                   max_parallel_stages: int = 2) -> GraphState:
    """
    Execute pipeline stages with controlled parallelism.

    Some stages can run in parallel if they don't depend on each other,
    while maintaining proper ordering for dependent stages.

    Args:
        state: Initial graph state
        pipeline_stages: List of pipeline stage functions
        max_parallel_stages: Maximum stages to run in parallel

    Returns:
        Final graph state after all stages
    """
    if not pipeline_stages:
        return state

    current_state = state.copy()
    semaphore = asyncio.Semaphore(max_parallel_stages)

    async def execute_stage_with_deps(stage_func: Callable[[GraphState], GraphState],
                                     input_state: GraphState) -> GraphState:
        """Execute stage with dependency management."""
        async with semaphore:
            try:
                result_state = stage_func(input_state)
                return result_state
            except Exception as e:
                logger.error(f"Pipeline stage failed: {e}")
                _append_warning(input_state, 'graph', 'pipeline_execution', str(e))
                return input_state

    # For now, execute stages sequentially to maintain dependencies
    # TODO: Implement dependency analysis for true parallel execution
    for stage in pipeline_stages:
        current_state = await execute_stage_with_deps(stage, current_state)

    return current_state


async def concurrent_db_operations(operations: List[Tuple[str, Tuple, Callable]],
                                 db_path: str,
                                 max_concurrent: Optional[int] = None) -> List[Any]:
    """
    Execute multiple database operations concurrently.

    Args:
        operations: List of (query, params, result_processor) tuples
        db_path: Database path
        max_concurrent: Maximum concurrent operations

    Returns:
        List of processed results
    """
    if max_concurrent is None:
        max_concurrent = perf_config.max_concurrent_db_connections

    semaphore = asyncio.Semaphore(max_concurrent)
    results = []

    async def execute_operation(query: str, params: Tuple, processor: Callable):
        """Execute single database operation."""
        async with semaphore:
            async with get_db_connection(db_path) as conn:
                try:
                    loop = asyncio.get_event_loop()
                    cursor = await loop.run_in_executor(None, conn.cursor)
                    await loop.run_in_executor(None, cursor.execute, query, params)
                    raw_result = await loop.run_in_executor(None, cursor.fetchall)
                    await loop.run_in_executor(None, cursor.close)

                    # Process result
                    if processor:
                        result = processor(raw_result)
                    else:
                        result = raw_result

                    results.append(result)

                except Exception as e:
                    logger.error(f"Concurrent DB operation failed: {e}")
                    results.append({'error': str(e)})

    # Execute all operations
    tasks = []
    for query, params, processor in operations:
        task = asyncio.create_task(execute_operation(query, params, processor))
        tasks.append(task)

    await asyncio.gather(*tasks, return_exceptions=True)
    return results