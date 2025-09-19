"""
Simple parallel processing utilities for synthetic data generation.
Optimized for T4 GPU and high-performance environments.
"""

import concurrent.futures
import os
import multiprocessing
from typing import List, Dict, Any, Callable, TypeVar, Optional
from functools import partial
import logging

T = TypeVar('T')
R = TypeVar('R')

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

class ParallelProcessor:
    """Simple parallel processing utility optimized for T4 GPU and high-performance environments."""

    def __init__(self, max_workers: Optional[int] = None, conservative_mode: bool = True, gpu_optimized: bool = False):
        """
        Initialize parallel processor optimized for different environments.

        Args:
            max_workers: Maximum number of worker threads. If None, auto-calculated.
            conservative_mode: If True, uses conservative resource allocation.
            gpu_optimized: If True, optimizes for T4 GPU/high-performance environments.
        """
        self.conservative_mode = conservative_mode
        self.gpu_optimized = gpu_optimized

        if max_workers is None:
            if gpu_optimized:
                # T4 GPU optimization: Use high parallelization
                # T4 has 2560 CUDA cores, but for CPU threading we use logical cores
                cpu_count = os.cpu_count() or 16
                if conservative_mode:
                    # Conservative GPU: 8-12 workers for balanced performance
                    self.max_workers = min(max(8, cpu_count), 12)
                else:
                    # Aggressive GPU: Use most available cores for maximum parallelization
                    self.max_workers = max(12, int(cpu_count * 0.9))
            elif conservative_mode:
                # Conservative CPU: use 50% of available CPUs, max 4 for local execution
                cpu_count = os.cpu_count() or 4
                self.max_workers = min(max(1, cpu_count // 2), 4)
            else:
                # Aggressive CPU: use 75% of available CPUs for server execution
                cpu_count = os.cpu_count() or 4
                self.max_workers = max(1, int(cpu_count * 0.75))
        else:
            self.max_workers = max_workers

        # GPU optimization: Increase thread pool size for better throughput
        if gpu_optimized:
            # Use ProcessPoolExecutor for CPU-bound tasks on GPU systems
            self.use_processes = True
            self.chunk_size = 50  # Process items in larger chunks
        else:
            self.use_processes = False
            self.chunk_size = 10

        print(f"🔧 Parallel processor initialized: {self.max_workers} workers (conservative: {conservative_mode}, GPU: {gpu_optimized})")

    def _check_system_resources(self) -> bool:
        """Check if system has sufficient resources for parallel processing."""
        if not PSUTIL_AVAILABLE or psutil is None:
            return True  # Skip resource checks if psutil not available

        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:  # More aggressive threshold for GPU systems
                print(f"⚠️  High CPU usage detected ({cpu_percent:.1f}%), reducing workers")
                self.max_workers = max(1, self.max_workers // 2)
                return False

            # Check memory usage - GPU systems have more memory
            memory = psutil.virtual_memory()
            if self.gpu_optimized:
                memory_threshold = 90  # Higher threshold for GPU systems
            else:
                memory_threshold = 85

            if memory.percent > memory_threshold:
                print(f"⚠️  High memory usage detected ({memory.percent:.1f}%), reducing workers")
                self.max_workers = max(1, self.max_workers // 2)
                return False

            return True
        except Exception as e:
            print(f"⚠️  Resource check failed: {e}")
            return True

    def _get_executor(self, max_workers: int):
        """Get the appropriate executor based on configuration."""
        if self.use_processes and self.gpu_optimized:
            return concurrent.futures.ProcessPoolExecutor(max_workers=max_workers)
        else:
            return concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    def process_items_parallel(
        self,
        items: List[T],
        process_func: Callable[[T], R],
        description: str = "Processing items"
    ) -> List[R]:
        """
        Process a list of items in parallel with GPU optimizations.

        Args:
            items: List of items to process
            process_func: Function to apply to each item
            description: Description for logging

        Returns:
            List of results in the same order as input items
        """
        if not items:
            return []

        # Check system resources before starting
        self._check_system_resources()

        print(f"🔄 {description} ({len(items)} items) using {self.max_workers} workers...")

        # For small datasets, don't bother with parallel processing
        if len(items) <= 2:
            print("📝 Small dataset detected, processing sequentially")
            results = []
            for item in items:
                try:
                    result = process_func(item)
                    results.append(result)
                except Exception as e:
                    print(f"❌ Error processing item: {e}")
            return results

        # GPU optimization: Use ProcessPoolExecutor for CPU-bound tasks
        with self._get_executor(self.max_workers) as executor:
            # Submit all tasks
            future_to_item = {
                executor.submit(process_func, item): item
                for item in items
            }

            # Collect results in order
            results = []
            for future in concurrent.futures.as_completed(future_to_item):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    item = future_to_item[future]
                    print(f"❌ Error processing item {item}: {e}")
                    continue

        print(f"✅ {description} completed: {len(results)}/{len(items)} items processed")
        return results

    def process_dict_parallel(
        self,
        items_dict: Dict[str, T],
        process_func: Callable[[str, T], tuple[str, R]],
        description: str = "Processing dictionary items"
    ) -> Dict[str, R]:
        """
        Process a dictionary of items in parallel with GPU optimizations.

        Args:
            items_dict: Dictionary of items to process
            process_func: Function that takes (key, value) and returns (key, result)
            description: Description for logging

        Returns:
            Dictionary mapping keys to results
        """
        if not items_dict:
            return {}

        # Check system resources before starting
        self._check_system_resources()

        print(f"🔄 {description} ({len(items_dict)} items) using {self.max_workers} workers...")

        # For small datasets, don't bother with parallel processing
        if len(items_dict) <= 2:
            print("📝 Small dataset detected, processing sequentially")
            results = {}
            for key, value in items_dict.items():
                try:
                    result_key, result_value = process_func(key, value)
                    results[result_key] = result_value
                except Exception as e:
                    print(f"❌ Error processing {key}: {e}")
            return results

        # GPU optimization: Process in larger chunks for better throughput
        with self._get_executor(self.max_workers) as executor:
            # Submit all tasks
            future_to_pair = {
                executor.submit(process_func, key, value): (key, value)
                for key, value in items_dict.items()
            }

            # Collect results
            results = {}
            for future in concurrent.futures.as_completed(future_to_pair):
                try:
                    result_key, result_value = future.result()
                    results[result_key] = result_value
                except Exception as e:
                    pair = future_to_pair[future]
                    print(f"❌ Error processing {pair[0]}: {e}")
                    continue

        print(f"✅ {description} completed: {len(results)}/{len(items_dict)} items processed")
        return results

# Environment-specific processor instances
def detect_gpu_environment() -> bool:
    """Detect if running in a GPU environment (T4 or similar)."""
    try:
        # Check for NVIDIA GPU
        import subprocess
        result = subprocess.run(['nvidia-smi'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and 'T4' in result.stdout:
            return True
    except (ImportError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: Check environment variables
    gpu_env_vars = ['CUDA_VISIBLE_DEVICES', 'NVIDIA_VISIBLE_DEVICES']
    for var in gpu_env_vars:
        if os.getenv(var) is not None:
            return True

    return False

# Auto-detect environment and create optimized processors
_is_gpu_env = detect_gpu_environment()

parallel_processor_local = ParallelProcessor(conservative_mode=True, gpu_optimized=False)  # For local CPU
parallel_processor_cloud = ParallelProcessor(conservative_mode=False, gpu_optimized=_is_gpu_env)  # Auto-detect GPU
parallel_processor_gpu = ParallelProcessor(conservative_mode=False, gpu_optimized=True)  # Explicit GPU optimization

# Default to GPU-optimized if GPU detected, otherwise conservative
parallel_processor = parallel_processor_gpu if _is_gpu_env else parallel_processor_local

def get_parallel_processor(conservative: bool = True, gpu_optimized: Optional[bool] = None):
    """Get the appropriate parallel processor based on execution environment."""
    if gpu_optimized is None:
        gpu_optimized = _is_gpu_env

    if gpu_optimized:
        return ParallelProcessor(conservative_mode=conservative, gpu_optimized=True)
    elif conservative:
        return parallel_processor_local
    else:
        return parallel_processor_cloud