"""
Registry for managing synthetic data producers.
"""

from typing import Dict, List, Any, Optional
from base_producer import BaseProducer
from process_producer import ProcessProducer
from network_producer import NetworkProducer
from kernel_params_producer import KernelParamsProducer
from modules_producer import ModulesProducer
from world_writable_producer import WorldWritableProducer
from suid_producer import SuidProducer
from ioc_producer import IocProducer
from mac_producer import MacProducer

# Import parallel processing utilities
try:
    from parallel_processor import process_producers_parallel, get_parallel_processor
    PARALLEL_AVAILABLE = True
except ImportError:
    PARALLEL_AVAILABLE = False

class ProducerRegistry:
    """Registry for all synthetic data producers."""

    def __init__(self):
        self.producers: Dict[str, BaseProducer] = {}
        self._register_default_producers()

    def _register_default_producers(self):
        """Register all default producers."""
        self.register_producer("processes", ProcessProducer())
        self.register_producer("network", NetworkProducer())
        self.register_producer("kernel_params", KernelParamsProducer())
        self.register_producer("modules", ModulesProducer())
        self.register_producer("world_writable", WorldWritableProducer())
        self.register_producer("suid", SuidProducer())
        self.register_producer("ioc", IocProducer())
        self.register_producer("mac", MacProducer())

    def register_producer(self, name: str, producer: BaseProducer):
        """Register a producer."""
        self.producers[name] = producer

    def get_producer(self, name: str) -> BaseProducer:
        """Get a producer by name."""
        if name not in self.producers:
            raise ValueError(f"Producer '{name}' not found")
        return self.producers[name]

    def list_producers(self) -> List[str]:
        """List all registered producers."""
        return list(self.producers.keys())

    def generate_all_findings(self, counts: Optional[Dict[str, int]] = None, conservative_parallel: bool = True, gpu_optimized: Optional[bool] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Generate findings from all producers.

        Args:
            counts: Dictionary mapping producer names to number of findings to generate.
                   If None, generates 10 findings per producer.
            conservative_parallel: Whether to use conservative parallel processing
            gpu_optimized: Whether to use GPU-optimized parallel processing

        Returns:
            Dictionary mapping producer names to their findings.
        """
        if counts is None:
            counts = {name: 10 for name in self.producers.keys()}

        # Use parallel processing if available and beneficial
        if PARALLEL_AVAILABLE and len(self.producers) > 2:
            processor = get_parallel_processor(conservative_parallel, gpu_optimized)
            print(f"🔄 Using parallel processing for {len(self.producers)} producers ({processor.max_workers} workers)")
            return process_producers_parallel(self.producers, counts, "Generating findings", processor)
        else:
            # Fallback to sequential processing for small numbers or when parallel not available
            if not PARALLEL_AVAILABLE:
                print("📝 Parallel processing not available, using sequential processing")
            else:
                print("📝 Small number of producers, using sequential processing")

            results = {}
            for name, producer in self.producers.items():
                count = counts.get(name, 10)
                results[name] = producer.generate_findings(count)
            return results

# Global registry instance
registry = ProducerRegistry()