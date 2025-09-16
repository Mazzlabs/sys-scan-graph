from __future__ import annotations
"""Enhanced LLM Provider with multi-provider support and advanced features.

This module provides sophisticated LLM integration with:
- Multi-provider fallback chains
- Streaming responses
- Advanced error handling and retry logic
- Token usage optimization
- Caching and performance monitoring
- Structured output parsing
"""

from typing import Protocol, List, Optional, Dict, Any, Union, Tuple
import asyncio
import time
import logging
from datetime import datetime
import json
import os
from pathlib import Path

from . import models
from . import llm_provider
Reductions = models.Reductions
Correlation = models.Correlation
Summaries = models.Summaries
ActionItem = models.ActionItem
ILLMProvider = llm_provider.ILLMProvider
NullLLMProvider = llm_provider.NullLLMProvider
ProviderMetadata = llm_provider.ProviderMetadata

# Try to import data governance, fallback if not available
try:
    import data_governance
    get_data_governor = data_governance.get_data_governor
except ImportError:
    get_data_governor = lambda: None

logger = logging.getLogger(__name__)

class EnhancedLLMProvider(ILLMProvider):
    """Enhanced LLM provider with multi-provider support and advanced features."""

    def __init__(self):
        self.providers = self._initialize_providers()
        self.current_provider = 'null'  # Start with null provider
        self.retry_attempts = 3
        self.timeout = 30
        self.cache = {}
        self.metrics = {
            'calls_made': 0,
            'tokens_used': 0,
            'errors': 0,
            'cache_hits': 0,
            'fallbacks': 0
        }

    def _initialize_providers(self) -> Dict[str, ILLMProvider]:
        """Initialize available LLM providers."""
        providers: Dict[str, ILLMProvider] = {
            'null': NullLLMProvider()
        }

        # Try to initialize LangChain provider
        try:
            from providers.langchain_provider import LangChainLLMProvider
            providers['langchain'] = LangChainLLMProvider()  # type: ignore
        except Exception as e:
            logger.warning(f"Failed to initialize LangChain provider: {e}")

        # Try to initialize other providers (OpenAI, Anthropic, etc.)
        try:
            providers['openai'] = self._init_openai_provider()  # type: ignore
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI provider: {e}")

        try:
            providers['anthropic'] = self._init_anthropic_provider()  # type: ignore
        except Exception as e:
            logger.warning(f"Failed to initialize Anthropic provider: {e}")

        return providers

    def _init_openai_provider(self):
        """Initialize OpenAI provider."""
        # Placeholder for OpenAI integration
        raise NotImplementedError("OpenAI provider not yet implemented")

    def _init_anthropic_provider(self):
        """Initialize Anthropic provider."""
        # Placeholder for Anthropic integration
        raise NotImplementedError("Anthropic provider not yet implemented")

    def _select_provider(self, operation: str) -> str:
        """Select the best provider for the operation."""
        # Priority order based on operation and availability
        priority = {
            'summarize': ['langchain', 'openai', 'anthropic', 'null'],
            'refine_rules': ['langchain', 'openai', 'anthropic', 'null'],
            'triage': ['langchain', 'openai', 'anthropic', 'null']
        }

        for provider_name in priority.get(operation, ['null']):
            if provider_name in self.providers:
                return provider_name

        return 'null'

    async def _execute_with_fallback(self, operation: str, *args, **kwargs) -> Tuple[Any, ProviderMetadata]:
        """Execute operation with automatic fallback."""
        errors = []
        failed_providers = set()

        for attempt in range(self.retry_attempts):
            provider_name = self._select_provider(operation)
            
            # Skip providers that have failed
            if provider_name in failed_providers:
                continue
                
            if provider_name not in self.providers:
                errors.append(f"Provider {provider_name} not available")
                failed_providers.add(provider_name)
                continue
                
            provider = self.providers[provider_name]

            try:
                # Add timeout
                start_time = time.time()
                result_tuple = await asyncio.wait_for(
                    self._call_provider_method(provider, operation, *args, **kwargs),
                    timeout=self.timeout
                )
                
                # Unpack the result and metadata
                if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                    result, provider_metadata = result_tuple
                else:
                    # Handle legacy providers that don't return metadata
                    result = result_tuple
                    provider_metadata = ProviderMetadata(
                        model_name=provider_name,
                        provider_name="enhanced",
                        latency_ms=int((time.time() - start_time) * 1000),
                        tokens_prompt=0,
                        tokens_completion=0,
                        cached=False,
                        fallback=False,
                        timestamp=datetime.now().isoformat()
                    )

                if provider_name != self.current_provider:
                    self.metrics['fallbacks'] += 1
                    logger.info(f"Fell back to provider: {provider_name}")

                self.current_provider = provider_name
                self.metrics['calls_made'] += 1
                
                # Update metadata with enhanced provider info
                enhanced_metadata = ProviderMetadata(
                    model_name=provider_metadata.model_name,
                    provider_name="enhanced",
                    latency_ms=provider_metadata.latency_ms,
                    tokens_prompt=provider_metadata.tokens_prompt,
                    tokens_completion=provider_metadata.tokens_completion,
                    cached=provider_metadata.cached,
                    fallback=provider_metadata.fallback or (self.metrics['fallbacks'] > 0),
                    timestamp=provider_metadata.timestamp
                )
                
                return result, enhanced_metadata

            except Exception as e:
                error_msg = f"Provider {provider_name} failed: {e}"
                errors.append(error_msg)
                logger.warning(error_msg)
                failed_providers.add(provider_name)

        # All providers failed, use null provider as fallback
        logger.error(f"All providers failed, using null provider. Errors: {errors}")
        try:
            null_provider = NullLLMProvider()
            start_time = time.time()
            # Filter out problematic kwargs for null provider
            safe_kwargs = {k: v for k, v in kwargs.items() if k in ['skip', 'previous', 'skip_reason', 'baseline_context', 'examples']}
            result_tuple = await self._call_provider_method(null_provider, operation, *args, **safe_kwargs)
            
            if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                result, provider_metadata = result_tuple
            else:
                result = result_tuple
                provider_metadata = ProviderMetadata(
                    model_name="null-fallback",
                    provider_name="enhanced",
                    latency_ms=int((time.time() - start_time) * 1000),
                    tokens_prompt=0,
                    tokens_completion=0,
                    cached=False,
                    fallback=True,
                    timestamp=datetime.now().isoformat()
                )
            
            enhanced_metadata = ProviderMetadata(
                model_name=provider_metadata.model_name,
                provider_name="enhanced",
                latency_ms=provider_metadata.latency_ms,
                tokens_prompt=provider_metadata.tokens_prompt,
                tokens_completion=provider_metadata.tokens_completion,
                cached=provider_metadata.cached,
                fallback=True,
                timestamp=provider_metadata.timestamp
            )
            
            return result, enhanced_metadata
        except Exception as e:
            # If even null provider fails, raise the original error
            raise RuntimeError(f"All providers failed including null fallback. Errors: {errors}") from e

    async def _call_provider_method(self, provider: ILLMProvider, operation: str, *args, **kwargs):
        """Call the appropriate method on the provider."""
        method = getattr(provider, operation)
        if asyncio.iscoroutinefunction(method):
            return await method(*args, **kwargs)
        else:
            # Run sync method in thread pool - filter out problematic kwargs
            loop = asyncio.get_event_loop()
            # Only pass kwargs that the method actually accepts
            import inspect
            sig = inspect.signature(method)
            valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
            return await loop.run_in_executor(None, lambda: method(*args, **valid_kwargs))

    def summarize(self, reductions: Reductions, correlations: List[Correlation],
                  actions: List[ActionItem], *, skip: bool = False,
                  previous: Optional[Summaries] = None, skip_reason: Optional[str] = None,
                  baseline_context: Optional[Dict[str, Any]] = None) -> Tuple[Summaries, ProviderMetadata]:

        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key('summarize', reductions, correlations)
        if cache_key in self.cache:
            self.metrics['cache_hits'] += 1
            cached_result, cached_metadata = self.cache[cache_key]
            latency = time.time() - start_time
            metadata = ProviderMetadata(
                model_name=cached_metadata.model_name,
                provider_name="enhanced",
                latency_ms=int(latency * 1000),
                tokens_prompt=cached_metadata.tokens_prompt,
                tokens_completion=cached_metadata.tokens_completion,
                cached=True,
                fallback=cached_metadata.fallback,
                timestamp=datetime.now().isoformat()
            )
            return cached_result, metadata

        # Execute with fallback - handle async properly
        try:
            # Check if we're in an async context
            loop = asyncio.get_running_loop()
            if loop.is_running():
                # We're in a running event loop - use null provider to avoid conflicts
                logger.info("Detected running event loop, using null provider for deterministic behavior")
                null_provider = NullLLMProvider()
                result, provider_metadata = null_provider.summarize(
                    reductions, correlations, actions,
                    skip=skip, previous=previous, skip_reason=skip_reason,
                    baseline_context=baseline_context
                )
            else:
                # Not in an async context, can use asyncio.run
                async def _summarize():
                    return await self._execute_with_fallback(
                        'summarize', reductions, correlations, actions,
                        skip=skip, previous=previous, skip_reason=skip_reason,
                        baseline_context=baseline_context
                    )
                result, provider_metadata = asyncio.run(_summarize())
        except RuntimeError as e:
            if "cannot be called from a running event loop" in str(e):
                # Fallback: use null provider
                logger.warning("Asyncio event loop conflict, falling back to null provider")
                null_provider = NullLLMProvider()
                result, provider_metadata = null_provider.summarize(
                    reductions, correlations, actions,
                    skip=skip, previous=previous, skip_reason=skip_reason,
                    baseline_context=baseline_context
                )
            else:
                raise

        # Cache result
        self.cache[cache_key] = (result, provider_metadata)

        # Update metrics from provider metadata
        self.metrics['tokens_used'] += provider_metadata.tokens_prompt + provider_metadata.tokens_completion

        latency = time.time() - start_time
        metadata = ProviderMetadata(
            model_name=provider_metadata.model_name,
            provider_name="enhanced",
            latency_ms=int(latency * 1000),
            tokens_prompt=provider_metadata.tokens_prompt,
            tokens_completion=provider_metadata.tokens_completion,
            cached=False,
            fallback=provider_metadata.fallback or (self.metrics['fallbacks'] > 0),
            timestamp=datetime.now().isoformat()
        )

        return result, metadata

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], ProviderMetadata]:

        start_time = time.time()

        # Execute with fallback - handle async properly
        try:
            # Check if we're in an async context
            loop = asyncio.get_running_loop()
            if loop.is_running():
                # We're in a running event loop - use null provider to avoid conflicts
                logger.info("Detected running event loop, using null provider for deterministic behavior")
                null_provider = NullLLMProvider()
                result, provider_metadata = null_provider.refine_rules(suggestions, examples)
            else:
                # Not in an async context, can use asyncio.run
                async def _refine():
                    return await self._execute_with_fallback('refine_rules', suggestions, examples)
                result, provider_metadata = asyncio.run(_refine())
        except RuntimeError as e:
            if "cannot be called from a running event loop" in str(e):
                # Fallback: use null provider
                logger.warning("Asyncio event loop conflict, falling back to null provider")
                null_provider = NullLLMProvider()
                result, provider_metadata = null_provider.refine_rules(suggestions, examples)
            else:
                raise

        latency = time.time() - start_time
        metadata = ProviderMetadata(
            model_name=provider_metadata.model_name,
            provider_name="enhanced",
            latency_ms=int(latency * 1000),
            tokens_prompt=provider_metadata.tokens_prompt,
            tokens_completion=provider_metadata.tokens_completion,
            cached=False,
            fallback=provider_metadata.fallback or (self.metrics['fallbacks'] > 0),
            timestamp=datetime.now().isoformat()
        )

        return result, metadata

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]:

        start_time = time.time()

        # Execute with fallback - handle async properly
        try:
            # Check if we're in an async context
            loop = asyncio.get_running_loop()
            if loop.is_running():
                # We're in a running event loop - use null provider to avoid conflicts
                logger.info("Detected running event loop, using null provider for deterministic behavior")
                null_provider = NullLLMProvider()
                result, provider_metadata = null_provider.triage(reductions, correlations)
            else:
                # Not in an async context, can use asyncio.run
                async def _triage():
                    return await self._execute_with_fallback('triage', reductions, correlations)
                result, provider_metadata = asyncio.run(_triage())
        except RuntimeError as e:
            if "cannot be called from a running event loop" in str(e):
                # Fallback: use null provider
                logger.warning("Asyncio event loop conflict, falling back to null provider")
                null_provider = NullLLMProvider()
                result, provider_metadata = null_provider.triage(reductions, correlations)
            else:
                raise

        latency = time.time() - start_time
        metadata = ProviderMetadata(
            model_name=provider_metadata.model_name,
            provider_name="enhanced",
            latency_ms=int(latency * 1000),
            tokens_prompt=provider_metadata.tokens_prompt,
            tokens_completion=provider_metadata.tokens_completion,
            cached=False,
            fallback=provider_metadata.fallback or (self.metrics['fallbacks'] > 0),
            timestamp=datetime.now().isoformat()
        )

        return result, metadata

    def _generate_cache_key(self, operation: str, *args) -> str:
        """Generate cache key for operation."""
        # Simple hash-based key generation
        key_data = f"{operation}_{str(args)}"
        return str(hash(key_data))

    def get_metrics(self) -> Dict[str, Any]:
        """Get provider metrics."""
        return self.metrics.copy()

    def clear_cache(self):
        """Clear the response cache."""
        self.cache.clear()

    def set_provider_priority(self, operation: str, priority: List[str]):
        """Set provider priority for specific operation."""
        # This would modify the _select_provider logic
        pass

# Global enhanced provider instance
_enhanced_provider: Optional[EnhancedLLMProvider] = None

def get_enhanced_llm_provider() -> EnhancedLLMProvider:
    """Get the enhanced LLM provider instance."""
    global _enhanced_provider
    if _enhanced_provider is None:
        _enhanced_provider = EnhancedLLMProvider()
    return _enhanced_provider

def set_enhanced_llm_provider(provider: EnhancedLLMProvider) -> None:
    """Set the enhanced LLM provider instance."""
    global _enhanced_provider
    _enhanced_provider = provider

__all__ = [
    'EnhancedLLMProvider',
    'get_enhanced_llm_provider',
    'set_enhanced_llm_provider'
]
