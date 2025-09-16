from __future__ import annotations
"""Retrieval augmentation system for knowledge packs and contextual information.

This module provides retrieval-augmented generation (RAG) capabilities for the LLM pipeline,
enabling context-aware responses by retrieving relevant information from knowledge bases.
"""

from typing import List, Dict, Any, Optional, Tuple
import logging
from pathlib import Path
import yaml
import json
from datetime import datetime
import re
from .knowledge import KNOWLEDGE_DIR, _load_yaml

logger = logging.getLogger(__name__)

class KnowledgeRetriever:
    """Retriever for knowledge packs and contextual information."""

    def __init__(self):
        self.knowledge_dir = KNOWLEDGE_DIR
        self.cache = {}
        self.last_updated = {}

    def retrieve_context(self, query: str, context_type: str = "general",
                        max_results: int = 5, similarity_threshold: float = 0.1) -> List[Dict[str, Any]]:
        """Retrieve relevant context from knowledge packs based on query.

        Args:
            query: The search query or context to match against
            context_type: Type of context to retrieve ('ports', 'modules', 'suid', 'orgs', 'general')
            max_results: Maximum number of results to return
            similarity_threshold: Minimum similarity score for results

        Returns:
            List of relevant context items with metadata
        """
        start_time = datetime.now()

        # Determine which knowledge files to search
        if context_type == "general":
            knowledge_files = ["ports.yaml", "modules.yaml", "suid_programs.yaml", "orgs.yaml"]
        else:
            knowledge_files = [f"{context_type}.yaml"]

        results = []

        for filename in knowledge_files:
            if not (self.knowledge_dir / filename).exists():
                continue

            # Load knowledge data
            data = _load_yaml(filename)

            # Search through the knowledge data
            file_results = self._search_knowledge_file(data, query, filename, similarity_threshold)
            results.extend(file_results)

        # Sort by relevance score and limit results
        results.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        results = results[:max_results]

        # Add retrieval metadata
        for result in results:
            result['retrieved_at'] = start_time.isoformat()
            result['query'] = query
            result['context_type'] = context_type

        logger.info(f"Retrieved {len(results)} context items for query: {query}")
        return results

    def _search_knowledge_file(self, data: Dict[str, Any], query: str,
                              filename: str, threshold: float) -> List[Dict[str, Any]]:
        """Search through a knowledge file for relevant content."""
        results = []
        query_lower = query.lower()

        # Extract the main data section
        main_key = filename.replace('.yaml', '')
        if main_key in data:
            items = data[main_key]
        else:
            items = data

        if not isinstance(items, dict):
            return results

        for key, item_data in items.items():
            if not isinstance(item_data, dict):
                continue

            # Calculate relevance score based on text matching
            relevance_score = self._calculate_relevance(query_lower, key, item_data)

            if relevance_score >= threshold:
                result = {
                    'key': key,
                    'data': item_data,
                    'relevance_score': relevance_score,
                    'source_file': filename,
                    'matched_fields': self._get_matched_fields(query_lower, key, item_data)
                }
                results.append(result)

        return results

    def _calculate_relevance(self, query: str, key: str, data: Dict[str, Any]) -> float:
        """Calculate relevance score for a knowledge item."""
        score = 0.0
        query_terms = set(re.findall(r'\b\w+\b', query))

        # Check key relevance
        key_lower = key.lower()
        key_matches = sum(1 for term in query_terms if term in key_lower)
        score += key_matches * 0.3  # Key matches are more important

        # Check data field relevance
        for field_value in data.values():
            if isinstance(field_value, str):
                field_lower = field_value.lower()
                field_matches = sum(1 for term in query_terms if term in field_lower)
                score += field_matches * 0.2
            elif isinstance(field_value, list):
                for item in field_value:
                    if isinstance(item, str):
                        item_lower = item.lower()
                        item_matches = sum(1 for term in query_terms if term in item_lower)
                        score += item_matches * 0.15

        # Normalize score
        max_possible_score = len(query_terms) * 0.5  # Conservative upper bound
        if max_possible_score > 0:
            score = min(score / max_possible_score, 1.0)

        return score

    def _get_matched_fields(self, query: str, key: str, data: Dict[str, Any]) -> List[str]:
        """Get list of fields that matched the query."""
        matched = []
        query_terms = set(re.findall(r'\b\w+\b', query))

        if any(term in key.lower() for term in query_terms):
            matched.append('key')

        for field_name, field_value in data.items():
            if isinstance(field_value, str):
                if any(term in field_value.lower() for term in query_terms):
                    matched.append(field_name)
            elif isinstance(field_value, list):
                if any(isinstance(item, str) and any(term in item.lower() for term in query_terms)
                      for item in field_value):
                    matched.append(field_name)

        return matched

    def get_context_summary(self, context_items: List[Dict[str, Any]]) -> str:
        """Generate a human-readable summary of retrieved context."""
        if not context_items:
            return "No relevant context found."

        summary_parts = []
        for item in context_items:
            key = item['key']
            data = item['data']
            score = item.get('relevance_score', 0)

            # Create a concise description
            if 'service' in data:
                desc = f"Port {key}: {data.get('service', 'Unknown service')}"
            elif 'family' in data:
                desc = f"Module {key}: {data.get('family', 'Unknown family')}"
            elif 'expected' in data:
                desc = f"SUID program {key}"
            elif 'cidrs' in data:
                desc = f"Organization {key}: {len(data.get('cidrs', []))} IP ranges"
            else:
                desc = f"Item {key}"

            summary_parts.append(f"• {desc} (relevance: {score:.2f})")

        return "\n".join(summary_parts)

# Global retriever instance
_retriever: Optional[KnowledgeRetriever] = None

def get_retriever() -> KnowledgeRetriever:
    """Get the global knowledge retriever instance."""
    global _retriever
    if _retriever is None:
        _retriever = KnowledgeRetriever()
    return _retriever

def retrieve_context(query: str, context_type: str = "general",
                    max_results: int = 5, similarity_threshold: float = 0.1) -> List[Dict[str, Any]]:
    """Retrieve relevant context from knowledge packs.

    This is the main entry point for retrieval augmentation in the LLM pipeline.

    Args:
        query: The search query or context to match against
        context_type: Type of context ('ports', 'modules', 'suid', 'orgs', 'general')
        max_results: Maximum number of results to return
        similarity_threshold: Minimum similarity score (0.0 to 1.0)

    Returns:
        List of relevant context items with metadata

    Example:
        >>> context = retrieve_context("nginx web server", "ports")
        >>> print(f"Found {len(context)} relevant items")
    """
    retriever = get_retriever()
    return retriever.retrieve_context(query, context_type, max_results, similarity_threshold)

def retrieve_context_with_summary(query: str, context_type: str = "general",
                                 max_results: int = 5, similarity_threshold: float = 0.1) -> Tuple[List[Dict[str, Any]], str]:
    """Retrieve context and return both raw data and human-readable summary."""
    context_items = retrieve_context(query, context_type, max_results, similarity_threshold)
    retriever = get_retriever()
    summary = retriever.get_context_summary(context_items)
    return context_items, summary

__all__ = [
    'KnowledgeRetriever',
    'get_retriever',
    'retrieve_context',
    'retrieve_context_with_summary'
]