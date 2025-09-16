from __future__ import annotations
"""Tool wrapper for contract validation and ToolMessage conversion.

This module provides a standardized wrapper for tool calls that:
- Validates inputs and outputs against the tool contract
- Converts between contract format and LangGraph ToolMessages
- Handles retries and error recovery
- Provides deterministic behavior and logging
"""

from typing import Dict, Any, List, Optional, Union, Tuple, Callable
import json
import uuid
import time
import logging
from datetime import datetime
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

# Try to import LangGraph components
try:
    from langchain_core.messages import AIMessage, ToolMessage
    LANGGRAPH_AVAILABLE = True
except ImportError:
    AIMessage = ToolMessage = None
    LANGGRAPH_AVAILABLE = False
    logger.warning("LangGraph not available, tool wrapper will use fallback mode")

class ToolContractError(Exception):
    """Raised when tool contract validation fails."""
    pass

class ToolContractValidator:
    """Validates tool calls against the contract specification."""

    def __init__(self):
        self.contract_version = "1.0"
        self.max_retries = 3
        self.retry_delay = 1.0

    def validate_input(self, tool_name: str, args: Dict[str, Any], request_id: str) -> Dict[str, Any]:
        """Validate tool input against contract.

        Args:
            tool_name: Name of the tool being called
            args: Tool arguments
            request_id: Request identifier

        Returns:
            Validated and normalized input

        Raises:
            ToolContractError: If validation fails
        """
        # Basic input validation
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ToolContractError("tool_name must be a non-empty string")

        if not isinstance(args, dict):
            raise ToolContractError("args must be a dictionary")

        if not isinstance(request_id, str) or not request_id.strip():
            raise ToolContractError("request_id must be a valid UUID string")

        # Tool-specific validation
        if tool_name == "query_baseline":
            self._validate_query_baseline_input(args)
        elif tool_name == "batch_baseline_query":
            self._validate_batch_baseline_query_input(args)
        else:
            logger.warning(f"Unknown tool: {tool_name}, skipping specific validation")

        # Add contract metadata
        validated_input = {
            "tool_name": tool_name,
            "args": args,
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "version": self.contract_version
        }

        return validated_input

    def validate_output(self, tool_name: str, output: Dict[str, Any]) -> Dict[str, Any]:
        """Validate tool output against contract.

        Args:
            tool_name: Name of the tool that produced output
            output: Tool output to validate

        Returns:
            Validated output

        Raises:
            ToolContractError: If validation fails
        """
        if not isinstance(output, dict):
            raise ToolContractError("Tool output must be a dictionary")

        required_fields = ["tool_name", "request_id", "status", "timestamp", "version"]
        for field in required_fields:
            if field not in output:
                raise ToolContractError(f"Missing required field: {field}")

        # Validate status
        valid_statuses = ["new", "existing", "error"]
        if output["status"] not in valid_statuses:
            raise ToolContractError(f"Invalid status: {output['status']}. Must be one of {valid_statuses}")

        # Validate payload for non-error responses
        if output["status"] != "error":
            if "payload" not in output:
                raise ToolContractError("payload field required for non-error responses")
            payload = output["payload"]
            if not isinstance(payload, dict):
                raise ToolContractError("payload must be a dictionary")

        # Validate error message for error responses
        if output["status"] == "error":
            if "error_msg" not in output or not output["error_msg"]:
                raise ToolContractError("error_msg field required for error responses")

        # Validate processing time
        if "processing_time_ms" in output:
            if not isinstance(output["processing_time_ms"], (int, float)) or output["processing_time_ms"] < 0:
                raise ToolContractError("processing_time_ms must be a non-negative number")

        # Tool-specific validation
        if tool_name == "query_baseline":
            self._validate_query_baseline_output(output)
        elif tool_name == "batch_baseline_query":
            self._validate_batch_baseline_query_output(output)

        return output

    def _validate_query_baseline_input(self, args: Dict[str, Any]):
        """Validate query_baseline tool input."""
        required_fields = ["finding_id", "composite_hash", "query_type"]
        for field in required_fields:
            if field not in args:
                raise ToolContractError(f"Missing required field for query_baseline: {field}")

        if args.get("query_type") != "baseline_check":
            raise ToolContractError("query_type must be 'baseline_check' for query_baseline")

    def _validate_batch_baseline_query_input(self, args: Dict[str, Any]):
        """Validate batch_baseline_query tool input."""
        required_fields = ["finding_ids", "composite_hashes", "query_type"]
        for field in required_fields:
            if field not in args:
                raise ToolContractError(f"Missing required field for batch_baseline_query: {field}")

        if args.get("query_type") != "batch_baseline_check":
            raise ToolContractError("query_type must be 'batch_baseline_check' for batch_baseline_query")

        # Validate array fields
        finding_ids = args.get("finding_ids", [])
        composite_hashes = args.get("composite_hashes", [])

        if not isinstance(finding_ids, list) or not isinstance(composite_hashes, list):
            raise ToolContractError("finding_ids and composite_hashes must be arrays")

        if len(finding_ids) != len(composite_hashes):
            raise ToolContractError("finding_ids and composite_hashes must have the same length")

        if len(finding_ids) == 0:
            raise ToolContractError("At least one finding must be provided")

    def _validate_query_baseline_output(self, output: Dict[str, Any]):
        """Validate query_baseline tool output."""
        if output["status"] != "error":
            payload = output["payload"]
            required_payload_fields = ["finding_id", "composite_hash", "baseline_status"]
            for field in required_payload_fields:
                if field not in payload:
                    raise ToolContractError(f"Missing required payload field for query_baseline: {field}")

    def _validate_batch_baseline_query_output(self, output: Dict[str, Any]):
        """Validate batch_baseline_query tool output."""
        if output["status"] != "error":
            payload = output["payload"]
            if not isinstance(payload, list):
                raise ToolContractError("payload must be an array for batch_baseline_query")

            if len(payload) == 0:
                raise ToolContractError("At least one result must be provided")

            # Validate each result in the batch
            for i, result in enumerate(payload):
                if not isinstance(result, dict):
                    raise ToolContractError(f"Batch result {i} must be a dictionary")

                required_fields = ["finding_id", "composite_hash", "baseline_status"]
                for field in required_fields:
                    if field not in result:
                        raise ToolContractError(f"Missing required field in batch result {i}: {field}")

class ToolWrapper:
    """Wrapper for tool calls with contract validation and ToolMessage conversion."""

    def __init__(self):
        self.validator = ToolContractValidator()
        self.logger = logging.getLogger(__name__)

    def wrap_tool_call(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap a tool call with contract validation and metadata.

        Args:
            tool_name: Name of the tool to call
            args: Tool arguments

        Returns:
            Wrapped tool call ready for execution
        """
        request_id = str(uuid.uuid4())

        # Validate input
        try:
            validated_input = self.validator.validate_input(tool_name, args, request_id)
            self.logger.debug(f"Tool call validated: {tool_name} ({request_id})")
            return validated_input
        except ToolContractError as e:
            self.logger.error(f"Tool input validation failed: {e}")
            raise

    def wrap_tool_response(self, tool_name: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap a tool response with contract validation and metadata.

        Args:
            tool_name: Name of the tool that produced the response
            response: Raw tool response

        Returns:
            Validated and wrapped tool response
        """
        start_time = time.time()

        try:
            # Add contract metadata if missing
            if "tool_name" not in response:
                response["tool_name"] = tool_name
            if "timestamp" not in response:
                response["timestamp"] = datetime.now().isoformat()
            if "version" not in response:
                response["version"] = self.validator.contract_version
            if "processing_time_ms" not in response:
                response["processing_time_ms"] = int((time.time() - start_time) * 1000)

            # Validate output
            validated_response = self.validator.validate_output(tool_name, response)
            self.logger.debug(f"Tool response validated: {tool_name}")

            return validated_response

        except ToolContractError as e:
            self.logger.error(f"Tool output validation failed: {e}")
            # Return error response
            return {
                "tool_name": tool_name,
                "request_id": response.get("request_id", "unknown"),
                "status": "error",
                "error_msg": f"Contract validation failed: {str(e)}",
                "timestamp": datetime.now().isoformat(),
                "version": self.validator.contract_version,
                "processing_time_ms": int((time.time() - start_time) * 1000)
            }

    def to_tool_message(self, tool_call: Dict[str, Any]) -> Optional[Any]:
        """Convert a wrapped tool call to a LangGraph ToolMessage.

        Args:
            tool_call: Wrapped tool call

        Returns:
            ToolMessage instance or None if LangGraph not available
        """
        if ToolMessage is None:
            self.logger.warning("LangGraph not available, cannot create ToolMessage")
            return None

        try:
            # Create tool call structure expected by LangGraph
            tool_call_structure = {
                "name": tool_call["tool_name"],
                "args": tool_call["args"],
                "id": tool_call["request_id"]
            }

            if LANGGRAPH_AVAILABLE and AIMessage is not None:
                message = AIMessage(
                    content="Tool execution required",
                    tool_calls=[tool_call_structure]
                )
                return message
            else:
                # Fallback: return the tool call structure directly
                return tool_call_structure

        except Exception as e:
            self.logger.error(f"Failed to create ToolMessage: {e}")
            return None

    def from_tool_message(self, tool_message: Any) -> Optional[Dict[str, Any]]:
        """Extract tool call from a LangGraph ToolMessage.

        Args:
            tool_message: ToolMessage instance

        Returns:
            Extracted tool call data or None if invalid
        """
        if ToolMessage is None or not hasattr(tool_message, 'tool_calls'):
            return None

        try:
            tool_calls = tool_message.tool_calls
            if not tool_calls:
                return None

            # Take the first tool call
            tool_call = tool_calls[0]

            wrapped_call = {
                "tool_name": tool_call.get("name", ""),
                "args": tool_call.get("args", {}),
                "request_id": tool_call.get("id", str(uuid.uuid4())),
                "timestamp": datetime.now().isoformat(),
                "version": self.validator.contract_version
            }

            return wrapped_call

        except Exception as e:
            self.logger.error(f"Failed to extract tool call from ToolMessage: {e}")
            return None

    def execute_with_retry(self, tool_func: Callable[..., Any], tool_name: str,
                          args: Dict[str, Any], max_retries: Optional[int] = None) -> Dict[str, Any]:
        """Execute a tool function with retry logic and contract validation.

        Args:
            tool_func: Tool function to execute
            tool_name: Name of the tool
            args: Tool arguments
            max_retries: Maximum number of retries (default: from validator)

        Returns:
            Validated tool response
        """
        if max_retries is None:
            max_retries = self.validator.max_retries

        last_error = None

        for attempt in range(max_retries + 1):
            try:
                # Wrap the tool call
                wrapped_call = self.wrap_tool_call(tool_name, args)

                # Execute the tool
                start_time = time.time()
                raw_response = tool_func(**wrapped_call)
                execution_time = time.time() - start_time

                # Ensure response is a dict
                if not isinstance(raw_response, dict):
                    raw_response = {"result": raw_response}

                # Add execution metadata
                raw_response["request_id"] = wrapped_call["request_id"]
                raw_response["processing_time_ms"] = int(execution_time * 1000)

                # Wrap and validate response
                validated_response = self.wrap_tool_response(tool_name, raw_response)

                self.logger.info(f"Tool execution successful: {tool_name} (attempt {attempt + 1})")
                return validated_response

            except Exception as e:
                last_error = e
                self.logger.warning(f"Tool execution failed (attempt {attempt + 1}/{max_retries + 1}): {e}")

                if attempt < max_retries:
                    time.sleep(self.validator.retry_delay * (2 ** attempt))  # Exponential backoff

        # All retries failed
        error_response = {
            "tool_name": tool_name,
            "request_id": str(uuid.uuid4()),
            "status": "error",
            "error_msg": f"Tool execution failed after {max_retries + 1} attempts: {str(last_error)}",
            "timestamp": datetime.now().isoformat(),
            "version": self.validator.contract_version,
            "processing_time_ms": 0
        }

        self.logger.error(f"Tool execution failed permanently: {tool_name}")
        return error_response

# Global tool wrapper instance
_tool_wrapper: Optional[ToolWrapper] = None

def get_tool_wrapper() -> ToolWrapper:
    """Get the global tool wrapper instance."""
    global _tool_wrapper
    if _tool_wrapper is None:
        _tool_wrapper = ToolWrapper()
    return _tool_wrapper

def validate_tool_contract(tool_name: str, input_data: Optional[Dict[str, Any]] = None,
                          output_data: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """Validate tool data against contract.

    Args:
        tool_name: Name of the tool
        input_data: Input data to validate (optional)
        output_data: Output data to validate (optional)

    Returns:
        Tuple of (is_valid, error_message)
    """
    wrapper = get_tool_wrapper()
    validator = wrapper.validator

    try:
        if input_data:
            validator.validate_input(tool_name, input_data, input_data.get("request_id", "test"))
        if output_data:
            validator.validate_output(tool_name, output_data)
        return True, ""
    except ToolContractError as e:
        return False, str(e)

def create_tool_message(tool_name: str, args: Dict[str, Any]) -> Optional[Any]:
    """Create a LangGraph ToolMessage for a tool call.

    Args:
        tool_name: Name of the tool
        args: Tool arguments

    Returns:
        ToolMessage instance or None
    """
    wrapper = get_tool_wrapper()
    wrapped_call = wrapper.wrap_tool_call(tool_name, args)
    return wrapper.to_tool_message(wrapped_call)

__all__ = [
    'ToolContractError',
    'ToolContractValidator',
    'ToolWrapper',
    'get_tool_wrapper',
    'validate_tool_contract',
    'create_tool_message'
]