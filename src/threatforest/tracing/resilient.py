"""
Resilient Tracing Manager Module

This module provides a resilient tracing manager that gracefully degrades when
Langfuse is unavailable. It extends the TracingManager with fallback mode
capabilities, buffering traces locally when connection fails and attempting
to flush them when the workflow completes.

Requirements:
- 9.3: When Langfuse connection fails, log a warning and continue workflow execution

Property 15: Connection Failure Resilience
*For any* workflow execution where Langfuse connection fails (network error,
invalid credentials), the workflow SHALL continue execution, a warning SHALL
be logged, and the workflow result SHALL not be affected.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.interfaces import ISpan, ITrace
from threatforest.tracing.manager import TracingManager
from threatforest.tracing.noop import NoOpSpan, NoOpTrace

logger = logging.getLogger(__name__)


@dataclass
class BufferedTrace:
    """
    Represents a trace that has been buffered due to connection failure.
    
    This dataclass stores all the information needed to recreate a trace
    when the connection is restored.
    
    Attributes:
        name: Name of the trace.
        session_id: Session identifier for grouping related traces.
        metadata: Optional metadata attached to the trace.
        trace_id: Unique identifier for this trace.
        created_at: Timestamp when the trace was created.
        output: Output data set on the trace.
        status: Completion status of the trace.
        error: Error message if status is "error".
        scores: List of scores added to the trace.
        categorical_scores: List of categorical scores added to the trace.
        additional_metadata: Additional metadata added after creation.
    """
    name: str
    session_id: str
    metadata: Optional[Dict[str, Any]] = None
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    output: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    error: Optional[str] = None
    scores: List[Dict[str, Any]] = field(default_factory=list)
    categorical_scores: List[Dict[str, Any]] = field(default_factory=list)
    additional_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BufferedSpan:
    """
    Represents a span that has been buffered due to connection failure.
    
    Attributes:
        name: Name of the span.
        trace_id: ID of the parent trace.
        metadata: Optional metadata attached to the span.
        span_id: Unique identifier for this span.
        input_data: Input data set on the span.
        output_data: Output data set on the span.
        span_metadata: Metadata set on the span.
        status: Completion status of the span.
    """
    name: str
    trace_id: str
    metadata: Optional[Dict[str, Any]] = None
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    input_data: Optional[Dict[str, Any]] = None
    output_data: Optional[Dict[str, Any]] = None
    span_metadata: Dict[str, Any] = field(default_factory=dict)
    status: str = "success"


class BufferedTraceWrapper(ITrace):
    """
    A trace wrapper that buffers operations when Langfuse is unavailable.
    
    This class implements the ITrace interface but stores all operations
    in a BufferedTrace dataclass instead of sending them to Langfuse.
    The buffered data can be flushed later when the connection is restored.
    """
    
    def __init__(self, buffered_trace: BufferedTrace):
        """
        Initialize a BufferedTraceWrapper.
        
        Args:
            buffered_trace: The BufferedTrace dataclass to store operations.
        """
        self._buffered_trace = buffered_trace
    
    @property
    def trace_id(self) -> str:
        """
        Get the unique identifier for this trace.
        
        Returns:
            str: Unique trace identifier (UUID format).
        """
        return self._buffered_trace.trace_id
    
    @property
    def session_id(self) -> str:
        """
        Get the session identifier for this trace.
        
        Returns:
            str: Session identifier for grouping related traces.
        """
        return self._buffered_trace.session_id
    
    def set_output(self, output: Dict[str, Any]) -> None:
        """
        Set the trace output data.
        
        Args:
            output: Dictionary containing the workflow's output data.
        """
        self._buffered_trace.output = output
    
    def set_status(self, status: str, error: Optional[str] = None) -> None:
        """
        Set trace completion status.
        
        Args:
            status: Completion status ("success" or "error").
            error: Error message if status is "error".
        """
        self._buffered_trace.status = status
        self._buffered_trace.error = error
    
    def add_score(
        self,
        name: str,
        value: float,
        comment: Optional[str] = None
    ) -> None:
        """
        Add a numeric score to this trace.
        
        Args:
            name: Score dimension name.
            value: Score value in range [0.0, 1.0].
            comment: Optional comment explaining the score.
        
        Raises:
            ValueError: If value is outside the range [0.0, 1.0].
        """
        if value < 0.0 or value > 1.0:
            raise ValueError(
                f"Score value must be in range [0.0, 1.0], got {value}"
            )
        self._buffered_trace.scores.append({
            "name": name,
            "value": value,
            "comment": comment
        })
    
    def add_categorical_score(
        self,
        name: str,
        category: str,
        allowed_categories: List[str],
        comment: Optional[str] = None
    ) -> None:
        """
        Add a categorical score to this trace.
        
        Args:
            name: Score dimension name.
            category: The categorical value.
            allowed_categories: List of valid category values.
            comment: Optional comment explaining the score.
        
        Raises:
            ValueError: If category is not in allowed_categories.
        """
        if category not in allowed_categories:
            raise ValueError(
                f"Category '{category}' is not in allowed categories: {allowed_categories}"
            )
        self._buffered_trace.categorical_scores.append({
            "name": name,
            "category": category,
            "allowed_categories": allowed_categories,
            "comment": comment
        })
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to this trace.
        
        Args:
            key: Metadata key name.
            value: Metadata value.
        """
        self._buffered_trace.additional_metadata[key] = value


class BufferedSpanWrapper(ISpan):
    """
    A span wrapper that buffers operations when Langfuse is unavailable.
    
    This class implements the ISpan interface but stores all operations
    in a BufferedSpan dataclass instead of sending them to Langfuse.
    """
    
    def __init__(self, buffered_span: BufferedSpan):
        """
        Initialize a BufferedSpanWrapper.
        
        Args:
            buffered_span: The BufferedSpan dataclass to store operations.
        """
        self._buffered_span = buffered_span
    
    @property
    def span_id(self) -> str:
        """
        Get the unique identifier for this span.
        
        Returns:
            str: Unique span identifier.
        """
        return self._buffered_span.span_id
    
    def set_input(self, input_data: Dict[str, Any]) -> None:
        """
        Set the input data for this span.
        
        Args:
            input_data: Dictionary containing the span's input parameters.
        """
        self._buffered_span.input_data = input_data
    
    def set_output(self, output_data: Dict[str, Any]) -> None:
        """
        Set the output data for this span.
        
        Args:
            output_data: Dictionary containing the span's output/results.
        """
        self._buffered_span.output_data = output_data
    
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Set span metadata including tokens and latency.
        
        Args:
            metadata: Dictionary containing metadata key-value pairs.
        """
        self._buffered_span.span_metadata.update(metadata)
    
    def end(self, status: str = "success") -> None:
        """
        Mark the span as complete.
        
        Args:
            status: Completion status ("success" or "error").
        """
        self._buffered_span.status = status
    
    def generation(self, name: str, model: str):
        """
        Create a nested generation for LLM calls.
        
        In buffered mode, this returns a NoOp generation context manager.
        
        Args:
            name: Name of the generation.
            model: Model identifier.
        
        Yields:
            IGeneration: Generation object for capturing LLM call details.
        """
        from contextlib import contextmanager
        from threatforest.tracing.noop import NoOpGeneration
        
        @contextmanager
        def _generation_context():
            yield NoOpGeneration()
        
        return _generation_context()


class ResilientTracingManager(TracingManager):
    """
    Tracing manager with graceful degradation.
    
    This class extends TracingManager with fallback mode capabilities.
    When Langfuse connection fails, it switches to buffering mode where
    traces are stored locally. On workflow completion, it attempts to
    flush the buffered traces.
    
    The resilient manager ensures that workflow execution continues
    uninterrupted even when Langfuse is unavailable, logging warnings
    to alert operators of the degraded state.
    
    Requirements:
    - 9.3: When Langfuse connection fails, log a warning and continue workflow
    
    Example:
        >>> config = LangfuseConfig.from_env()
        >>> manager = ResilientTracingManager(config)
        >>> trace = manager.create_trace("workflow", "session-123")
        >>> # If Langfuse fails, trace will be buffered
        >>> manager.flush()  # Attempts to flush buffered traces
    """
    
    _instance: Optional["ResilientTracingManager"] = None
    
    def __new__(cls, config: Optional[LangfuseConfig] = None) -> "ResilientTracingManager":
        """
        Create or return the singleton ResilientTracingManager instance.
        
        Note: This overrides the parent's singleton to ensure we get a
        ResilientTracingManager instance, not a TracingManager.
        
        Args:
            config: Optional Langfuse configuration.
        
        Returns:
            ResilientTracingManager: The singleton instance.
        """
        if cls._instance is None:
            instance = object.__new__(cls)
            instance._initialized = False
            cls._instance = instance
        return cls._instance
    
    def __init__(self, config: Optional[LangfuseConfig] = None):
        """
        Initialize the ResilientTracingManager.
        
        This initializes the parent TracingManager and sets up the
        fallback mode and buffered traces storage.
        
        Args:
            config: Optional Langfuse configuration.
        """
        if self._initialized:
            return
        
        self._fallback_mode = False
        self._buffered_traces: List[BufferedTrace] = []
        self._buffered_spans: List[BufferedSpan] = []
        self._logger = logger
        
        # Initialize parent - this may fail if Langfuse is unavailable
        try:
            # Store config before calling parent init
            self._config = config or LangfuseConfig.from_env()
            self._client = None
            
            if self._config.enabled:
                self._config.validate()
                self._client = self._init_client()
            
            self._initialized = True
            self._logger.info(
                f"ResilientTracingManager initialized (enabled={self._config.enabled})"
            )
        except Exception as e:
            # If initialization fails, switch to fallback mode
            self._logger.warning(
                f"Langfuse initialization failed, switching to fallback mode: {e}"
            )
            self._fallback_mode = True
            self._client = None
            self._initialized = True
    
    def _buffer_trace(
        self,
        name: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ITrace:
        """
        Create a buffered trace when in fallback mode.
        
        Args:
            name: Name of the trace.
            session_id: Session identifier.
            metadata: Optional metadata.
        
        Returns:
            BufferedTraceWrapper: A trace wrapper that buffers operations.
        """
        buffered = BufferedTrace(
            name=name,
            session_id=session_id,
            metadata=metadata
        )
        self._buffered_traces.append(buffered)
        return BufferedTraceWrapper(buffered)
    
    def _buffer_span(
        self,
        name: str,
        trace: ITrace,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ISpan:
        """
        Create a buffered span when in fallback mode.
        
        Args:
            name: Name of the span.
            trace: Parent trace.
            metadata: Optional metadata.
        
        Returns:
            BufferedSpanWrapper: A span wrapper that buffers operations.
        """
        buffered = BufferedSpan(
            name=name,
            trace_id=trace.trace_id,
            metadata=metadata
        )
        self._buffered_spans.append(buffered)
        return BufferedSpanWrapper(buffered)
    
    def create_trace(
        self,
        name: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ITrace:
        """
        Create a new parent trace for a workflow run.
        
        If in fallback mode, returns a buffered trace. Otherwise, attempts
        to create a real Langfuse trace. If the Langfuse call fails, switches
        to fallback mode and returns a buffered trace.
        
        Args:
            name: Name of the trace.
            session_id: Session identifier.
            metadata: Optional metadata.
        
        Returns:
            ITrace: New trace object (LangfuseTrace or BufferedTraceWrapper).
        """
        if self._fallback_mode:
            return self._buffer_trace(name, session_id, metadata)
        
        try:
            return super().create_trace(name, session_id, metadata)
        except Exception as e:
            self._logger.warning(
                f"Langfuse unavailable, buffering traces: {e}"
            )
            self._fallback_mode = True
            return self._buffer_trace(name, session_id, metadata)
    
    def create_span(
        self,
        name: str,
        trace: ITrace,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ISpan:
        """
        Create a child span within a trace.
        
        If in fallback mode or the trace is buffered, returns a buffered span.
        Otherwise, attempts to create a real Langfuse span.
        
        Args:
            name: Name of the span.
            trace: Parent trace.
            metadata: Optional metadata.
        
        Returns:
            ISpan: New span object (LangfuseSpan or BufferedSpanWrapper).
        """
        # If trace is buffered, span should also be buffered
        if isinstance(trace, BufferedTraceWrapper):
            return self._buffer_span(name, trace, metadata)
        
        if self._fallback_mode:
            return self._buffer_span(name, trace, metadata)
        
        try:
            return super().create_span(name, trace, metadata)
        except Exception as e:
            self._logger.warning(
                f"Langfuse unavailable for span creation, buffering: {e}"
            )
            self._fallback_mode = True
            return self._buffer_span(name, trace, metadata)
    
    def _flush_buffered_traces(self) -> bool:
        """
        Attempt to flush buffered traces to Langfuse.
        
        This method tries to recreate all buffered traces and spans in
        Langfuse. If successful, clears the buffers and exits fallback mode.
        
        Returns:
            bool: True if flush was successful, False otherwise.
        """
        if not self._buffered_traces:
            return True
        
        try:
            # Try to reinitialize the client
            if self._client is None and self._config.enabled:
                self._client = self._init_client()
            
            if self._client is None:
                return False
            
            # Recreate traces
            for buffered in self._buffered_traces:
                trace_metadata = buffered.metadata.copy() if buffered.metadata else {}
                trace_metadata["timestamp"] = buffered.created_at
                trace_metadata.update(buffered.additional_metadata)
                trace_metadata["buffered"] = True  # Mark as recovered from buffer
                
                langfuse_trace = self._client.trace(
                    id=buffered.trace_id,
                    name=buffered.name,
                    session_id=buffered.session_id,
                    metadata=trace_metadata
                )
                
                # Apply output if set
                if buffered.output:
                    langfuse_trace.update(output=buffered.output)
                
                # Apply status if set
                if buffered.status:
                    update_data: Dict[str, Any] = {"status_message": buffered.status}
                    if buffered.error:
                        update_data["metadata"] = {
                            **trace_metadata,
                            "error": buffered.error
                        }
                    langfuse_trace.update(**update_data)
                
                # Apply scores
                for score in buffered.scores:
                    score_data: Dict[str, Any] = {
                        "name": score["name"],
                        "value": score["value"],
                    }
                    if score.get("comment"):
                        score_data["comment"] = score["comment"]
                    langfuse_trace.score(**score_data)
                
                # Apply categorical scores
                for cat_score in buffered.categorical_scores:
                    score_data = {
                        "name": cat_score["name"],
                        "value": cat_score["category"],
                    }
                    if cat_score.get("comment"):
                        score_data["comment"] = cat_score["comment"]
                    langfuse_trace.score(**score_data)
            
            # Recreate spans
            for buffered_span in self._buffered_spans:
                span_metadata = buffered_span.metadata.copy() if buffered_span.metadata else {}
                span_metadata.update(buffered_span.span_metadata)
                span_metadata["buffered"] = True
                
                langfuse_span = self._client.span(
                    id=buffered_span.span_id,
                    trace_id=buffered_span.trace_id,
                    name=buffered_span.name,
                    metadata=span_metadata
                )
                
                if buffered_span.input_data:
                    langfuse_span.update(input=buffered_span.input_data)
                
                if buffered_span.output_data:
                    langfuse_span.update(output=buffered_span.output_data)
                
                langfuse_span.update(status_message=buffered_span.status)
                langfuse_span.end()
            
            # Clear buffers and exit fallback mode
            self._buffered_traces.clear()
            self._buffered_spans.clear()
            self._fallback_mode = False
            self._logger.info("Successfully flushed buffered traces to Langfuse")
            return True
            
        except Exception as e:
            self._logger.warning(
                f"Failed to flush buffered traces to Langfuse: {e}"
            )
            return False
    
    def flush(self) -> None:
        """
        Flush pending traces to Langfuse.
        
        If there are buffered traces and we're not in fallback mode,
        attempts to flush them first. Then calls the parent flush method.
        """
        # Try to flush buffered traces if we have any
        if self._buffered_traces and not self._fallback_mode:
            self._flush_buffered_traces()
        elif self._buffered_traces and self._fallback_mode:
            # Try to recover from fallback mode
            self._flush_buffered_traces()
        
        # Call parent flush if we have a client
        if self._client:
            try:
                super().flush()
            except Exception as e:
                self._logger.warning(f"Failed to flush to Langfuse: {e}")
    
    @property
    def fallback_mode(self) -> bool:
        """
        Check if the manager is in fallback mode.
        
        Returns:
            bool: True if in fallback mode (buffering traces), False otherwise.
        """
        return self._fallback_mode
    
    @property
    def buffered_trace_count(self) -> int:
        """
        Get the number of buffered traces.
        
        Returns:
            int: Number of traces currently buffered.
        """
        return len(self._buffered_traces)
    
    @property
    def buffered_span_count(self) -> int:
        """
        Get the number of buffered spans.
        
        Returns:
            int: Number of spans currently buffered.
        """
        return len(self._buffered_spans)
    
    @classmethod
    def reset_instance(cls) -> None:
        """
        Reset the singleton instance.
        
        This method is primarily intended for testing purposes to allow
        creating fresh ResilientTracingManager instances between tests.
        
        Warning:
            Do not use this in production code as it can lead to
            inconsistent tracing state.
        """
        cls._instance = None
        # Also reset parent class instance to avoid conflicts
        TracingManager._instance = None


def get_resilient_tracing_manager(
    config: Optional[LangfuseConfig] = None
) -> ResilientTracingManager:
    """
    Get the ResilientTracingManager singleton instance.
    
    This factory function returns the ResilientTracingManager, which provides
    graceful degradation when Langfuse is unavailable.
    
    Args:
        config: Optional Langfuse configuration. If not provided,
               configuration will be loaded from environment variables.
    
    Returns:
        ResilientTracingManager: The resilient tracing manager instance.
    
    Example:
        >>> manager = get_resilient_tracing_manager()
        >>> trace = manager.create_trace("workflow", "session-123")
    """
    return ResilientTracingManager(config)
