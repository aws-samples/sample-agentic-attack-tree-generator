"""
No-Op Tracing Implementations

This module provides no-op (no operation) implementations of the tracing interfaces.
These implementations are used when Langfuse tracing is disabled, ensuring that
workflows can execute without tracing overhead and without conditional checks
throughout the codebase.

All methods in these classes are no-ops that return empty/default values,
allowing the same code paths to be used regardless of whether tracing is enabled.

Requirements:
- 9.1: Execute workflows without tracing overhead when Langfuse is not configured
- 9.2: Use no-op implementation when disabled to avoid conditional checks
"""

from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

from threatforest.tracing.interfaces import (
    IGeneration,
    ISpan,
    ITrace,
    ITracingManager,
)


class NoOpGeneration(IGeneration):
    """
    No-op implementation of IGeneration.
    
    This class provides a no-op implementation for LLM generation tracking.
    All methods do nothing and return default values, ensuring zero overhead
    when tracing is disabled.
    
    Example:
        >>> gen = NoOpGeneration()
        >>> gen.set_input({"prompt": "test"})  # Does nothing
        >>> gen.set_output({"response": "test"})  # Does nothing
        >>> gen.generation_id  # Returns "noop"
        'noop'
    """
    
    @property
    def generation_id(self) -> str:
        """
        Get the generation identifier.
        
        Returns:
            str: Always returns "noop" for no-op implementations.
        """
        return "noop"
    
    def set_input(self, input_data: Dict[str, Any]) -> None:
        """
        No-op: Set input data for this generation.
        
        Args:
            input_data: Input data (ignored).
        """
        pass
    
    def set_output(self, output_data: Dict[str, Any]) -> None:
        """
        No-op: Set output data for this generation.
        
        Args:
            output_data: Output data (ignored).
        """
        pass
    
    def set_usage(
        self,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None
    ) -> None:
        """
        No-op: Set token usage metrics.
        
        Args:
            input_tokens: Input token count (ignored).
            output_tokens: Output token count (ignored).
            total_tokens: Total token count (ignored).
        """
        pass
    
    def end(self, status: str = "success") -> None:
        """
        No-op: Mark generation as complete.
        
        Args:
            status: Completion status (ignored).
        """
        pass


class NoOpSpan(ISpan):
    """
    No-op implementation of ISpan.
    
    This class provides a no-op implementation for span tracking.
    All methods do nothing and return default values, ensuring zero overhead
    when tracing is disabled.
    
    Example:
        >>> span = NoOpSpan()
        >>> span.set_input({"project_path": "/test"})  # Does nothing
        >>> span.set_output({"files": []})  # Does nothing
        >>> span.span_id  # Returns "noop"
        'noop'
    """
    
    @property
    def span_id(self) -> str:
        """
        Get the span identifier.
        
        Returns:
            str: Always returns "noop" for no-op implementations.
        """
        return "noop"
    
    def set_input(self, input_data: Dict[str, Any]) -> None:
        """
        No-op: Set input data for this span.
        
        Args:
            input_data: Input data (ignored).
        """
        pass
    
    def set_output(self, output_data: Dict[str, Any]) -> None:
        """
        No-op: Set output data for this span.
        
        Args:
            output_data: Output data (ignored).
        """
        pass
    
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        No-op: Set span metadata.
        
        Args:
            metadata: Metadata dictionary (ignored).
        """
        pass
    
    def end(self, status: str = "success") -> None:
        """
        No-op: Mark span as complete.
        
        Args:
            status: Completion status (ignored).
        """
        pass
    
    @contextmanager
    def generation(self, name: str, model: str) -> Generator[IGeneration, None, None]:
        """
        Create a no-op generation context manager.
        
        This method returns a NoOpGeneration that does nothing,
        allowing LLM call instrumentation code to run without overhead.
        
        Args:
            name: Generation name (ignored).
            model: Model identifier (ignored).
        
        Yields:
            NoOpGeneration: A no-op generation object.
        """
        yield NoOpGeneration()


class NoOpTrace(ITrace):
    """
    No-op implementation of ITrace.
    
    This class provides a no-op implementation for trace tracking.
    All methods do nothing and return default values, ensuring zero overhead
    when tracing is disabled.
    
    The trace_id and session_id return fixed "noop" values to indicate
    that this is a no-op trace.
    
    Example:
        >>> trace = NoOpTrace()
        >>> trace.set_output({"threats": 5})  # Does nothing
        >>> trace.add_score("quality", 0.9)  # Does nothing
        >>> trace.trace_id  # Returns "noop"
        'noop'
    """
    
    @property
    def trace_id(self) -> str:
        """
        Get the trace identifier.
        
        Returns:
            str: Always returns "noop" for no-op implementations.
        """
        return "noop"
    
    @property
    def session_id(self) -> str:
        """
        Get the session identifier.
        
        Returns:
            str: Always returns "noop" for no-op implementations.
        """
        return "noop"
    
    def set_output(self, output: Dict[str, Any]) -> None:
        """
        No-op: Set trace output data.
        
        Args:
            output: Output data (ignored).
        """
        pass
    
    def set_status(self, status: str, error: Optional[str] = None) -> None:
        """
        No-op: Set trace completion status.
        
        Args:
            status: Completion status (ignored).
            error: Error message (ignored).
        """
        pass
    
    def add_score(
        self,
        name: str,
        value: float,
        comment: Optional[str] = None
    ) -> None:
        """
        No-op: Add a numeric score to this trace.
        
        Args:
            name: Score name (ignored).
            value: Score value (ignored).
            comment: Score comment (ignored).
        """
        pass
    
    def add_categorical_score(
        self,
        name: str,
        category: str,
        allowed_categories: List[str],
        comment: Optional[str] = None
    ) -> None:
        """
        No-op: Add a categorical score to this trace.
        
        Args:
            name: Score name (ignored).
            category: Category value (ignored).
            allowed_categories: Allowed categories (ignored).
            comment: Score comment (ignored).
        """
        pass
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        No-op: Add metadata to this trace.
        
        Args:
            key: Metadata key (ignored).
            value: Metadata value (ignored).
        """
        pass


class NoOpTracingManager(ITracingManager):
    """
    No-op implementation of ITracingManager.
    
    This class provides a no-op implementation of the tracing manager
    that returns NoOpTrace and NoOpSpan objects. It is used when Langfuse
    tracing is disabled, ensuring that workflows can execute without
    tracing overhead.
    
    The enabled property always returns False to indicate that tracing
    is not active.
    
    Example:
        >>> manager = NoOpTracingManager()
        >>> manager.enabled  # Returns False
        False
        >>> trace = manager.create_trace("workflow", "session-123")
        >>> isinstance(trace, NoOpTrace)
        True
        >>> span = manager.create_span("analysis", trace)
        >>> isinstance(span, NoOpSpan)
        True
    
    Requirements:
    - 9.1: Execute workflows without tracing overhead
    - 9.2: Use no-op implementation to avoid conditional checks
    """
    
    def create_trace(
        self,
        name: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ITrace:
        """
        Create a no-op trace.
        
        This method returns a NoOpTrace that does nothing, allowing
        workflow code to run without tracing overhead.
        
        Args:
            name: Trace name (ignored).
            session_id: Session identifier (ignored).
            metadata: Trace metadata (ignored).
        
        Returns:
            NoOpTrace: A no-op trace object.
        """
        return NoOpTrace()
    
    def create_span(
        self,
        name: str,
        trace: ITrace,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ISpan:
        """
        Create a no-op span.
        
        This method returns a NoOpSpan that does nothing, allowing
        workflow stage instrumentation code to run without overhead.
        
        Args:
            name: Span name (ignored).
            trace: Parent trace (ignored).
            metadata: Span metadata (ignored).
        
        Returns:
            NoOpSpan: A no-op span object.
        """
        return NoOpSpan()
    
    def flush(self) -> None:
        """
        No-op: Flush pending traces.
        
        This method does nothing since there are no traces to flush
        when tracing is disabled.
        """
        pass
    
    @property
    def enabled(self) -> bool:
        """
        Check if tracing is enabled.
        
        Returns:
            bool: Always returns False for no-op implementations.
        """
        return False
