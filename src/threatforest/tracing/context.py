"""
Tracing Context Module

This module provides the TracingContext class, which offers context managers for
workflow tracing. It simplifies the creation and management of traces and spans
by handling session_id generation, status setting, and latency capture automatically.

The TracingContext wraps an ITracingManager and provides a clean, Pythonic interface
for instrumenting workflow code using context managers.

Requirements:
- 8.1: Generate unique session_id at workflow start
- 8.2: Propagate session_id to all child spans
"""

from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional
import time
import uuid

from threatforest.tracing.interfaces import ISpan, ITrace, ITracingManager
from threatforest.tracing.noop import NoOpSpan


class TracingContext:
    """
    Context manager for workflow tracing.
    
    TracingContext provides a high-level interface for instrumenting ThreatForest
    workflows with tracing. It manages the lifecycle of traces and spans, including:
    
    - Automatic session_id generation if not provided
    - Automatic status setting based on success/exception
    - Automatic latency capture for spans
    - Propagation of session_id to all child spans
    
    The context managers handle all the boilerplate of creating traces/spans,
    setting status on completion or error, and flushing data to Langfuse.
    
    Requirements:
    - 8.1: Generate unique session_id at workflow start
    - 8.2: Propagate session_id to all child spans
    
    Example:
        >>> manager = get_tracing_manager()
        >>> ctx = TracingContext(manager)
        >>> 
        >>> with ctx.trace("threatforest_analysis") as trace:
        ...     trace.add_metadata("bedrock_model", "anthropic.claude-3-sonnet")
        ...     
        ...     with ctx.span("context_analysis") as span:
        ...         span.set_input({"project_path": "/path/to/project"})
        ...         result = analyze_context(project_path)
        ...         span.set_output({"context_files": result})
        ...     
        ...     with ctx.span("threat_generation") as span:
        ...         span.set_input({"context": result})
        ...         threats = generate_threats(result)
        ...         span.set_output({"threats": threats})
    """
    
    def __init__(self, manager: ITracingManager):
        """
        Initialize a TracingContext with a tracing manager.
        
        Args:
            manager: The tracing manager to use for creating traces and spans.
                    Can be a TracingManager (when Langfuse is enabled) or
                    NoOpTracingManager (when disabled).
        """
        self._manager = manager
        self._current_trace: Optional[ITrace] = None
        self._current_session_id: Optional[str] = None
    
    @property
    def current_trace(self) -> Optional[ITrace]:
        """
        Get the currently active trace, if any.
        
        Returns:
            Optional[ITrace]: The current trace, or None if not within a trace context.
        """
        return self._current_trace
    
    @property
    def current_session_id(self) -> Optional[str]:
        """
        Get the current session_id, if any.
        
        Returns:
            Optional[str]: The current session_id, or None if not within a trace context.
        """
        return self._current_session_id
    
    @contextmanager
    def trace(
        self,
        name: str,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ) -> Generator[ITrace, None, None]:
        """
        Context manager for a complete trace.
        
        Creates a parent trace for a workflow run and handles automatic status
        setting based on whether the context exits normally or with an exception.
        
        If session_id is not provided, a new UUID is generated automatically.
        The session_id is stored and propagated to all child spans created
        within this trace context.
        
        On successful completion, the trace status is set to "success".
        On exception, the trace status is set to "error" with the error message,
        and the exception is re-raised.
        
        The trace is always flushed to Langfuse when the context exits.
        
        Args:
            name: Name of the trace (e.g., "threatforest_analysis").
            session_id: Optional session identifier. If not provided, a new
                       UUID will be generated.
            metadata: Optional metadata to attach to the trace.
            tags: Optional list of tags for filtering in Langfuse.
        
        Yields:
            ITrace: The created trace object.
        
        Raises:
            Exception: Re-raises any exception that occurs within the context.
        
        Requirements:
        - 8.1: Generate unique session_id at workflow start if not provided
        - 8.2: Store session_id for propagation to child spans
        
        Example:
            >>> with ctx.trace("threatforest_analysis", metadata={"model": "claude"}) as trace:
            ...     trace.add_metadata("project_path", "/path/to/project")
            ...     # ... workflow execution ...
            ...     trace.set_output({"threats_generated": 5})
        """
        # Generate session_id if not provided (Requirement 8.1)
        session_id = session_id or str(uuid.uuid4())
        
        # Store session_id for propagation to child spans (Requirement 8.2)
        self._current_session_id = session_id
        
        # Create the trace
        trace = self._manager.create_trace(name, session_id, metadata, tags)
        self._current_trace = trace
        
        try:
            yield trace
            # Set success status on normal completion
            trace.set_status("success")
        except Exception as e:
            # Set error status with error message on exception
            trace.set_status("error", str(e))
            raise
        finally:
            # Always flush and clean up
            self._manager.flush()
            self._current_trace = None
            self._current_session_id = None

    @contextmanager
    def session_trace(
        self,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ) -> Generator[ITrace, None, None]:
        """
        Context manager for a trace within the current session.
        
        Creates a new trace that shares the session_id of the current session,
        allowing multiple traces to be grouped together in Langfuse while each
        being independently queueable for annotation.
        
        Unlike trace(), this does NOT reset the session_id on exit, so multiple
        session_trace() calls can share the same session.
        
        Args:
            name: Name of the trace (e.g., "threat_statement_generation").
            metadata: Optional metadata to attach to the trace.
            tags: Optional list of tags for filtering (e.g., ["trace_type:attack_tree"]).
        
        Yields:
            ITrace: The created trace object.
        
        Raises:
            ValueError: If called outside of a session (no current session_id).
            Exception: Re-raises any exception that occurs within the context.
        
        Example:
            >>> ctx.start_session()
            >>> with ctx.session_trace("threat_generation", tags=["trace_type:threat_statement"]) as trace:
            ...     trace.set_output({"threats": [...]})
            >>> with ctx.session_trace("attack_tree", tags=["trace_type:attack_tree"]) as trace:
            ...     trace.set_output({"trees": [...]})
            >>> ctx.end_session()
        """
        if not self._current_session_id:
            raise ValueError("session_trace() requires an active session. Call start_session() first.")
        
        trace = self._manager.create_trace(
            name, self._current_session_id, metadata, tags
        )
        previous_trace = self._current_trace
        self._current_trace = trace
        
        try:
            yield trace
            trace.set_status("success")
        except Exception as e:
            trace.set_status("error", str(e))
            raise
        finally:
            self._manager.flush()
            self._current_trace = previous_trace

    def start_session(self, session_id: Optional[str] = None) -> str:
        """
        Start a tracing session. All subsequent session_trace() calls will
        share this session_id.
        
        Args:
            session_id: Optional session identifier. Generated if not provided.
        
        Returns:
            str: The session_id for this session.
        """
        self._current_session_id = session_id or str(uuid.uuid4())
        return self._current_session_id

    def end_session(self) -> None:
        """End the current tracing session."""
        self._manager.flush()
        self._current_trace = None
        self._current_session_id = None
    
    @contextmanager
    def span(
        self,
        name: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Generator[ISpan, None, None]:
        """
        Context manager for a span within the current trace.
        
        Creates a child span within the current trace and handles automatic
        latency capture and status setting. If there is no current trace,
        returns a NoOpSpan to allow code to run without errors.
        
        The span automatically captures:
        - Start time when entering the context
        - End time and latency_ms when exiting the context
        - Status based on success/exception
        - Error message in metadata if an exception occurs
        
        The session_id from the parent trace is automatically propagated
        to the span via the trace relationship.
        
        Args:
            name: Name of the span (e.g., "context_analysis", "threat_generation").
            metadata: Optional metadata to attach to the span.
        
        Yields:
            ISpan: The created span object, or NoOpSpan if no trace is active.
        
        Raises:
            Exception: Re-raises any exception that occurs within the context.
        
        Requirements:
        - 8.2: Propagate session_id to all child spans (via trace relationship)
        
        Example:
            >>> with ctx.trace("workflow") as trace:
            ...     with ctx.span("context_analysis") as span:
            ...         span.set_input({"project_path": "/path"})
            ...         result = analyze_context()
            ...         span.set_output({"files": result})
            ...     # span.metadata now includes latency_ms
        """
        # If no current trace, return a NoOpSpan
        if not self._current_trace:
            yield NoOpSpan()
            return
        
        # Create the span within the current trace
        # Session_id is propagated via the trace relationship (Requirement 8.2)
        span = self._manager.create_span(name, self._current_trace, metadata)
        
        # Record start time for latency calculation
        start_time = time.time()
        
        try:
            yield span
            # Set success status on normal completion
            span.end("success")
        except Exception as e:
            # Capture error in metadata and set error status
            span.set_metadata({"error": str(e)})
            span.end("error")
            raise
        finally:
            # Calculate and record latency
            latency_ms = int((time.time() - start_time) * 1000)
            span.set_metadata({"latency_ms": latency_ms})
