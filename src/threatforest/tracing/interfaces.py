"""
Tracing Interfaces Module

This module defines the abstract base classes for the ThreatForest tracing infrastructure.
These interfaces enable dependency injection and allow for both Langfuse-backed implementations
and no-op fallbacks when tracing is disabled.

The interfaces follow the design pattern where:
- ITracingManager: Central coordinator for creating traces and spans
- ITrace: Represents a complete workflow run (parent trace)
- ISpan: Represents a single operation within a trace (child span)
- IGeneration: Represents an LLM generation within a span

Requirements:
- 2.1: Create parent trace with unique trace_id for workflow execution
- 3.1: Create child spans for workflow stages
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    pass


class IGeneration(ABC):
    """
    Interface for an LLM generation within a span.
    
    A generation represents a single LLM call, capturing model information,
    input/output, and token usage metrics.
    """
    
    @property
    @abstractmethod
    def generation_id(self) -> str:
        """
        Get the unique identifier for this generation.
        
        Returns:
            str: Unique generation identifier.
        """
        pass
    
    @abstractmethod
    def set_input(self, input_data: Dict[str, Any]) -> None:
        """
        Set the input data for this generation.
        
        Args:
            input_data: Dictionary containing the input prompt and parameters.
        """
        pass
    
    @abstractmethod
    def set_output(self, output_data: Dict[str, Any]) -> None:
        """
        Set the output data for this generation.
        
        Args:
            output_data: Dictionary containing the model response.
        """
        pass
    
    @abstractmethod
    def set_usage(
        self,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None
    ) -> None:
        """
        Set token usage metrics for this generation.
        
        Args:
            input_tokens: Number of tokens in the input prompt.
            output_tokens: Number of tokens in the model response.
            total_tokens: Total tokens used (input + output).
        """
        pass
    
    @abstractmethod
    def end(self, status: str = "success") -> None:
        """
        Mark the generation as complete.
        
        Args:
            status: Completion status ("success" or "error").
        """
        pass


class ISpan(ABC):
    """
    Interface for a span (single operation within a trace).
    
    A span represents a discrete unit of work within a workflow, such as
    context analysis, threat generation, or attack tree creation. Spans
    capture input/output data, metadata, and timing information.
    
    Spans can contain nested generations for LLM calls.
    
    Example:
        >>> with tracing_context.span("context_analysis") as span:
        ...     span.set_input({"project_path": "/path/to/project"})
        ...     result = analyze_context(project_path)
        ...     span.set_output({"context_files": result})
    """
    
    @property
    @abstractmethod
    def span_id(self) -> str:
        """
        Get the unique identifier for this span.
        
        Returns:
            str: Unique span identifier.
        """
        pass
    
    @abstractmethod
    def set_input(self, input_data: Dict[str, Any]) -> None:
        """
        Set the input data for this span.
        
        Args:
            input_data: Dictionary containing the span's input parameters.
        
        Example:
            >>> span.set_input({
            ...     "project_path": "/path/to/project",
            ...     "include_tests": True
            ... })
        """
        pass
    
    @abstractmethod
    def set_output(self, output_data: Dict[str, Any]) -> None:
        """
        Set the output data for this span.
        
        Args:
            output_data: Dictionary containing the span's output/results.
        
        Example:
            >>> span.set_output({
            ...     "context_files": {"src/main.py": "..."},
            ...     "file_count": 42
            ... })
        """
        pass
    
    @abstractmethod
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Set span metadata including tokens and latency.
        
        This method is used to capture operational metrics like latency,
        token counts, and other diagnostic information.
        
        Args:
            metadata: Dictionary containing metadata key-value pairs.
        
        Example:
            >>> span.set_metadata({
            ...     "latency_ms": 1234,
            ...     "input_tokens": 500,
            ...     "output_tokens": 200
            ... })
        """
        pass
    
    @abstractmethod
    def end(self, status: str = "success") -> None:
        """
        Mark the span as complete.
        
        This method should be called when the span's operation is finished.
        It records the completion status and finalizes timing information.
        
        Args:
            status: Completion status. Use "success" for successful completion
                   or "error" for failed operations.
        """
        pass
    
    @contextmanager
    @abstractmethod
    def generation(self, name: str, model: str) -> Generator["IGeneration", None, None]:
        """
        Create a nested generation for LLM calls.
        
        This context manager creates a generation span that captures details
        about a specific LLM invocation, including model information,
        input/output, and token usage.
        
        Args:
            name: Name of the generation (e.g., "threat_generation", "tree_synthesis").
            model: Model identifier (e.g., "anthropic.claude-3-sonnet").
        
        Yields:
            IGeneration: Generation object for capturing LLM call details.
        
        Example:
            >>> with span.generation("threat_generation", "anthropic.claude-3-sonnet") as gen:
            ...     gen.set_input({"prompt": "Generate threats for..."})
            ...     response = call_llm(prompt)
            ...     gen.set_output({"response": response})
            ...     gen.set_usage(input_tokens=500, output_tokens=200)
        """
        pass


class ITrace(ABC):
    """
    Interface for a trace (complete workflow run).
    
    A trace represents a complete ThreatForest workflow execution, from start
    to finish. It serves as the parent container for all spans created during
    the workflow and captures overall metadata, status, and scores.
    
    Traces are grouped by session_id to allow analysis of related workflow runs.
    
    Example:
        >>> with tracing_context.trace("threatforest_analysis", session_id) as trace:
        ...     trace.add_metadata("bedrock_model", "anthropic.claude-3-sonnet")
        ...     # ... workflow execution ...
        ...     trace.set_output({"threats_generated": 5, "trees_created": 5})
        ...     trace.add_score("overall_quality", 0.85, "Good coverage")
    """
    
    @property
    @abstractmethod
    def trace_id(self) -> str:
        """
        Get the unique identifier for this trace.
        
        Returns:
            str: Unique trace identifier (UUID format).
        """
        pass
    
    @property
    @abstractmethod
    def session_id(self) -> str:
        """
        Get the session identifier for this trace.
        
        The session_id groups related traces from the same analysis run,
        enabling queries across all traces in a session.
        
        Returns:
            str: Session identifier.
        """
        pass
    
    @abstractmethod
    def set_output(self, output: Dict[str, Any]) -> None:
        """
        Set the trace output data.
        
        This method captures the final output/results of the workflow execution.
        
        Args:
            output: Dictionary containing the workflow's output data.
        
        Example:
            >>> trace.set_output({
            ...     "threats_generated": 5,
            ...     "attack_trees_created": 5,
            ...     "techniques_mapped": 42
            ... })
        """
        pass
    
    @abstractmethod
    def set_status(self, status: str, error: Optional[str] = None) -> None:
        """
        Set trace completion status.
        
        This method records whether the workflow completed successfully or
        encountered an error. For failed workflows, the error message is captured.
        
        Args:
            status: Completion status ("success" or "error").
            error: Error message if status is "error". Optional.
        
        Example:
            >>> # Successful completion
            >>> trace.set_status("success")
            
            >>> # Failed completion
            >>> trace.set_status("error", "Connection timeout to Bedrock")
        """
        pass
    
    @abstractmethod
    def add_score(
        self,
        name: str,
        value: float,
        comment: Optional[str] = None
    ) -> None:
        """
        Add a numeric score to this trace.
        
        Scores are numeric evaluations (0.0-1.0) that can be added by SMEs
        or automated evaluation pipelines. Each score has a name, value,
        and optional comment.
        
        Args:
            name: Score dimension name (e.g., "overall_quality", "completeness").
            value: Score value in range [0.0, 1.0].
            comment: Optional comment explaining the score.
        
        Raises:
            ValueError: If value is outside the range [0.0, 1.0].
        
        Example:
            >>> trace.add_score("overall_quality", 0.85, "Good threat coverage")
            >>> trace.add_score("technical_accuracy", 0.92)
        """
        pass
    
    @abstractmethod
    def add_categorical_score(
        self,
        name: str,
        category: str,
        allowed_categories: List[str],
        comment: Optional[str] = None
    ) -> None:
        """
        Add a categorical score to this trace.
        
        Categorical scores are discrete evaluations from a predefined set of
        categories. This is used for TTP mapping quality scores and other
        categorical evaluations.
        
        Args:
            name: Score dimension name (e.g., "mapping_quality").
            category: The categorical value (e.g., "excellent", "good", "poor").
            allowed_categories: List of valid category values.
            comment: Optional comment explaining the score.
        
        Raises:
            ValueError: If category is not in allowed_categories.
        
        Example:
            >>> trace.add_categorical_score(
            ...     "mapping_quality",
            ...     "excellent",
            ...     ["excellent", "good", "poor", "no_mapping"],
            ...     "Perfect technique match"
            ... )
        """
        pass
    
    @abstractmethod
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to this trace.
        
        Metadata captures contextual information about the workflow execution,
        such as model configuration, project details, and evaluation mode.
        
        Args:
            key: Metadata key name.
            value: Metadata value (any JSON-serializable type).
        
        Example:
            >>> trace.add_metadata("bedrock_model", "anthropic.claude-3-sonnet")
            >>> trace.add_metadata("project_path", "/path/to/project")
            >>> trace.add_metadata("evaluation_mode", "generate_new")
        """
        pass


class ITracingManager(ABC):
    """
    Interface for tracing operations.
    
    The TracingManager is the central coordinator for all tracing operations.
    It provides factory methods for creating traces and spans, and manages
    the connection to the tracing backend (Langfuse).
    
    When tracing is disabled, a NoOpTracingManager implementation is used
    that returns no-op trace and span objects, ensuring zero overhead.
    
    Example:
        >>> manager = TracingManager(config)
        >>> if manager.enabled:
        ...     trace = manager.create_trace("workflow", session_id, metadata)
        ...     span = manager.create_span("context_analysis", trace)
        ...     # ... do work ...
        ...     manager.flush()
    """
    
    @abstractmethod
    def create_trace(
        self,
        name: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ) -> ITrace:
        """
        Create a new parent trace for a workflow run.
        
        This method creates a new trace that serves as the parent container
        for all spans in a workflow execution. The trace is associated with
        a session_id for grouping related traces.
        
        Args:
            name: Name of the trace (e.g., "threatforest_analysis").
            session_id: Session identifier for grouping related traces.
            metadata: Optional metadata to attach to the trace.
            tags: Optional list of tags for filtering (e.g., ["trace_type:attack_tree"]).
        
        Returns:
            ITrace: New trace object.
        
        Example:
            >>> trace = manager.create_trace(
            ...     name="threatforest_analysis",
            ...     session_id="session-123",
            ...     metadata={"bedrock_model": "anthropic.claude-3-sonnet"},
            ...     tags=["trace_type:attack_tree"]
            ... )
        """
        pass
    
    @abstractmethod
    def create_span(
        self,
        name: str,
        trace: ITrace,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ISpan:
        """
        Create a child span within a trace.
        
        This method creates a new span that represents a single operation
        within the parent trace. Spans capture input/output data and
        timing information for individual workflow stages.
        
        Args:
            name: Name of the span (e.g., "context_analysis", "threat_generation").
            trace: Parent trace that this span belongs to.
            metadata: Optional metadata to attach to the span.
        
        Returns:
            ISpan: New span object.
        
        Example:
            >>> span = manager.create_span(
            ...     name="context_analysis",
            ...     trace=trace,
            ...     metadata={"stage": "analysis"}
            ... )
        """
        pass
    
    @abstractmethod
    def flush(self) -> None:
        """
        Flush pending traces to Langfuse.
        
        This method ensures all buffered trace data is sent to the Langfuse
        backend. It should be called at the end of a workflow to ensure
        all data is persisted.
        
        Note:
            This method is a no-op when tracing is disabled.
        """
        pass
    
    @property
    @abstractmethod
    def enabled(self) -> bool:
        """
        Check if tracing is enabled.
        
        Returns:
            bool: True if tracing is enabled and the Langfuse client is
                  initialized, False otherwise.
        """
        pass
