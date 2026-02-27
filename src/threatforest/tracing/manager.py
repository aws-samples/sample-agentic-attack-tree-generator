"""
Tracing Manager Module

This module provides the TracingManager class, which is the central coordinator
for all Langfuse tracing operations. It implements the singleton pattern to ensure
a single tracing instance throughout the application lifecycle.

When Langfuse is enabled, the manager creates real traces and spans via the Langfuse
client. When disabled, it returns NoOp implementations for transparent fallback.

Requirements:
- 2.1: Create parent trace with unique trace_id for workflow execution
- 2.2: Attach session_id to group related traces from the same analysis run
- 2.3: Capture workflow metadata including bedrock_model, project_path, and timestamp
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING
import logging
import uuid

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.interfaces import ISpan, ITrace, ITracingManager
from threatforest.tracing.noop import NoOpSpan, NoOpTrace, NoOpTracingManager

if TYPE_CHECKING:
    from langfuse import Langfuse
    from threatforest.tracing.score_configs import ScoreConfigRegistry

logger = logging.getLogger(__name__)


class LangfuseTrace(ITrace):
    """
    Langfuse-backed implementation of ITrace.
    
    This class wraps a Langfuse trace object and provides the ITrace interface.
    It generates a unique trace_id and captures session_id for grouping related traces.
    
    Requirements:
    - 2.1: Create parent trace with unique trace_id
    - 2.2: Attach session_id to group related traces
    - 2.3: Capture workflow metadata
    """
    
    def __init__(
        self,
        langfuse_trace: Any,
        trace_id: str,
        session_id: str,
        score_config_registry: Optional["ScoreConfigRegistry"] = None
    ):
        """
        Initialize a LangfuseTrace wrapper.
        
        Args:
            langfuse_trace: The underlying Langfuse trace object.
            trace_id: Unique identifier for this trace.
            session_id: Session identifier for grouping related traces.
            score_config_registry: Optional registry for score config validation.
        """
        self._langfuse_trace = langfuse_trace
        self._trace_id = trace_id
        self._session_id = session_id
        self._metadata: Dict[str, Any] = {}
        self._score_config_registry = score_config_registry
    
    @property
    def trace_id(self) -> str:
        """
        Get the unique identifier for this trace.
        
        Returns:
            str: Unique trace identifier (UUID format).
        """
        return self._trace_id
    
    @property
    def session_id(self) -> str:
        """
        Get the session identifier for this trace.
        
        Returns:
            str: Session identifier for grouping related traces.
        """
        return self._session_id
    
    def set_output(self, output: Dict[str, Any]) -> None:
        """
        Set the trace output data.
        
        Args:
            output: Dictionary containing the workflow's output data.
        """
        if self._langfuse_trace:
            self._langfuse_trace.update(output=output)
    
    def set_status(self, status: str, error: Optional[str] = None) -> None:
        """
        Set trace completion status.
        
        Args:
            status: Completion status ("success" or "error").
            error: Error message if status is "error".
        """
        if self._langfuse_trace:
            update_data: Dict[str, Any] = {"status_message": status}
            if error:
                update_data["metadata"] = {**self._metadata, "error": error}
            self._langfuse_trace.update(**update_data)
    
    def add_score(
        self,
        name: str,
        value: float,
        comment: Optional[str] = None,
        config_id: Optional[str] = None
    ) -> None:
        """
        Add a numeric score to this trace.
        
        Args:
            name: Score dimension name.
            value: Score value in range [0.0, 1.0].
            comment: Optional comment explaining the score.
            config_id: Optional Langfuse score config ID for server-side validation.
                      If not provided and a score_config_registry is available,
                      the config_id will be looked up automatically.
        
        Raises:
            ValueError: If value is outside the range [0.0, 1.0].
        """
        if value < 0.0 or value > 1.0:
            raise ValueError(
                f"Score value must be in range [0.0, 1.0], got {value}"
            )
        
        if self._langfuse_trace:
            score_data: Dict[str, Any] = {
                "name": name,
                "value": value,
            }
            if comment:
                score_data["comment"] = comment
            
            # Try to get config_id from registry if not provided
            if config_id is None and self._score_config_registry:
                config_id = self._score_config_registry.get_config_id(name)
            
            if config_id:
                score_data["config_id"] = config_id
            
            self._langfuse_trace.score(**score_data)
    
    def add_categorical_score(
        self,
        name: str,
        category: str,
        allowed_categories: List[str],
        comment: Optional[str] = None,
        config_id: Optional[str] = None
    ) -> None:
        """
        Add a categorical score to this trace.
        
        Categorical scores are validated against a list of allowed categories
        and then stored with the category as a string value.
        
        Args:
            name: Score dimension name.
            category: The categorical value.
            allowed_categories: List of valid category values.
            comment: Optional comment explaining the score.
            config_id: Optional Langfuse score config ID for server-side validation.
                      If not provided and a score_config_registry is available,
                      the config_id will be looked up automatically.
        
        Raises:
            ValueError: If category is not in allowed_categories.
        """
        if category not in allowed_categories:
            raise ValueError(
                f"Category '{category}' is not in allowed categories: {allowed_categories}"
            )
        
        if self._langfuse_trace:
            score_data: Dict[str, Any] = {
                "name": name,
                "value": category,  # Langfuse supports string values for categorical scores
            }
            if comment:
                score_data["comment"] = comment
            
            # Try to get config_id from registry if not provided
            if config_id is None and self._score_config_registry:
                config_id = self._score_config_registry.get_config_id(name)
            
            if config_id:
                score_data["config_id"] = config_id
            
            self._langfuse_trace.score(**score_data)
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to this trace.
        
        Args:
            key: Metadata key name.
            value: Metadata value.
        """
        self._metadata[key] = value
        if self._langfuse_trace:
            self._langfuse_trace.update(metadata=self._metadata)


class LangfuseSpan(ISpan):
    """
    Langfuse-backed implementation of ISpan.
    
    This class wraps a Langfuse span object and provides the ISpan interface.
    It captures input/output data and metadata for individual workflow stages.
    
    Requirements:
    - 3.1: Create child spans for workflow stages
    - 3.6: Capture latency_ms, input_tokens, and output_tokens
    """
    
    def __init__(self, langfuse_span: Any, span_id: str):
        """
        Initialize a LangfuseSpan wrapper.
        
        Args:
            langfuse_span: The underlying Langfuse span object.
            span_id: Unique identifier for this span.
        """
        self._langfuse_span = langfuse_span
        self._span_id = span_id
        self._metadata: Dict[str, Any] = {}
    
    @property
    def span_id(self) -> str:
        """
        Get the unique identifier for this span.
        
        Returns:
            str: Unique span identifier.
        """
        return self._span_id
    
    def set_input(self, input_data: Dict[str, Any]) -> None:
        """
        Set the input data for this span.
        
        Args:
            input_data: Dictionary containing the span's input parameters.
        """
        if self._langfuse_span:
            self._langfuse_span.update(input=input_data)
    
    def set_output(self, output_data: Dict[str, Any]) -> None:
        """
        Set the output data for this span.
        
        Args:
            output_data: Dictionary containing the span's output/results.
        """
        if self._langfuse_span:
            self._langfuse_span.update(output=output_data)
    
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Set span metadata including tokens and latency.
        
        Args:
            metadata: Dictionary containing metadata key-value pairs.
        """
        self._metadata.update(metadata)
        if self._langfuse_span:
            self._langfuse_span.update(metadata=self._metadata)
    
    def end(self, status: str = "success") -> None:
        """
        Mark the span as complete.
        
        Args:
            status: Completion status ("success" or "error").
        """
        if self._langfuse_span:
            self._langfuse_span.update(status_message=status)
            self._langfuse_span.end()
    
    def generation(self, name: str, model: str):
        """
        Create a nested generation for LLM calls.
        
        Note: This is a placeholder that will be fully implemented in task 3.3.
        For now, it returns a NoOp generation context manager.
        
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
            # TODO: Implement full Langfuse generation in task 3.3
            yield NoOpGeneration()
        
        return _generation_context()


class TracingManager(ITracingManager):
    """
    Langfuse-backed tracing manager implementing the singleton pattern.
    
    This class is the central coordinator for all tracing operations. It manages
    the Langfuse client connection and provides factory methods for creating
    traces and spans.
    
    When Langfuse is disabled (via configuration), the manager returns NoOp
    implementations to ensure transparent fallback without conditional checks
    throughout the codebase.
    
    The singleton pattern ensures a single tracing instance throughout the
    application lifecycle, preventing multiple Langfuse client connections.
    
    Requirements:
    - 2.1: Create parent trace with unique trace_id
    - 2.2: Attach session_id to group related traces
    - 2.3: Capture workflow metadata including bedrock_model, project_path, timestamp
    
    Example:
        >>> config = LangfuseConfig.from_env()
        >>> manager = TracingManager(config)
        >>> if manager.enabled:
        ...     trace = manager.create_trace("workflow", "session-123")
        ...     span = manager.create_span("analysis", trace)
        ...     manager.flush()
    """
    
    _instance: Optional["TracingManager"] = None
    
    def __new__(cls, config: Optional[LangfuseConfig] = None) -> "TracingManager":
        """
        Create or return the singleton TracingManager instance.
        
        Args:
            config: Optional Langfuse configuration. If not provided,
                   configuration will be loaded from environment variables.
        
        Returns:
            TracingManager: The singleton instance.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config: Optional[LangfuseConfig] = None):
        """
        Initialize the TracingManager with Langfuse configuration.
        
        This method is idempotent due to the singleton pattern - subsequent
        calls after initialization will be no-ops.
        
        Args:
            config: Optional Langfuse configuration. If not provided,
                   configuration will be loaded from environment variables.
        """
        if self._initialized:
            return
        
        self._config = config or LangfuseConfig.from_env()
        self._client: Optional["Langfuse"] = None
        self._score_config_registry: Optional["ScoreConfigRegistry"] = None
        
        if self._config.enabled:
            self._config.validate()
            self._client = self._init_client()
            self._init_score_config_registry()
        
        self._initialized = True
        logger.info(
            f"TracingManager initialized (enabled={self._config.enabled})"
        )
    
    def _init_client(self) -> "Langfuse":
        """
        Initialize the Langfuse client.
        
        Returns:
            Langfuse: Initialized Langfuse client.
        
        Raises:
            ImportError: If langfuse package is not installed.
        """
        try:
            from langfuse import Langfuse
        except ImportError:
            raise ImportError(
                "Langfuse is enabled but the 'langfuse' package is not installed. "
                "Install it with: pip install threatforest[tracing]"
            )
        
        return Langfuse(
            public_key=self._config.public_key,
            secret_key=self._config.secret_key,
            host=self._config.host
        )
    
    def _init_score_config_registry(self) -> None:
        """
        Initialize the score config registry and register all score definitions.
        
        This method creates a ScoreConfigRegistry and registers all ThreatForest
        score definitions with Langfuse for server-side validation.
        """
        if not self._client:
            return
        
        try:
            from threatforest.tracing.score_configs import ScoreConfigRegistry
            
            self._score_config_registry = ScoreConfigRegistry(self._config)
            
            # Register all score definitions on startup
            registered = self._score_config_registry.register_all_score_definitions()
            
            if registered:
                logger.info(
                    f"Registered {len(registered)} score configs with Langfuse"
                )
        except Exception as e:
            logger.warning(f"Failed to initialize score config registry: {e}")
            self._score_config_registry = None
    
    @property
    def score_config_registry(self) -> Optional["ScoreConfigRegistry"]:
        """
        Get the score config registry.
        
        Returns:
            ScoreConfigRegistry if initialized, None otherwise.
        """
        return self._score_config_registry
    
    def create_trace(
        self,
        name: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ) -> ITrace:
        """
        Create a new parent trace for a workflow run.
        
        When Langfuse is enabled, this creates a real Langfuse trace with
        the provided session_id and metadata. When disabled, returns a NoOpTrace.
        
        The trace automatically includes a timestamp in the metadata.
        
        Args:
            name: Name of the trace (e.g., "threatforest_analysis").
            session_id: Session identifier for grouping related traces.
            metadata: Optional metadata to attach to the trace.
            tags: Optional list of tags for filtering (e.g., ["trace_type:attack_tree"]).
        
        Returns:
            ITrace: New trace object (LangfuseTrace or NoOpTrace).
        
        Requirements:
        - 2.1: Create parent trace with unique trace_id
        - 2.2: Attach session_id to group related traces
        - 2.3: Capture workflow metadata including timestamp
        """
        if not self._client:
            return NoOpTrace()
        
        trace_id = str(uuid.uuid4())
        
        # Build metadata with timestamp (Requirement 2.3)
        trace_metadata = metadata.copy() if metadata else {}
        trace_metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        trace_kwargs: Dict[str, Any] = {
            "id": trace_id,
            "name": name,
            "session_id": session_id,
            "metadata": trace_metadata,
        }
        if tags:
            trace_kwargs["tags"] = tags
        
        langfuse_trace = self._client.trace(**trace_kwargs)
        
        return LangfuseTrace(
            langfuse_trace=langfuse_trace,
            trace_id=trace_id,
            session_id=session_id,
            score_config_registry=self._score_config_registry
        )
    
    def create_span(
        self,
        name: str,
        trace: ITrace,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ISpan:
        """
        Create a child span within a trace.
        
        When Langfuse is enabled and the trace is a LangfuseTrace, this creates
        a real Langfuse span. Otherwise, returns a NoOpSpan.
        
        Args:
            name: Name of the span (e.g., "context_analysis").
            trace: Parent trace that this span belongs to.
            metadata: Optional metadata to attach to the span.
        
        Returns:
            ISpan: New span object (LangfuseSpan or NoOpSpan).
        """
        if not self._client:
            return NoOpSpan()
        
        if not isinstance(trace, LangfuseTrace):
            return NoOpSpan()
        
        span_id = str(uuid.uuid4())
        
        langfuse_span = self._client.span(
            id=span_id,
            trace_id=trace.trace_id,
            name=name,
            metadata=metadata
        )
        
        return LangfuseSpan(
            langfuse_span=langfuse_span,
            span_id=span_id
        )
    
    def flush(self) -> None:
        """
        Flush pending traces to Langfuse.
        
        This method ensures all buffered trace data is sent to the Langfuse
        backend. It should be called at the end of a workflow to ensure
        all data is persisted.
        
        This is a no-op when tracing is disabled.
        """
        if self._client:
            self._client.flush()
    
    @property
    def enabled(self) -> bool:
        """
        Check if tracing is enabled.
        
        Returns:
            bool: True if tracing is enabled and the Langfuse client is
                  initialized, False otherwise.
        """
        return self._client is not None
    
    @classmethod
    def reset_instance(cls) -> None:
        """
        Reset the singleton instance.
        
        This method is primarily intended for testing purposes to allow
        creating fresh TracingManager instances between tests.
        
        Warning:
            Do not use this in production code as it can lead to
            inconsistent tracing state.
        """
        cls._instance = None


def get_tracing_manager(config: Optional[LangfuseConfig] = None) -> ITracingManager:
    """
    Get the appropriate tracing manager based on configuration.
    
    This factory function returns either a TracingManager (when Langfuse is enabled)
    or a NoOpTracingManager (when disabled), providing a clean interface for
    obtaining the tracing manager.
    
    Args:
        config: Optional Langfuse configuration. If not provided,
               configuration will be loaded from environment variables.
    
    Returns:
        ITracingManager: TracingManager if enabled, NoOpTracingManager if disabled.
    
    Example:
        >>> manager = get_tracing_manager()
        >>> trace = manager.create_trace("workflow", "session-123")
    """
    config = config or LangfuseConfig.from_env()
    
    if not config.enabled:
        return NoOpTracingManager()
    
    return TracingManager(config)
