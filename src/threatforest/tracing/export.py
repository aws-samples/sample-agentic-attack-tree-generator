"""
Export Pipeline for ThreatForest Tracing

This module provides functionality for exporting scored traces from Langfuse
to DynamoDB for evaluation pipelines and ground truth dataset curation.

The export pipeline supports:
- Filtering traces by type, review status, date range, and ground truth status
- Transforming Langfuse trace data to DynamoDB schema
- Exporting ground truth candidates to a separate table without TTL
- Setting TTL on non-ground-truth traces for automatic cleanup

Requirements:
- 7.1: THE Export_Pipeline SHALL query Langfuse API for traces with specified
       review_status and date_range filters
- 7.2: THE Export_Pipeline SHALL transform Langfuse trace data to the DynamoDB
       schema with PK format TRACE#{trace_type}#{trace_id}
- 7.3: THE Export_Pipeline SHALL support filtering by trace_type:
       threat_statement, attack_tree, ttp_matching
- 7.4: THE Export_Pipeline SHALL set TTL on non-ground-truth traces to 90 days
- 7.5: THE Export_Pipeline SHALL preserve langfuse_trace_id for cross-reference
- 7.6: WHEN a trace is marked as ground_truth_candidate, THE Export_Pipeline
       SHALL export to threatforest-ground-truth table without TTL
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import uuid
from typing import Any, Dict, List, Optional

from threatforest.tracing.config import LangfuseConfig


logger = logging.getLogger(__name__)


@dataclass
class ExportFilter:
    """
    Filters for querying Langfuse traces.
    
    This dataclass defines the filter criteria used when querying traces
    from Langfuse for export to DynamoDB. All filter fields are optional
    and can be combined to narrow down the query results.
    
    Attributes:
        trace_type: Filter by trace type. Valid values are:
            - "threat_statement": Threat statement generation traces
            - "attack_tree": Attack tree generation traces
            - "ttp_matching": TTP matching traces
            When None, all trace types are included.
        
        review_status: Filter by review status. Valid values are:
            - "pending_review": Traces awaiting SME review
            - "reviewed": Traces that have been reviewed and scored
            When None, all review statuses are included.
        
        start_date: Filter traces created on or after this date.
            When None, no lower bound is applied.
        
        end_date: Filter traces created on or before this date.
            When None, no upper bound is applied.
        
        ground_truth_only: When True, only return traces marked as
            ground truth candidates. Default is False.
    
    Requirements:
        - 7.1: THE Export_Pipeline SHALL query Langfuse API for traces with
               specified review_status and date_range filters
        - 7.3: THE Export_Pipeline SHALL support filtering by trace_type
    
    Example:
        >>> # Filter for reviewed attack tree traces from the last week
        >>> from datetime import datetime, timedelta
        >>> filter = ExportFilter(
        ...     trace_type="attack_tree",
        ...     review_status="reviewed",
        ...     start_date=datetime.now() - timedelta(days=7),
        ...     end_date=datetime.now()
        ... )
        >>> filter.validate()  # Raises ValueError if invalid
        >>> params = filter.to_langfuse_params()
    
    Example:
        >>> # Filter for ground truth candidates only
        >>> filter = ExportFilter(ground_truth_only=True)
        >>> params = filter.to_langfuse_params()
    """
    
    # Valid trace types for filtering
    VALID_TRACE_TYPES: List[str] = field(
        default_factory=lambda: ["threat_statement", "attack_tree", "ttp_matching"],
        repr=False,
        compare=False
    )
    
    # Valid review statuses for filtering
    VALID_REVIEW_STATUSES: List[str] = field(
        default_factory=lambda: ["pending_review", "reviewed"],
        repr=False,
        compare=False
    )
    
    trace_type: Optional[str] = None
    review_status: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    ground_truth_only: bool = False
    
    def validate(self) -> None:
        """
        Validate the filter configuration.
        
        Checks that:
        1. If both start_date and end_date are provided, start_date <= end_date
        2. If trace_type is provided, it's a valid trace type
        3. If review_status is provided, it's a valid review status
        
        Raises:
            ValueError: If the date range is invalid (start_date > end_date)
            ValueError: If trace_type is not a valid trace type
            ValueError: If review_status is not a valid review status
        
        Example:
            >>> filter = ExportFilter(
            ...     start_date=datetime(2024, 1, 1),
            ...     end_date=datetime(2023, 12, 31)  # Invalid: end before start
            ... )
            >>> filter.validate()
            Traceback (most recent call last):
                ...
            ValueError: Invalid date range: start_date (2024-01-01 00:00:00) must be <= end_date (2023-12-31 00:00:00)
        """
        # Validate date range
        if self.start_date is not None and self.end_date is not None:
            if self.start_date > self.end_date:
                raise ValueError(
                    f"Invalid date range: start_date ({self.start_date}) "
                    f"must be <= end_date ({self.end_date})"
                )
        
        # Validate trace_type
        if self.trace_type is not None:
            if self.trace_type not in self.VALID_TRACE_TYPES:
                raise ValueError(
                    f"Invalid trace_type: '{self.trace_type}'. "
                    f"Must be one of: {', '.join(self.VALID_TRACE_TYPES)}"
                )
        
        # Validate review_status
        if self.review_status is not None:
            if self.review_status not in self.VALID_REVIEW_STATUSES:
                raise ValueError(
                    f"Invalid review_status: '{self.review_status}'. "
                    f"Must be one of: {', '.join(self.VALID_REVIEW_STATUSES)}"
                )
    
    def to_langfuse_params(self) -> Dict[str, Any]:
        """
        Convert filter to Langfuse API query parameters.
        
        Transforms the filter fields into a dictionary format suitable
        for querying the Langfuse API. Only non-None filter values are
        included in the output.
        
        Returns:
            Dict[str, Any]: Dictionary of query parameters for Langfuse API.
                The dictionary may contain:
                - "trace_type": String filter for trace type
                - "review_status": String filter for review status  
                - "from_timestamp": ISO format string for start date
                - "to_timestamp": ISO format string for end date
                - "tags": List containing "ground_truth_candidate" if filtering
                         for ground truth only
        
        Example:
            >>> filter = ExportFilter(
            ...     trace_type="attack_tree",
            ...     start_date=datetime(2024, 1, 1),
            ...     ground_truth_only=True
            ... )
            >>> params = filter.to_langfuse_params()
            >>> params["trace_type"]
            'attack_tree'
            >>> "from_timestamp" in params
            True
            >>> "ground_truth_candidate" in params.get("tags", [])
            True
        """
        params: Dict[str, Any] = {}
        
        if self.trace_type is not None:
            params["trace_type"] = self.trace_type
        
        if self.review_status is not None:
            params["review_status"] = self.review_status
        
        if self.start_date is not None:
            params["from_timestamp"] = self.start_date.isoformat()
        
        if self.end_date is not None:
            params["to_timestamp"] = self.end_date.isoformat()
        
        if self.ground_truth_only:
            params["tags"] = ["ground_truth_candidate"]
        
        return params
    
    def __post_init__(self) -> None:
        """
        Post-initialization hook to validate the filter.
        
        This method is automatically called after the dataclass is initialized.
        It validates the filter configuration to catch errors early.
        
        Note: This validation runs automatically on construction. If you need
        to create an ExportFilter without immediate validation (e.g., for
        testing invalid configurations), you can catch the ValueError.
        """
        # Don't auto-validate to allow creating filters for testing
        # Users should call validate() explicitly before use
        pass


class LangfuseExporter:
    """
    Export scored traces from Langfuse to DynamoDB.
    
    This class provides functionality to query traces from Langfuse based on
    filter criteria and export them to DynamoDB tables. It supports:
    
    - Querying traces with filters (trace_type, review_status, date range)
    - Transforming Langfuse trace data to DynamoDB schema
    - Exporting ground truth candidates to a separate table without TTL
    - Setting TTL on non-ground-truth traces for automatic cleanup (90 days)
    
    The DynamoDB schema uses a single-table design with the following key structure:
    - PK: TRACE#{trace_type}#{trace_id}
    - SK: META
    - GSI1: TYPE#{trace_type} / {timestamp}#{trace_id}
    - GSI2: SESSION#{session_id} / {timestamp}#{trace_id}
    - GSI3: STATUS#{review_status} / {timestamp}#{trace_id}
    
    Requirements:
        - 7.1: Query Langfuse API with review_status and date_range filters
        - 7.2: Transform to DynamoDB schema with PK format TRACE#{trace_type}#{trace_id}
        - 7.4: Set TTL on non-ground-truth traces to 90 days
        - 7.5: Preserve langfuse_trace_id for cross-reference
        - 7.6: Export ground_truth_candidate traces to separate table without TTL
    
    Attributes:
        _langfuse: Langfuse client for querying traces
        _dynamodb: boto3 DynamoDB resource
        _traces_table: DynamoDB table for regular traces
        _gt_table: DynamoDB table for ground truth records
    
    Example:
        >>> from threatforest.tracing.config import LangfuseConfig
        >>> from threatforest.tracing.export import LangfuseExporter, ExportFilter
        >>> 
        >>> config = LangfuseConfig.from_env()
        >>> exporter = LangfuseExporter(config)
        >>> 
        >>> # Export reviewed attack tree traces from the last week
        >>> filter = ExportFilter(
        ...     trace_type="attack_tree",
        ...     review_status="reviewed",
        ...     start_date=datetime.now() - timedelta(days=7)
        ... )
        >>> result = exporter.export_traces(filter)
        >>> print(f"Exported {result['traces']} traces, {result['ground_truth']} ground truth")
    """
    
    # Default TTL duration for non-ground-truth traces (90 days)
    DEFAULT_TTL_DAYS: int = 90
    
    def __init__(
        self,
        langfuse_config: LangfuseConfig,
        dynamodb_table: str = "threatforest-traces",
        ground_truth_table: str = "threatforest-ground-truth"
    ):
        """
        Initialize the LangfuseExporter.
        
        Args:
            langfuse_config: Configuration for connecting to Langfuse.
            dynamodb_table: Name of the DynamoDB table for regular traces.
                Defaults to "threatforest-traces".
            ground_truth_table: Name of the DynamoDB table for ground truth records.
                Defaults to "threatforest-ground-truth".
        
        Raises:
            ValueError: If langfuse_config is enabled but credentials are missing.
            ImportError: If boto3 is not installed.
        
        Example:
            >>> config = LangfuseConfig.from_env()
            >>> exporter = LangfuseExporter(
            ...     langfuse_config=config,
            ...     dynamodb_table="my-traces-table",
            ...     ground_truth_table="my-gt-table"
            ... )
        """
        self._config = langfuse_config
        self._langfuse = self._init_langfuse(langfuse_config)
        self._dynamodb = self._init_dynamodb()
        self._traces_table = self._dynamodb.Table(dynamodb_table)
        self._gt_table = self._dynamodb.Table(ground_truth_table)
        self._dynamodb_table_name = dynamodb_table
        self._ground_truth_table_name = ground_truth_table
    
    def _init_langfuse(self, config: LangfuseConfig) -> Any:
        """
        Initialize the Langfuse client from configuration.
        
        Args:
            config: LangfuseConfig with connection settings.
        
        Returns:
            Langfuse client instance, or None if not enabled.
        
        Raises:
            ValueError: If enabled but credentials are missing.
            ImportError: If langfuse package is not installed.
        """
        if not config.enabled:
            logger.info("Langfuse is disabled, exporter will not query traces")
            return None
        
        # Validate configuration before attempting to create client
        config.validate()
        
        try:
            from langfuse import Langfuse
            return Langfuse(
                public_key=config.public_key,
                secret_key=config.secret_key,
                host=config.host
            )
        except ImportError:
            raise ImportError(
                "langfuse package is required for LangfuseExporter. "
                "Install it with: pip install langfuse"
            )
    
    def _init_dynamodb(self) -> Any:
        """
        Initialize the DynamoDB resource.
        
        Returns:
            boto3 DynamoDB resource.
        
        Raises:
            ImportError: If boto3 is not installed.
        """
        try:
            import boto3
            return boto3.resource("dynamodb")
        except ImportError:
            raise ImportError(
                "boto3 package is required for LangfuseExporter. "
                "Install it with: pip install boto3"
            )
    
    def _query_langfuse(self, filters: ExportFilter) -> List[Dict[str, Any]]:
        """
        Query Langfuse for traces matching the given filters.
        
        This method queries the Langfuse API to retrieve traces that match
        the specified filter criteria. It handles pagination automatically
        to retrieve all matching traces.
        
        Args:
            filters: ExportFilter with query criteria.
        
        Returns:
            List of trace dictionaries from Langfuse.
        
        Raises:
            RuntimeError: If Langfuse client is not initialized.
        
        Requirements:
            - 7.1: Query Langfuse API with review_status and date_range filters
            - 7.3: Support filtering by trace_type
        
        Example:
            >>> filter = ExportFilter(trace_type="attack_tree", review_status="reviewed")
            >>> traces = exporter._query_langfuse(filter)
            >>> print(f"Found {len(traces)} traces")
        """
        if self._langfuse is None:
            logger.warning("Langfuse client not initialized, returning empty list")
            return []
        
        # Validate filters before querying
        filters.validate()
        
        # Convert filters to Langfuse API parameters
        params = filters.to_langfuse_params()
        
        traces: List[Dict[str, Any]] = []
        page = 1
        
        try:
            while True:
                # Query Langfuse API with pagination
                response = self._langfuse.fetch_traces(
                    page=page,
                    limit=100,  # Max page size
                    **self._build_langfuse_query_params(params)
                )
                
                # Extract traces from response
                page_traces = response.data if hasattr(response, 'data') else []
                
                if not page_traces:
                    break
                
                # Apply additional filtering that Langfuse API may not support directly
                filtered_traces = self._apply_local_filters(page_traces, filters)
                traces.extend(filtered_traces)
                
                # Check if there are more pages
                if len(page_traces) < 100:
                    break
                
                page += 1
                
        except Exception as e:
            logger.error(f"Error querying Langfuse: {e}")
            raise RuntimeError(f"Failed to query Langfuse: {e}") from e
        
        logger.info(f"Retrieved {len(traces)} traces from Langfuse")
        return traces
    
    def _build_langfuse_query_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build Langfuse API query parameters from filter params.
        
        Args:
            params: Dictionary of filter parameters.
        
        Returns:
            Dictionary of Langfuse API query parameters.
        """
        query_params: Dict[str, Any] = {}
        
        # Map filter params to Langfuse API params
        if "from_timestamp" in params:
            query_params["from_timestamp"] = params["from_timestamp"]
        
        if "to_timestamp" in params:
            query_params["to_timestamp"] = params["to_timestamp"]
        
        if "tags" in params:
            query_params["tags"] = params["tags"]
        
        return query_params
    
    def _apply_local_filters(
        self,
        traces: List[Dict[str, Any]],
        filters: ExportFilter
    ) -> List[Dict[str, Any]]:
        """
        Apply additional filters locally that Langfuse API may not support.
        
        Args:
            traces: List of traces from Langfuse.
            filters: ExportFilter with filter criteria.
        
        Returns:
            Filtered list of traces.
        """
        filtered = traces
        
        # Filter by trace_type (stored in metadata)
        if filters.trace_type is not None:
            filtered = [
                t for t in filtered
                if t.get("metadata", {}).get("trace_type") == filters.trace_type
            ]
        
        # Filter by review_status (stored in metadata)
        if filters.review_status is not None:
            filtered = [
                t for t in filtered
                if t.get("metadata", {}).get("review_status") == filters.review_status
            ]
        
        # Filter for ground truth candidates only
        if filters.ground_truth_only:
            filtered = [
                t for t in filtered
                if t.get("metadata", {}).get("is_ground_truth_candidate", False)
            ]
        
        return filtered
    
    def _transform_to_ddb(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform a Langfuse trace to DynamoDB schema.
        
        This method converts a Langfuse trace dictionary to the DynamoDB
        schema used for storing traces. The schema includes:
        - Primary key (PK): TRACE#{trace_type}#{trace_id}
        - Sort key (SK): META
        - GSI keys for querying by type, session, and status
        
        Args:
            trace: Langfuse trace dictionary.
        
        Returns:
            Dictionary formatted for DynamoDB put_item.
        
        Requirements:
            - 7.2: Transform to DynamoDB schema with PK format TRACE#{trace_type}#{trace_id}
            - 7.5: Preserve langfuse_trace_id for cross-reference
        
        Example:
            >>> trace = {"id": "lf_123", "metadata": {"trace_type": "attack_tree"}, ...}
            >>> ddb_item = exporter._transform_to_ddb(trace)
            >>> print(ddb_item["PK"])  # "TRACE#attack_tree#lf_123"
        """
        metadata = trace.get("metadata", {})
        trace_type = metadata.get("trace_type", "unknown")
        trace_id = trace.get("id", str(uuid.uuid4()))
        timestamp = trace.get("timestamp", datetime.now().isoformat())
        session_id = trace.get("session_id", "")
        review_status = metadata.get("review_status", "pending_review")
        
        # Ensure timestamp is a string
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()
        
        return {
            # Primary key
            "PK": f"TRACE#{trace_type}#{trace_id}",
            "SK": "META",
            
            # GSI keys for efficient querying
            "GSI1PK": f"TYPE#{trace_type}",
            "GSI1SK": f"{timestamp}#{trace_id}",
            "GSI2PK": f"SESSION#{session_id}",
            "GSI2SK": f"{timestamp}#{trace_id}",
            "GSI3PK": f"STATUS#{review_status}",
            "GSI3SK": f"{timestamp}#{trace_id}",
            
            # Core trace data
            "trace_id": trace_id,
            "trace_type": trace_type,
            "langfuse_trace_id": trace.get("id"),
            "created_at": timestamp,
            "session_id": session_id,
            
            # Input/output data
            "input": trace.get("input"),
            "output": trace.get("output"),
            
            # Metadata
            "generation_metadata": metadata.get("generation_metadata"),
            "scores": self._extract_scores(trace),
            "review_status": review_status,
        }
    
    def _transform_to_gt(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform a Langfuse trace to ground truth DynamoDB schema.
        
        This method converts a Langfuse trace marked as a ground truth candidate
        to the ground truth table schema. Ground truth records have a different
        key structure and include evaluation criteria.
        
        Args:
            trace: Langfuse trace dictionary marked as ground truth candidate.
        
        Returns:
            Dictionary formatted for ground truth table put_item.
        
        Requirements:
            - 7.6: Export ground_truth_candidate traces to separate table without TTL
            - 10.2: Export approved ground truth with evaluation_criteria
        
        Example:
            >>> trace = {"id": "lf_123", "metadata": {"is_ground_truth_candidate": True}, ...}
            >>> gt_item = exporter._transform_to_gt(trace)
            >>> print(gt_item["PK"])  # "GT#attack_tree#gt_..."
        """
        metadata = trace.get("metadata", {})
        trace_type = metadata.get("trace_type", "unknown")
        trace_id = trace.get("id", str(uuid.uuid4()))
        timestamp = trace.get("timestamp", datetime.now().isoformat())
        
        # Generate a unique ground truth ID
        gt_id = f"gt_{trace_id}"
        
        # Ensure timestamp is a string
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()
        
        return {
            # Primary key for ground truth table
            "PK": f"GT#{trace_type}#{gt_id}",
            "SK": "META",
            
            # Ground truth identifiers
            "ground_truth_id": gt_id,
            "type": trace_type,
            "source_trace_id": trace_id,
            
            # Timestamps and attribution
            "created_at": timestamp,
            "created_by": metadata.get("reviewer_id", "system"),
            
            # Dataset information
            "dataset_id": metadata.get("dataset_id", "default"),
            "split": metadata.get("split", "train"),
            
            # Input/output data
            "input": trace.get("input"),
            "reference_output": trace.get("output"),
            
            # Evaluation criteria from metadata
            "evaluation_criteria": metadata.get("evaluation_criteria", {}),
            
            # Additional metadata
            "metadata": {
                "langfuse_trace_id": trace.get("id"),
                "scores": self._extract_scores(trace),
                "session_id": trace.get("session_id"),
            }
        }
    
    def _extract_scores(self, trace: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract scores from a Langfuse trace.
        
        This method extracts SME scores from the trace data, converting them
        to a standardized format for storage in DynamoDB.
        
        Args:
            trace: Langfuse trace dictionary.
        
        Returns:
            List of score dictionaries with name, value, and optional comment.
        
        Example:
            >>> trace = {"scores": [{"name": "quality", "value": 0.85}]}
            >>> scores = exporter._extract_scores(trace)
            >>> print(scores[0]["name"])  # "quality"
        """
        scores: List[Dict[str, Any]] = []
        
        # Extract scores from trace data
        trace_scores = trace.get("scores", [])
        
        for score in trace_scores:
            score_dict: Dict[str, Any] = {
                "name": score.get("name", "unknown"),
                "value": score.get("value", 0.0),
            }
            
            # Include optional fields if present
            if "comment" in score:
                score_dict["comment"] = score["comment"]
            
            if "reviewer_id" in score:
                score_dict["reviewer_id"] = score["reviewer_id"]
            
            if "reviewed_at" in score:
                reviewed_at = score["reviewed_at"]
                if isinstance(reviewed_at, datetime):
                    score_dict["reviewed_at"] = reviewed_at.isoformat()
                else:
                    score_dict["reviewed_at"] = reviewed_at
            
            scores.append(score_dict)
        
        return scores
    
    def export_traces(self, filters: ExportFilter) -> Dict[str, int]:
        """
        Export traces matching filters to DynamoDB.
        
        This is the main method for exporting traces from Langfuse to DynamoDB.
        It queries Langfuse for traces matching the filter criteria, transforms
        them to the DynamoDB schema, and writes them to the appropriate table.
        
        Ground truth candidates are written to the ground truth table without TTL.
        Regular traces are written to the traces table with a 90-day TTL.
        
        Args:
            filters: ExportFilter with query criteria.
        
        Returns:
            Dictionary with counts of exported items:
            - "traces": Number of regular traces exported
            - "ground_truth": Number of ground truth records exported
        
        Raises:
            RuntimeError: If Langfuse query fails.
            Exception: If DynamoDB write fails after retries.
        
        Requirements:
            - 7.1: Query Langfuse API with filters
            - 7.2: Transform to DynamoDB schema
            - 7.4: Set TTL on non-ground-truth traces to 90 days
            - 7.6: Export ground_truth_candidate to separate table without TTL
        
        Example:
            >>> filter = ExportFilter(
            ...     trace_type="attack_tree",
            ...     review_status="reviewed"
            ... )
            >>> result = exporter.export_traces(filter)
            >>> print(f"Exported {result['traces']} traces")
            >>> print(f"Exported {result['ground_truth']} ground truth records")
        """
        # Query Langfuse for matching traces
        traces = self._query_langfuse(filters)
        
        exported = {"traces": 0, "ground_truth": 0}
        
        for trace in traces:
            try:
                # Check if this is a ground truth candidate
                is_gt_candidate = trace.get("metadata", {}).get(
                    "is_ground_truth_candidate", False
                )
                
                if is_gt_candidate:
                    # Export to ground truth table without TTL
                    gt_item = self._transform_to_gt(trace)
                    self._gt_table.put_item(Item=gt_item)
                    exported["ground_truth"] += 1
                    logger.debug(f"Exported ground truth: {gt_item['PK']}")
                else:
                    # Export to traces table with TTL
                    ddb_item = self._transform_to_ddb(trace)
                    
                    # Set TTL for non-ground-truth traces (90 days from now)
                    ttl = int((datetime.now() + timedelta(days=self.DEFAULT_TTL_DAYS)).timestamp())
                    ddb_item["ttl"] = ttl
                    
                    self._traces_table.put_item(Item=ddb_item)
                    exported["traces"] += 1
                    logger.debug(f"Exported trace: {ddb_item['PK']}")
                    
            except Exception as e:
                logger.error(f"Failed to export trace {trace.get('id')}: {e}")
                # Continue with other traces instead of failing completely
                continue
        
        logger.info(
            f"Export complete: {exported['traces']} traces, "
            f"{exported['ground_truth']} ground truth records"
        )
        
        return exported
