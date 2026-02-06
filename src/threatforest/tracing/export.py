"""
Export Pipeline for ThreatForest Tracing

This module provides functionality for exporting scored traces from Langfuse
to Langfuse Datasets for evaluation pipelines and ground truth dataset curation.

The export pipeline supports:
- Filtering traces by type, review status, date range, and ground truth status
- Creating and managing Langfuse Datasets
- Adding dataset items with input/expected_output for evaluation
- Supporting dataset versioning and experiment tracking

Requirements:
- 7.1: THE Export_Pipeline SHALL query Langfuse API for traces with specified
       review_status and date_range filters
- 7.3: THE Export_Pipeline SHALL support filtering by trace_type:
       threat_statement, attack_tree, ttp_matching
- 7.5: THE Export_Pipeline SHALL preserve langfuse_trace_id for cross-reference
"""

from dataclasses import dataclass, field
from datetime import datetime
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
    from Langfuse for export to Langfuse Datasets. All filter fields are optional
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
        
        Returns:
            Dict[str, Any]: Dictionary of query parameters for Langfuse API.
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
        """Post-initialization hook - validation is deferred to explicit call."""
        pass


class LangfuseDatasetExporter:
    """
    Export scored traces from Langfuse to Langfuse Datasets.
    
    This class provides functionality to query traces from Langfuse based on
    filter criteria and export them to Langfuse Datasets for evaluation. It supports:
    
    - Querying traces with filters (trace_type, review_status, date range)
    - Creating datasets in Langfuse
    - Adding dataset items with input/expected_output pairs
    - Preserving metadata and scores for evaluation
    
    Langfuse Datasets enable:
    - Running experiments with different model configurations
    - Comparing outputs against reference outputs
    - Tracking evaluation metrics over time
    
    Requirements:
        - 7.1: Query Langfuse API with review_status and date_range filters
        - 7.5: Preserve langfuse_trace_id for cross-reference
    
    Attributes:
        _langfuse: Langfuse client for querying traces and managing datasets
        _config: LangfuseConfig with connection settings
    
    Example:
        >>> from threatforest.tracing.config import LangfuseConfig
        >>> from threatforest.tracing.export import LangfuseDatasetExporter, ExportFilter
        >>> 
        >>> config = LangfuseConfig.from_env()
        >>> exporter = LangfuseDatasetExporter(config)
        >>> 
        >>> # Export reviewed attack tree traces to a dataset
        >>> filter = ExportFilter(
        ...     trace_type="attack_tree",
        ...     review_status="reviewed",
        ...     start_date=datetime.now() - timedelta(days=7)
        ... )
        >>> result = exporter.export_to_dataset(filter, dataset_name="attack-trees-v1")
        >>> print(f"Exported {result['items_created']} items to dataset")
    """
    
    def __init__(self, langfuse_config: LangfuseConfig):
        """
        Initialize the LangfuseDatasetExporter.
        
        Args:
            langfuse_config: Configuration for connecting to Langfuse.
        
        Raises:
            ValueError: If langfuse_config is enabled but credentials are missing.
            ImportError: If langfuse is not installed.
        """
        self._config = langfuse_config
        self._langfuse = self._init_langfuse(langfuse_config)
    
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
                "langfuse package is required for LangfuseDatasetExporter. "
                "Install it with: pip install langfuse"
            )
    
    def _query_langfuse(self, filters: ExportFilter) -> List[Dict[str, Any]]:
        """
        Query Langfuse for traces matching the given filters.
        
        Args:
            filters: ExportFilter with query criteria.
        
        Returns:
            List of trace dictionaries from Langfuse.
        
        Raises:
            RuntimeError: If Langfuse client is not initialized.
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
        """Build Langfuse API query parameters from filter params."""
        query_params: Dict[str, Any] = {}
        
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
        """Apply additional filters locally that Langfuse API may not support."""
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
    
    def _extract_scores(self, trace: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract scores from a Langfuse trace."""
        scores: List[Dict[str, Any]] = []
        trace_scores = trace.get("scores", [])
        
        for score in trace_scores:
            score_dict: Dict[str, Any] = {
                "name": score.get("name", "unknown"),
                "value": score.get("value", 0.0),
            }
            
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
    
    def create_dataset(self, name: str, description: Optional[str] = None) -> Any:
        """
        Create a new dataset in Langfuse.
        
        Args:
            name: Name of the dataset to create.
            description: Optional description for the dataset.
        
        Returns:
            The created dataset object.
        
        Raises:
            RuntimeError: If Langfuse client is not initialized.
        """
        if self._langfuse is None:
            raise RuntimeError("Langfuse client not initialized")
        
        try:
            dataset = self._langfuse.create_dataset(
                name=name,
                description=description or f"ThreatForest evaluation dataset: {name}"
            )
            logger.info(f"Created dataset: {name}")
            return dataset
        except Exception as e:
            logger.error(f"Failed to create dataset {name}: {e}")
            raise RuntimeError(f"Failed to create dataset: {e}") from e
    
    def get_or_create_dataset(self, name: str, description: Optional[str] = None) -> Any:
        """
        Get an existing dataset or create a new one.
        
        Args:
            name: Name of the dataset.
            description: Optional description for new dataset.
        
        Returns:
            The dataset object.
        """
        if self._langfuse is None:
            raise RuntimeError("Langfuse client not initialized")
        
        try:
            # Try to get existing dataset
            dataset = self._langfuse.get_dataset(name)
            logger.info(f"Found existing dataset: {name}")
            return dataset
        except Exception:
            # Dataset doesn't exist, create it
            return self.create_dataset(name, description)
    
    def _transform_to_dataset_item(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform a Langfuse trace to a dataset item format.
        
        Args:
            trace: Langfuse trace dictionary.
        
        Returns:
            Dictionary with input, expected_output, and metadata for dataset item.
        """
        metadata = trace.get("metadata", {})
        trace_type = metadata.get("trace_type", "unknown")
        trace_id = trace.get("id", str(uuid.uuid4()))
        timestamp = trace.get("timestamp", datetime.now().isoformat())
        
        # Ensure timestamp is a string
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()
        
        return {
            "input": trace.get("input"),
            "expected_output": trace.get("output"),
            "metadata": {
                "langfuse_trace_id": trace_id,
                "trace_type": trace_type,
                "session_id": trace.get("session_id"),
                "created_at": timestamp,
                "review_status": metadata.get("review_status", "pending_review"),
                "generation_metadata": metadata.get("generation_metadata"),
                "scores": self._extract_scores(trace),
                "is_ground_truth_candidate": metadata.get("is_ground_truth_candidate", False),
                "evaluation_criteria": metadata.get("evaluation_criteria"),
            }
        }
    
    def export_to_dataset(
        self,
        filters: ExportFilter,
        dataset_name: str,
        dataset_description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export traces matching filters to a Langfuse Dataset.
        
        This is the main method for exporting traces from Langfuse to a Dataset.
        It queries Langfuse for traces matching the filter criteria, transforms
        them to dataset items, and adds them to the specified dataset.
        
        Args:
            filters: ExportFilter with query criteria.
            dataset_name: Name of the dataset to export to.
            dataset_description: Optional description for the dataset.
        
        Returns:
            Dictionary with export statistics:
            - "dataset_name": Name of the dataset
            - "items_created": Number of items added to the dataset
            - "items_skipped": Number of items skipped (e.g., duplicates)
            - "total_traces": Total traces found matching filters
        
        Raises:
            RuntimeError: If Langfuse query or dataset operations fail.
        
        Example:
            >>> filter = ExportFilter(
            ...     trace_type="attack_tree",
            ...     review_status="reviewed"
            ... )
            >>> result = exporter.export_to_dataset(filter, "attack-trees-eval-v1")
            >>> print(f"Created {result['items_created']} dataset items")
        """
        # Query Langfuse for matching traces
        traces = self._query_langfuse(filters)
        
        result = {
            "dataset_name": dataset_name,
            "items_created": 0,
            "items_skipped": 0,
            "total_traces": len(traces),
        }
        
        if not traces:
            logger.info("No traces found matching filters")
            return result
        
        # Get or create the dataset
        dataset = self.get_or_create_dataset(dataset_name, dataset_description)
        
        for trace in traces:
            try:
                # Transform trace to dataset item format
                item_data = self._transform_to_dataset_item(trace)
                
                # Create dataset item
                self._langfuse.create_dataset_item(
                    dataset_name=dataset_name,
                    input=item_data["input"],
                    expected_output=item_data["expected_output"],
                    metadata=item_data["metadata"],
                )
                
                result["items_created"] += 1
                logger.debug(f"Created dataset item for trace: {trace.get('id')}")
                
            except Exception as e:
                logger.warning(f"Failed to create dataset item for trace {trace.get('id')}: {e}")
                result["items_skipped"] += 1
                continue
        
        logger.info(
            f"Export complete: {result['items_created']} items created, "
            f"{result['items_skipped']} skipped"
        )
        
        return result
    
    def list_datasets(self) -> List[Dict[str, Any]]:
        """
        List all datasets in Langfuse.
        
        Returns:
            List of dataset dictionaries with name and metadata.
        """
        if self._langfuse is None:
            return []
        
        try:
            # Note: Langfuse v2 API may not have a direct list_datasets method
            # This is a placeholder - actual implementation depends on API
            datasets = self._langfuse.get_datasets()
            return [{"name": d.name, "description": d.description} for d in datasets.data]
        except Exception as e:
            logger.warning(f"Failed to list datasets: {e}")
            return []


# Backwards compatibility alias
LangfuseExporter = LangfuseDatasetExporter
