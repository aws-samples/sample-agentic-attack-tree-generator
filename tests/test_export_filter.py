"""
Unit Tests for ExportFilter Dataclass

This module tests the ExportFilter dataclass used for querying Langfuse traces
for export to DynamoDB.

Requirements:
- 7.1: THE Export_Pipeline SHALL query Langfuse API for traces with specified
       review_status and date_range filters
- 7.3: THE Export_Pipeline SHALL support filtering by trace_type:
       threat_statement, attack_tree, ttp_matching
"""

from datetime import datetime, timedelta

import pytest

from threatforest.tracing.export import ExportFilter


class TestExportFilterCreation:
    """Tests for ExportFilter dataclass creation."""

    def test_default_values(self):
        """Test that ExportFilter has correct default values."""
        filter = ExportFilter()
        
        assert filter.trace_type is None
        assert filter.review_status is None
        assert filter.start_date is None
        assert filter.end_date is None
        assert filter.ground_truth_only is False

    def test_with_trace_type(self):
        """Test ExportFilter with trace_type specified."""
        filter = ExportFilter(trace_type="attack_tree")
        
        assert filter.trace_type == "attack_tree"

    def test_with_review_status(self):
        """Test ExportFilter with review_status specified."""
        filter = ExportFilter(review_status="reviewed")
        
        assert filter.review_status == "reviewed"

    def test_with_date_range(self):
        """Test ExportFilter with date range specified."""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 31)
        
        filter = ExportFilter(start_date=start, end_date=end)
        
        assert filter.start_date == start
        assert filter.end_date == end

    def test_with_ground_truth_only(self):
        """Test ExportFilter with ground_truth_only flag."""
        filter = ExportFilter(ground_truth_only=True)
        
        assert filter.ground_truth_only is True

    def test_with_all_fields(self):
        """Test ExportFilter with all fields specified."""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 31)
        
        filter = ExportFilter(
            trace_type="threat_statement",
            review_status="pending_review",
            start_date=start,
            end_date=end,
            ground_truth_only=True
        )
        
        assert filter.trace_type == "threat_statement"
        assert filter.review_status == "pending_review"
        assert filter.start_date == start
        assert filter.end_date == end
        assert filter.ground_truth_only is True


class TestExportFilterValidation:
    """Tests for ExportFilter validation method."""

    def test_valid_filter_passes_validation(self):
        """Test that a valid filter passes validation without error."""
        filter = ExportFilter(
            trace_type="attack_tree",
            review_status="reviewed",
            start_date=datetime(2024, 1, 1),
            end_date=datetime(2024, 1, 31)
        )
        
        # Should not raise
        filter.validate()

    def test_empty_filter_passes_validation(self):
        """Test that an empty filter passes validation."""
        filter = ExportFilter()
        
        # Should not raise
        filter.validate()

    def test_invalid_date_range_raises_error(self):
        """Test that start_date > end_date raises ValueError."""
        filter = ExportFilter(
            start_date=datetime(2024, 2, 1),
            end_date=datetime(2024, 1, 1)
        )
        
        with pytest.raises(ValueError) as exc_info:
            filter.validate()
        
        assert "Invalid date range" in str(exc_info.value)
        assert "start_date" in str(exc_info.value)
        assert "end_date" in str(exc_info.value)

    def test_equal_dates_passes_validation(self):
        """Test that start_date == end_date passes validation."""
        same_date = datetime(2024, 1, 15)
        filter = ExportFilter(start_date=same_date, end_date=same_date)
        
        # Should not raise
        filter.validate()

    def test_only_start_date_passes_validation(self):
        """Test that only start_date specified passes validation."""
        filter = ExportFilter(start_date=datetime(2024, 1, 1))
        
        # Should not raise
        filter.validate()

    def test_only_end_date_passes_validation(self):
        """Test that only end_date specified passes validation."""
        filter = ExportFilter(end_date=datetime(2024, 1, 31))
        
        # Should not raise
        filter.validate()

    def test_invalid_trace_type_raises_error(self):
        """Test that invalid trace_type raises ValueError."""
        filter = ExportFilter(trace_type="invalid_type")
        
        with pytest.raises(ValueError) as exc_info:
            filter.validate()
        
        assert "Invalid trace_type" in str(exc_info.value)
        assert "invalid_type" in str(exc_info.value)

    def test_valid_trace_types(self):
        """Test that all valid trace types pass validation."""
        valid_types = ["threat_statement", "attack_tree", "ttp_matching"]
        
        for trace_type in valid_types:
            filter = ExportFilter(trace_type=trace_type)
            filter.validate()  # Should not raise

    def test_invalid_review_status_raises_error(self):
        """Test that invalid review_status raises ValueError."""
        filter = ExportFilter(review_status="invalid_status")
        
        with pytest.raises(ValueError) as exc_info:
            filter.validate()
        
        assert "Invalid review_status" in str(exc_info.value)
        assert "invalid_status" in str(exc_info.value)

    def test_valid_review_statuses(self):
        """Test that all valid review statuses pass validation."""
        valid_statuses = ["pending_review", "reviewed"]
        
        for status in valid_statuses:
            filter = ExportFilter(review_status=status)
            filter.validate()  # Should not raise


class TestExportFilterToLangfuseParams:
    """Tests for ExportFilter.to_langfuse_params() method."""

    def test_empty_filter_returns_empty_dict(self):
        """Test that empty filter returns empty params dict."""
        filter = ExportFilter()
        params = filter.to_langfuse_params()
        
        assert params == {}

    def test_trace_type_in_params(self):
        """Test that trace_type is included in params."""
        filter = ExportFilter(trace_type="attack_tree")
        params = filter.to_langfuse_params()
        
        assert params["trace_type"] == "attack_tree"

    def test_review_status_in_params(self):
        """Test that review_status is included in params."""
        filter = ExportFilter(review_status="reviewed")
        params = filter.to_langfuse_params()
        
        assert params["review_status"] == "reviewed"

    def test_start_date_in_params(self):
        """Test that start_date is converted to ISO format."""
        start = datetime(2024, 1, 15, 10, 30, 0)
        filter = ExportFilter(start_date=start)
        params = filter.to_langfuse_params()
        
        assert "from_timestamp" in params
        assert params["from_timestamp"] == start.isoformat()

    def test_end_date_in_params(self):
        """Test that end_date is converted to ISO format."""
        end = datetime(2024, 1, 31, 23, 59, 59)
        filter = ExportFilter(end_date=end)
        params = filter.to_langfuse_params()
        
        assert "to_timestamp" in params
        assert params["to_timestamp"] == end.isoformat()

    def test_ground_truth_only_adds_tag(self):
        """Test that ground_truth_only adds tag to params."""
        filter = ExportFilter(ground_truth_only=True)
        params = filter.to_langfuse_params()
        
        assert "tags" in params
        assert "ground_truth_candidate" in params["tags"]

    def test_ground_truth_false_no_tag(self):
        """Test that ground_truth_only=False doesn't add tag."""
        filter = ExportFilter(ground_truth_only=False)
        params = filter.to_langfuse_params()
        
        assert "tags" not in params

    def test_all_params_combined(self):
        """Test that all params are combined correctly."""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 31)
        
        filter = ExportFilter(
            trace_type="ttp_matching",
            review_status="pending_review",
            start_date=start,
            end_date=end,
            ground_truth_only=True
        )
        params = filter.to_langfuse_params()
        
        assert params["trace_type"] == "ttp_matching"
        assert params["review_status"] == "pending_review"
        assert params["from_timestamp"] == start.isoformat()
        assert params["to_timestamp"] == end.isoformat()
        assert "ground_truth_candidate" in params["tags"]

    def test_none_values_excluded(self):
        """Test that None values are not included in params."""
        filter = ExportFilter(trace_type="attack_tree")
        params = filter.to_langfuse_params()
        
        assert "trace_type" in params
        assert "review_status" not in params
        assert "from_timestamp" not in params
        assert "to_timestamp" not in params


class TestExportFilterValidTraceTypes:
    """Tests for valid trace type constants."""

    def test_valid_trace_types_list(self):
        """Test that VALID_TRACE_TYPES contains expected values."""
        filter = ExportFilter()
        
        assert "threat_statement" in filter.VALID_TRACE_TYPES
        assert "attack_tree" in filter.VALID_TRACE_TYPES
        assert "ttp_matching" in filter.VALID_TRACE_TYPES
        assert len(filter.VALID_TRACE_TYPES) == 3


class TestExportFilterValidReviewStatuses:
    """Tests for valid review status constants."""

    def test_valid_review_statuses_list(self):
        """Test that VALID_REVIEW_STATUSES contains expected values."""
        filter = ExportFilter()
        
        assert "pending_review" in filter.VALID_REVIEW_STATUSES
        assert "reviewed" in filter.VALID_REVIEW_STATUSES
        assert len(filter.VALID_REVIEW_STATUSES) == 2


class TestExportFilterImport:
    """Tests for ExportFilter import from tracing module."""

    def test_import_from_tracing_module(self):
        """Test that ExportFilter can be imported from threatforest.tracing."""
        from threatforest.tracing import ExportFilter as ImportedExportFilter
        
        # Verify it's the same class
        filter = ImportedExportFilter(trace_type="attack_tree")
        assert filter.trace_type == "attack_tree"

    def test_import_from_export_module(self):
        """Test that ExportFilter can be imported from export module."""
        from threatforest.tracing.export import ExportFilter as DirectExportFilter
        
        filter = DirectExportFilter(review_status="reviewed")
        assert filter.review_status == "reviewed"


class TestExportFilterEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_datetime_with_microseconds(self):
        """Test that datetime with microseconds is handled correctly."""
        start = datetime(2024, 1, 1, 12, 30, 45, 123456)
        filter = ExportFilter(start_date=start)
        params = filter.to_langfuse_params()
        
        # ISO format should include microseconds
        assert "123456" in params["from_timestamp"]

    def test_datetime_at_midnight(self):
        """Test that datetime at midnight is handled correctly."""
        midnight = datetime(2024, 1, 1, 0, 0, 0)
        filter = ExportFilter(start_date=midnight, end_date=midnight)
        
        filter.validate()  # Should not raise
        params = filter.to_langfuse_params()
        
        assert params["from_timestamp"] == "2024-01-01T00:00:00"
        assert params["to_timestamp"] == "2024-01-01T00:00:00"

    def test_date_range_spanning_year(self):
        """Test date range spanning multiple years."""
        filter = ExportFilter(
            start_date=datetime(2023, 12, 1),
            end_date=datetime(2024, 2, 28)
        )
        
        filter.validate()  # Should not raise

    def test_very_small_date_range(self):
        """Test very small date range (1 second)."""
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = datetime(2024, 1, 1, 12, 0, 1)
        
        filter = ExportFilter(start_date=start, end_date=end)
        filter.validate()  # Should not raise

    def test_filter_repr(self):
        """Test that filter has a reasonable string representation."""
        filter = ExportFilter(
            trace_type="attack_tree",
            ground_truth_only=True
        )
        
        repr_str = repr(filter)
        assert "attack_tree" in repr_str
        assert "ground_truth_only=True" in repr_str
