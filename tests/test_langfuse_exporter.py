"""
Unit Tests for LangfuseExporter Class

This module tests the LangfuseExporter class used for exporting scored traces
from Langfuse to DynamoDB.

Requirements:
- 7.1: THE Export_Pipeline SHALL query Langfuse API for traces with specified
       review_status and date_range filters
- 7.2: THE Export_Pipeline SHALL transform Langfuse trace data to the DynamoDB
       schema with PK format TRACE#{trace_type}#{trace_id}
- 7.4: THE Export_Pipeline SHALL set TTL on non-ground-truth traces to 90 days
- 7.5: THE Export_Pipeline SHALL preserve langfuse_trace_id for cross-reference
- 7.6: WHEN a trace is marked as ground_truth_candidate, THE Export_Pipeline
       SHALL export to threatforest-ground-truth table without TTL
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import pytest

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.export import ExportFilter, LangfuseExporter


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_boto3():
    """Create a mock boto3 module."""
    with patch('threatforest.tracing.export.LangfuseExporter._init_dynamodb') as mock_init:
        mock_resource = MagicMock()
        mock_init.return_value = mock_resource
        yield mock_resource


@pytest.fixture
def mock_langfuse():
    """Create a mock Langfuse client."""
    with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init:
        mock_client = MagicMock()
        mock_init.return_value = mock_client
        yield mock_client


@pytest.fixture
def disabled_config():
    """Create a disabled LangfuseConfig."""
    return LangfuseConfig(enabled=False)


@pytest.fixture
def enabled_config():
    """Create an enabled LangfuseConfig with mock credentials."""
    return LangfuseConfig(
        enabled=True,
        public_key="pk-lf-test-key",
        secret_key="sk-lf-test-key",
        host="https://test.langfuse.com"
    )


@pytest.fixture
def mock_exporter(mock_boto3, mock_langfuse, disabled_config):
    """Create a LangfuseExporter with mocked dependencies."""
    mock_traces_table = MagicMock()
    mock_gt_table = MagicMock()
    mock_boto3.Table.side_effect = lambda name: (
        mock_traces_table if "traces" in name else mock_gt_table
    )
    
    exporter = LangfuseExporter(disabled_config)
    exporter._traces_table = mock_traces_table
    exporter._gt_table = mock_gt_table
    return exporter, mock_traces_table, mock_gt_table


@pytest.fixture
def sample_trace():
    """Create a sample Langfuse trace for testing."""
    return {
        "id": "lf_trace_123",
        "timestamp": "2024-01-15T10:30:00",
        "session_id": "session_456",
        "input": {"threat_statement": {"id": "T1", "description": "SQL Injection"}},
        "output": {"attack_tree_markdown": "# Attack Tree"},
        "metadata": {
            "trace_type": "attack_tree",
            "review_status": "reviewed",
            "generation_metadata": {"model_id": "claude-3", "latency_ms": 1500}
        },
        "scores": [
            {"name": "overall_quality", "value": 0.85, "comment": "Good quality"}
        ]
    }


@pytest.fixture
def sample_ground_truth_trace():
    """Create a sample ground truth candidate trace."""
    return {
        "id": "lf_trace_gt_789",
        "timestamp": "2024-01-15T11:00:00",
        "session_id": "session_789",
        "input": {"threat_statement": {"id": "T2", "description": "XSS Attack"}},
        "output": {"attack_tree_markdown": "# XSS Attack Tree"},
        "metadata": {
            "trace_type": "attack_tree",
            "review_status": "reviewed",
            "is_ground_truth_candidate": True,
            "reviewer_id": "sme_user_123",
            "dataset_id": "dataset_v1",
            "split": "train",
            "evaluation_criteria": {"min_nodes": 5}
        },
        "scores": [
            {"name": "overall_quality", "value": 0.95}
        ]
    }


# =============================================================================
# Test LangfuseExporter Initialization
# =============================================================================


class TestLangfuseExporterInit:
    """Tests for LangfuseExporter initialization."""

    def test_init_with_disabled_config(self, mock_boto3, disabled_config):
        """Test initialization with disabled Langfuse config."""
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = None
            exporter = LangfuseExporter(disabled_config)
            
            assert exporter._langfuse is None
            assert exporter._config == disabled_config

    def test_init_with_enabled_config(self, mock_boto3, enabled_config):
        """Test initialization with enabled Langfuse config."""
        mock_langfuse_instance = MagicMock()
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_langfuse_instance
            exporter = LangfuseExporter(enabled_config)
            
            assert exporter._langfuse == mock_langfuse_instance

    def test_init_creates_dynamodb_tables(self, disabled_config):
        """Test that initialization creates DynamoDB table references."""
        mock_resource = MagicMock()
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        mock_resource.Table.side_effect = lambda name: (
            mock_traces_table if name == "custom-traces" else mock_gt_table
        )
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf, \
             patch('threatforest.tracing.export.LangfuseExporter._init_dynamodb') as mock_init_ddb:
            mock_init_lf.return_value = None
            mock_init_ddb.return_value = mock_resource
            
            exporter = LangfuseExporter(
                disabled_config,
                dynamodb_table="custom-traces",
                ground_truth_table="custom-gt"
            )
            
            mock_resource.Table.assert_any_call("custom-traces")
            mock_resource.Table.assert_any_call("custom-gt")

    def test_init_with_invalid_enabled_config_raises_error(self, mock_boto3):
        """Test that invalid enabled config raises ValueError."""
        invalid_config = LangfuseConfig(enabled=True, public_key=None, secret_key=None)
        
        with pytest.raises(ValueError) as exc_info:
            LangfuseExporter(invalid_config)
        
        assert "credentials are missing" in str(exc_info.value)


# =============================================================================
# Test _transform_to_ddb Method
# =============================================================================


class TestTransformToDdb:
    """Tests for _transform_to_ddb method."""

    def test_transform_creates_correct_pk(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that PK is created in correct format."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert result["PK"] == "TRACE#attack_tree#lf_trace_123"

    def test_transform_creates_correct_sk(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that SK is set to META."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert result["SK"] == "META"

    def test_transform_creates_gsi_keys(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that GSI keys are created correctly."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert result["GSI1PK"] == "TYPE#attack_tree"
        assert "2024-01-15T10:30:00#lf_trace_123" in result["GSI1SK"]
        assert result["GSI2PK"] == "SESSION#session_456"
        assert result["GSI3PK"] == "STATUS#reviewed"

    def test_transform_preserves_langfuse_trace_id(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that langfuse_trace_id is preserved (Requirement 7.5)."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert result["langfuse_trace_id"] == "lf_trace_123"

    def test_transform_includes_input_output(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that input and output are included."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert result["input"] == sample_trace["input"]
        assert result["output"] == sample_trace["output"]

    def test_transform_includes_generation_metadata(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that generation_metadata is included."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert result["generation_metadata"] == {"model_id": "claude-3", "latency_ms": 1500}

    def test_transform_extracts_scores(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test that scores are extracted correctly."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_ddb(sample_trace)
        
        assert len(result["scores"]) == 1
        assert result["scores"][0]["name"] == "overall_quality"
        assert result["scores"][0]["value"] == 0.85

    def test_transform_handles_missing_metadata(self, mock_boto3, mock_langfuse, disabled_config):
        """Test transformation handles trace with missing metadata."""
        exporter = LangfuseExporter(disabled_config)
        
        trace = {
            "id": "lf_trace_minimal",
            "timestamp": "2024-01-15T10:00:00",
            "session_id": "session_min"
        }
        
        result = exporter._transform_to_ddb(trace)
        
        assert result["PK"] == "TRACE#unknown#lf_trace_minimal"
        assert result["trace_type"] == "unknown"
        assert result["review_status"] == "pending_review"

    def test_transform_handles_datetime_timestamp(self, mock_boto3, mock_langfuse, disabled_config):
        """Test transformation handles datetime object as timestamp."""
        exporter = LangfuseExporter(disabled_config)
        
        trace = {
            "id": "lf_trace_dt",
            "timestamp": datetime(2024, 1, 15, 10, 30, 0),
            "session_id": "session_dt",
            "metadata": {"trace_type": "threat_statement"}
        }
        
        result = exporter._transform_to_ddb(trace)
        
        assert result["created_at"] == "2024-01-15T10:30:00"


# =============================================================================
# Test _transform_to_gt Method
# =============================================================================


class TestTransformToGt:
    """Tests for _transform_to_gt method."""

    def test_transform_gt_creates_correct_pk(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that ground truth PK is created correctly."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["PK"].startswith("GT#attack_tree#gt_")

    def test_transform_gt_includes_source_trace_id(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that source_trace_id is included."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["source_trace_id"] == "lf_trace_gt_789"

    def test_transform_gt_includes_dataset_info(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that dataset_id and split are included."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["dataset_id"] == "dataset_v1"
        assert result["split"] == "train"

    def test_transform_gt_includes_evaluation_criteria(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that evaluation_criteria is included."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["evaluation_criteria"] == {"min_nodes": 5}

    def test_transform_gt_includes_reference_output(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that reference_output is included."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["reference_output"] == sample_ground_truth_trace["output"]

    def test_transform_gt_includes_created_by(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that created_by is included from reviewer_id."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["created_by"] == "sme_user_123"

    def test_transform_gt_preserves_langfuse_trace_id_in_metadata(self, mock_boto3, mock_langfuse, disabled_config, sample_ground_truth_trace):
        """Test that langfuse_trace_id is preserved in metadata."""
        exporter = LangfuseExporter(disabled_config)
        
        result = exporter._transform_to_gt(sample_ground_truth_trace)
        
        assert result["metadata"]["langfuse_trace_id"] == "lf_trace_gt_789"


# =============================================================================
# Test _extract_scores Method
# =============================================================================


class TestExtractScores:
    """Tests for _extract_scores method."""

    def test_extract_scores_basic(self, mock_boto3, mock_langfuse, disabled_config, sample_trace):
        """Test basic score extraction."""
        exporter = LangfuseExporter(disabled_config)
        
        scores = exporter._extract_scores(sample_trace)
        
        assert len(scores) == 1
        assert scores[0]["name"] == "overall_quality"
        assert scores[0]["value"] == 0.85
        assert scores[0]["comment"] == "Good quality"

    def test_extract_scores_empty(self, mock_boto3, mock_langfuse, disabled_config):
        """Test extraction from trace with no scores."""
        exporter = LangfuseExporter(disabled_config)
        
        trace = {"id": "lf_no_scores"}
        scores = exporter._extract_scores(trace)
        
        assert scores == []

    def test_extract_scores_multiple(self, mock_boto3, mock_langfuse, disabled_config):
        """Test extraction of multiple scores."""
        exporter = LangfuseExporter(disabled_config)
        
        trace = {
            "id": "lf_multi_scores",
            "scores": [
                {"name": "quality", "value": 0.9},
                {"name": "completeness", "value": 0.8},
                {"name": "accuracy", "value": 0.85}
            ]
        }
        
        scores = exporter._extract_scores(trace)
        
        assert len(scores) == 3
        assert scores[0]["name"] == "quality"
        assert scores[1]["name"] == "completeness"
        assert scores[2]["name"] == "accuracy"

    def test_extract_scores_with_reviewer_info(self, mock_boto3, mock_langfuse, disabled_config):
        """Test extraction includes reviewer info when present."""
        exporter = LangfuseExporter(disabled_config)
        
        trace = {
            "id": "lf_reviewer_scores",
            "scores": [
                {
                    "name": "quality",
                    "value": 0.9,
                    "reviewer_id": "sme_123",
                    "reviewed_at": "2024-01-15T12:00:00"
                }
            ]
        }
        
        scores = exporter._extract_scores(trace)
        
        assert scores[0]["reviewer_id"] == "sme_123"
        assert scores[0]["reviewed_at"] == "2024-01-15T12:00:00"


# =============================================================================
# Test _query_langfuse Method
# =============================================================================


class TestQueryLangfuse:
    """Tests for _query_langfuse method."""

    def test_query_returns_empty_when_disabled(self, mock_boto3, mock_langfuse, disabled_config):
        """Test that query returns empty list when Langfuse is disabled."""
        mock_langfuse.return_value = None  # Simulate disabled
        exporter = LangfuseExporter(disabled_config)
        exporter._langfuse = None  # Ensure it's None
        
        result = exporter._query_langfuse(ExportFilter())
        
        assert result == []

    def test_query_calls_langfuse_api(self, mock_boto3, enabled_config):
        """Test that query calls Langfuse fetch_traces API."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = []
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._query_langfuse(ExportFilter())
            
            mock_client.fetch_traces.assert_called()

    def test_query_applies_local_filters(self, mock_boto3, enabled_config, sample_trace):
        """Test that local filters are applied to results."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [
            sample_trace,
            {
                "id": "lf_other",
                "metadata": {"trace_type": "threat_statement"}
            }
        ]
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            result = exporter._query_langfuse(ExportFilter(trace_type="attack_tree"))
            
            # Only attack_tree trace should be returned
            assert len(result) == 1
            assert result[0]["id"] == "lf_trace_123"


# =============================================================================
# Test export_traces Method
# =============================================================================


class TestExportTraces:
    """Tests for export_traces method."""

    def test_export_returns_zero_counts_when_disabled(self, mock_boto3, mock_langfuse, disabled_config):
        """Test that export returns zero counts when Langfuse is disabled."""
        mock_langfuse.return_value = None
        exporter = LangfuseExporter(disabled_config)
        exporter._langfuse = None
        
        result = exporter.export_traces(ExportFilter())
        
        assert result == {"traces": 0, "ground_truth": 0}

    def test_export_regular_trace_to_traces_table(self, mock_boto3, enabled_config, sample_trace):
        """Test that regular traces are exported to traces table with TTL."""
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_trace]
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._traces_table = mock_traces_table
            exporter._gt_table = mock_gt_table
            
            result = exporter.export_traces(ExportFilter())
            
            assert result["traces"] == 1
            assert result["ground_truth"] == 0
            mock_traces_table.put_item.assert_called_once()
            
            # Verify TTL is set
            call_args = mock_traces_table.put_item.call_args
            item = call_args.kwargs["Item"]
            assert "ttl" in item

    def test_export_ground_truth_to_gt_table(self, mock_boto3, enabled_config, sample_ground_truth_trace):
        """Test that ground truth traces are exported to GT table without TTL."""
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_ground_truth_trace]
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._traces_table = mock_traces_table
            exporter._gt_table = mock_gt_table
            
            result = exporter.export_traces(ExportFilter())
            
            assert result["traces"] == 0
            assert result["ground_truth"] == 1
            mock_gt_table.put_item.assert_called_once()
            
            # Verify no TTL on ground truth
            call_args = mock_gt_table.put_item.call_args
            item = call_args.kwargs["Item"]
            assert "ttl" not in item

    def test_export_mixed_traces(self, mock_boto3, enabled_config, sample_trace, sample_ground_truth_trace):
        """Test export of mixed regular and ground truth traces."""
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_trace, sample_ground_truth_trace]
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._traces_table = mock_traces_table
            exporter._gt_table = mock_gt_table
            
            result = exporter.export_traces(ExportFilter())
            
            assert result["traces"] == 1
            assert result["ground_truth"] == 1
            mock_traces_table.put_item.assert_called_once()
            mock_gt_table.put_item.assert_called_once()


# =============================================================================
# Test TTL Handling (Requirement 7.4)
# =============================================================================


class TestTTLHandling:
    """Tests for TTL handling on non-ground-truth traces."""

    def test_ttl_set_to_90_days(self, mock_boto3, enabled_config, sample_trace):
        """Test that TTL is set to approximately 90 days (Requirement 7.4)."""
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_trace]
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._traces_table = mock_traces_table
            exporter._gt_table = mock_gt_table
            
            # Capture the time before export
            before_export = datetime.now()
            exporter.export_traces(ExportFilter())
            
            # Get the TTL from the put_item call
            call_args = mock_traces_table.put_item.call_args
            item = call_args.kwargs["Item"]
            ttl = item["ttl"]
            
            # TTL should be approximately 90 days from now
            expected_ttl = int((before_export + timedelta(days=90)).timestamp())
            
            # Allow 1 day tolerance for test execution time
            assert abs(ttl - expected_ttl) < 86400  # 86400 seconds = 1 day

    def test_ground_truth_has_no_ttl(self, mock_boto3, enabled_config, sample_ground_truth_trace):
        """Test that ground truth traces have no TTL (Requirement 7.6)."""
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_ground_truth_trace]
        mock_client.fetch_traces.return_value = mock_response
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._traces_table = mock_traces_table
            exporter._gt_table = mock_gt_table
            
            exporter.export_traces(ExportFilter())
            
            # Get the item from the put_item call
            call_args = mock_gt_table.put_item.call_args
            item = call_args.kwargs["Item"]
            
            # Ground truth should not have TTL
            assert "ttl" not in item


# =============================================================================
# Test Error Handling
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in LangfuseExporter."""

    def test_export_continues_on_single_trace_failure(self, mock_boto3, enabled_config, sample_trace):
        """Test that export continues when a single trace fails."""
        mock_traces_table = MagicMock()
        mock_gt_table = MagicMock()
        
        mock_client = MagicMock()
        
        # Create two traces
        trace1 = sample_trace.copy()
        trace1["id"] = "lf_trace_1"
        trace2 = sample_trace.copy()
        trace2["id"] = "lf_trace_2"
        
        mock_response = MagicMock()
        mock_response.data = [trace1, trace2]
        mock_client.fetch_traces.return_value = mock_response
        
        # Make first put_item fail, second succeed
        mock_traces_table.put_item.side_effect = [Exception("DynamoDB error"), None]
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            exporter._traces_table = mock_traces_table
            exporter._gt_table = mock_gt_table
            
            result = exporter.export_traces(ExportFilter())
            
            # Should have exported 1 trace (the second one)
            assert result["traces"] == 1

    def test_query_raises_on_langfuse_error(self, mock_boto3, enabled_config):
        """Test that query raises RuntimeError on Langfuse API error."""
        mock_client = MagicMock()
        mock_client.fetch_traces.side_effect = Exception("API error")
        
        with patch('threatforest.tracing.export.LangfuseExporter._init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_client
            exporter = LangfuseExporter(enabled_config)
            
            with pytest.raises(RuntimeError) as exc_info:
                exporter._query_langfuse(ExportFilter())
            
            assert "Failed to query Langfuse" in str(exc_info.value)


# =============================================================================
# Test _apply_local_filters Method
# =============================================================================


class TestApplyLocalFilters:
    """Tests for _apply_local_filters method."""

    def test_filter_by_trace_type(self, mock_boto3, mock_langfuse, disabled_config):
        """Test filtering by trace_type."""
        exporter = LangfuseExporter(disabled_config)
        
        traces = [
            {"id": "1", "metadata": {"trace_type": "attack_tree"}},
            {"id": "2", "metadata": {"trace_type": "threat_statement"}},
            {"id": "3", "metadata": {"trace_type": "attack_tree"}}
        ]
        
        result = exporter._apply_local_filters(
            traces, ExportFilter(trace_type="attack_tree")
        )
        
        assert len(result) == 2
        assert all(t["metadata"]["trace_type"] == "attack_tree" for t in result)

    def test_filter_by_review_status(self, mock_boto3, mock_langfuse, disabled_config):
        """Test filtering by review_status."""
        exporter = LangfuseExporter(disabled_config)
        
        traces = [
            {"id": "1", "metadata": {"review_status": "reviewed"}},
            {"id": "2", "metadata": {"review_status": "pending_review"}},
            {"id": "3", "metadata": {"review_status": "reviewed"}}
        ]
        
        result = exporter._apply_local_filters(
            traces, ExportFilter(review_status="reviewed")
        )
        
        assert len(result) == 2
        assert all(t["metadata"]["review_status"] == "reviewed" for t in result)

    def test_filter_ground_truth_only(self, mock_boto3, mock_langfuse, disabled_config):
        """Test filtering for ground truth candidates only."""
        exporter = LangfuseExporter(disabled_config)
        
        traces = [
            {"id": "1", "metadata": {"is_ground_truth_candidate": True}},
            {"id": "2", "metadata": {"is_ground_truth_candidate": False}},
            {"id": "3", "metadata": {}}  # No flag
        ]
        
        result = exporter._apply_local_filters(
            traces, ExportFilter(ground_truth_only=True)
        )
        
        assert len(result) == 1
        assert result[0]["id"] == "1"

    def test_filter_combined(self, mock_boto3, mock_langfuse, disabled_config):
        """Test combined filtering."""
        exporter = LangfuseExporter(disabled_config)
        
        traces = [
            {"id": "1", "metadata": {"trace_type": "attack_tree", "review_status": "reviewed"}},
            {"id": "2", "metadata": {"trace_type": "attack_tree", "review_status": "pending_review"}},
            {"id": "3", "metadata": {"trace_type": "threat_statement", "review_status": "reviewed"}}
        ]
        
        result = exporter._apply_local_filters(
            traces, ExportFilter(trace_type="attack_tree", review_status="reviewed")
        )
        
        assert len(result) == 1
        assert result[0]["id"] == "1"


# =============================================================================
# Test DEFAULT_TTL_DAYS Constant
# =============================================================================


class TestConstants:
    """Tests for LangfuseExporter constants."""

    def test_default_ttl_days_is_90(self, mock_boto3, mock_langfuse, disabled_config):
        """Test that DEFAULT_TTL_DAYS is 90."""
        exporter = LangfuseExporter(disabled_config)
        
        assert exporter.DEFAULT_TTL_DAYS == 90
