"""
Unit Tests for LangfuseDatasetExporter Class

This module tests the LangfuseDatasetExporter class used for exporting scored traces
from Langfuse to Langfuse Datasets for evaluation.

Requirements:
- 7.1: THE Export_Pipeline SHALL query Langfuse API for traces with specified
       review_status and date_range filters
- 7.3: THE Export_Pipeline SHALL support filtering by trace_type:
       threat_statement, attack_tree, ttp_matching
- 7.5: THE Export_Pipeline SHALL preserve langfuse_trace_id for cross-reference
"""

from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.export import ExportFilter, LangfuseDatasetExporter


# =============================================================================
# Fixtures
# =============================================================================


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
            "evaluation_criteria": {"min_nodes": 5}
        },
        "scores": [
            {"name": "overall_quality", "value": 0.95}
        ]
    }


# =============================================================================
# Test LangfuseDatasetExporter Initialization
# =============================================================================


class TestLangfuseDatasetExporterInit:
    """Tests for LangfuseDatasetExporter initialization."""

    def test_init_with_disabled_config(self, disabled_config):
        """Test initialization with disabled Langfuse config."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = None
            exporter = LangfuseDatasetExporter(disabled_config)
            
            assert exporter._langfuse is None
            assert exporter._config == disabled_config

    def test_init_with_enabled_config(self, enabled_config):
        """Test initialization with enabled Langfuse config."""
        mock_langfuse_instance = MagicMock()
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse') as mock_init_lf:
            mock_init_lf.return_value = mock_langfuse_instance
            exporter = LangfuseDatasetExporter(enabled_config)
            
            assert exporter._langfuse == mock_langfuse_instance

    def test_init_with_invalid_enabled_config_raises_error(self):
        """Test that invalid enabled config raises ValueError."""
        invalid_config = LangfuseConfig(enabled=True, public_key=None, secret_key=None)
        
        with pytest.raises(ValueError) as exc_info:
            LangfuseDatasetExporter(invalid_config)
        
        assert "credentials are missing" in str(exc_info.value)


# =============================================================================
# Test _transform_to_dataset_item Method
# =============================================================================


class TestTransformToDatasetItem:
    """Tests for _transform_to_dataset_item method."""

    def test_transform_includes_input(self, disabled_config, sample_trace):
        """Test that input is included in dataset item."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert result["input"] == sample_trace["input"]

    def test_transform_includes_expected_output(self, disabled_config, sample_trace):
        """Test that output becomes expected_output in dataset item."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert result["expected_output"] == sample_trace["output"]

    def test_transform_preserves_langfuse_trace_id(self, disabled_config, sample_trace):
        """Test that langfuse_trace_id is preserved in metadata (Requirement 7.5)."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert result["metadata"]["langfuse_trace_id"] == "lf_trace_123"

    def test_transform_includes_trace_type(self, disabled_config, sample_trace):
        """Test that trace_type is included in metadata."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert result["metadata"]["trace_type"] == "attack_tree"

    def test_transform_includes_review_status(self, disabled_config, sample_trace):
        """Test that review_status is included in metadata."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert result["metadata"]["review_status"] == "reviewed"

    def test_transform_includes_scores(self, disabled_config, sample_trace):
        """Test that scores are included in metadata."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert len(result["metadata"]["scores"]) == 1
            assert result["metadata"]["scores"][0]["name"] == "overall_quality"
            assert result["metadata"]["scores"][0]["value"] == 0.85

    def test_transform_includes_generation_metadata(self, disabled_config, sample_trace):
        """Test that generation_metadata is included."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_trace)
            
            assert result["metadata"]["generation_metadata"] == {"model_id": "claude-3", "latency_ms": 1500}

    def test_transform_handles_missing_metadata(self, disabled_config):
        """Test transformation handles trace with missing metadata."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            trace = {
                "id": "lf_trace_minimal",
                "timestamp": "2024-01-15T10:00:00",
                "session_id": "session_min"
            }
            
            result = exporter._transform_to_dataset_item(trace)
            
            assert result["metadata"]["trace_type"] == "unknown"
            assert result["metadata"]["review_status"] == "pending_review"

    def test_transform_handles_datetime_timestamp(self, disabled_config):
        """Test transformation handles datetime object as timestamp."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            trace = {
                "id": "lf_trace_dt",
                "timestamp": datetime(2024, 1, 15, 10, 30, 0),
                "session_id": "session_dt",
                "metadata": {"trace_type": "threat_statement"}
            }
            
            result = exporter._transform_to_dataset_item(trace)
            
            assert result["metadata"]["created_at"] == "2024-01-15T10:30:00"

    def test_transform_includes_ground_truth_flag(self, disabled_config, sample_ground_truth_trace):
        """Test that is_ground_truth_candidate is included."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_ground_truth_trace)
            
            assert result["metadata"]["is_ground_truth_candidate"] is True

    def test_transform_includes_evaluation_criteria(self, disabled_config, sample_ground_truth_trace):
        """Test that evaluation_criteria is included."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._transform_to_dataset_item(sample_ground_truth_trace)
            
            assert result["metadata"]["evaluation_criteria"] == {"min_nodes": 5}


# =============================================================================
# Test _extract_scores Method
# =============================================================================


class TestExtractScores:
    """Tests for _extract_scores method."""

    def test_extract_scores_basic(self, disabled_config, sample_trace):
        """Test basic score extraction."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            scores = exporter._extract_scores(sample_trace)
            
            assert len(scores) == 1
            assert scores[0]["name"] == "overall_quality"
            assert scores[0]["value"] == 0.85
            assert scores[0]["comment"] == "Good quality"

    def test_extract_scores_empty(self, disabled_config):
        """Test extraction from trace with no scores."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            trace = {"id": "lf_no_scores"}
            scores = exporter._extract_scores(trace)
            
            assert scores == []

    def test_extract_scores_multiple(self, disabled_config):
        """Test extraction of multiple scores."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
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

    def test_extract_scores_with_reviewer_info(self, disabled_config):
        """Test extraction includes reviewer info when present."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
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

    def test_query_returns_empty_when_disabled(self, disabled_config):
        """Test that query returns empty list when Langfuse is disabled."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter._query_langfuse(ExportFilter())
            
            assert result == []

    def test_query_calls_langfuse_api(self, enabled_config):
        """Test that query calls Langfuse fetch_traces API."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = []
        mock_client.fetch_traces.return_value = mock_response
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            exporter._query_langfuse(ExportFilter())
            
            mock_client.fetch_traces.assert_called()

    def test_query_applies_local_filters(self, enabled_config, sample_trace):
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
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter._query_langfuse(ExportFilter(trace_type="attack_tree"))
            
            # Only attack_tree trace should be returned
            assert len(result) == 1
            assert result[0]["id"] == "lf_trace_123"


# =============================================================================
# Test export_to_dataset Method
# =============================================================================


class TestExportToDataset:
    """Tests for export_to_dataset method."""

    def test_export_returns_zero_counts_when_disabled(self, disabled_config):
        """Test that export returns zero counts when Langfuse is disabled."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            result = exporter.export_to_dataset(ExportFilter(), "test-dataset")
            
            assert result["items_created"] == 0
            assert result["total_traces"] == 0

    def test_export_creates_dataset_items(self, enabled_config, sample_trace):
        """Test that export creates dataset items."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_trace]
        mock_client.fetch_traces.return_value = mock_response
        mock_client.get_dataset.return_value = MagicMock()
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.export_to_dataset(ExportFilter(), "test-dataset")
            
            assert result["items_created"] == 1
            assert result["total_traces"] == 1
            mock_client.create_dataset_item.assert_called_once()

    def test_export_creates_dataset_if_not_exists(self, enabled_config, sample_trace):
        """Test that export creates dataset if it doesn't exist."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [sample_trace]
        mock_client.fetch_traces.return_value = mock_response
        mock_client.get_dataset.side_effect = Exception("Dataset not found")
        mock_client.create_dataset.return_value = MagicMock()
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.export_to_dataset(ExportFilter(), "new-dataset")
            
            mock_client.create_dataset.assert_called_once()
            assert result["items_created"] == 1

    def test_export_handles_item_creation_failure(self, enabled_config, sample_trace):
        """Test that export continues when a single item fails."""
        mock_client = MagicMock()
        
        # Create two traces
        trace1 = sample_trace.copy()
        trace1["id"] = "lf_trace_1"
        trace2 = sample_trace.copy()
        trace2["id"] = "lf_trace_2"
        
        mock_response = MagicMock()
        mock_response.data = [trace1, trace2]
        mock_client.fetch_traces.return_value = mock_response
        mock_client.get_dataset.return_value = MagicMock()
        
        # Make first create_dataset_item fail, second succeed
        mock_client.create_dataset_item.side_effect = [Exception("API error"), None]
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.export_to_dataset(ExportFilter(), "test-dataset")
            
            # Should have created 1 item (the second one)
            assert result["items_created"] == 1
            assert result["items_skipped"] == 1


# =============================================================================
# Test _apply_local_filters Method
# =============================================================================


class TestApplyLocalFilters:
    """Tests for _apply_local_filters method."""

    def test_filter_by_trace_type(self, disabled_config):
        """Test filtering by trace_type."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
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

    def test_filter_by_review_status(self, disabled_config):
        """Test filtering by review_status."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
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

    def test_filter_ground_truth_only(self, disabled_config):
        """Test filtering for ground truth candidates only."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            
            traces = [
                {"id": "1", "metadata": {"is_ground_truth_candidate": True}},
                {"id": "2", "metadata": {"is_ground_truth_candidate": False}},
                {"id": "3", "metadata": {}}  # No flag = False
            ]
            
            result = exporter._apply_local_filters(
                traces, ExportFilter(ground_truth_only=True)
            )
            
            assert len(result) == 1
            assert result[0]["id"] == "1"


# =============================================================================
# Test Error Handling
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in LangfuseDatasetExporter."""

    def test_query_raises_on_langfuse_error(self, enabled_config):
        """Test that query raises RuntimeError on Langfuse API error."""
        mock_client = MagicMock()
        mock_client.fetch_traces.side_effect = Exception("API error")
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            
            with pytest.raises(RuntimeError) as exc_info:
                exporter._query_langfuse(ExportFilter())
            
            assert "Failed to query Langfuse" in str(exc_info.value)

    def test_create_dataset_raises_on_error(self, enabled_config):
        """Test that create_dataset raises RuntimeError on error."""
        mock_client = MagicMock()
        mock_client.create_dataset.side_effect = Exception("API error")
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            
            with pytest.raises(RuntimeError) as exc_info:
                exporter.create_dataset("test-dataset")
            
            assert "Failed to create dataset" in str(exc_info.value)


# =============================================================================
# Test Dataset Management Methods
# =============================================================================


class TestDatasetManagement:
    """Tests for dataset management methods."""

    def test_create_dataset(self, enabled_config):
        """Test creating a new dataset."""
        mock_client = MagicMock()
        mock_dataset = MagicMock()
        mock_client.create_dataset.return_value = mock_dataset
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.create_dataset("test-dataset", "Test description")
            
            mock_client.create_dataset.assert_called_once_with(
                name="test-dataset",
                description="Test description"
            )
            assert result == mock_dataset

    def test_get_or_create_dataset_existing(self, enabled_config):
        """Test getting an existing dataset."""
        mock_client = MagicMock()
        mock_dataset = MagicMock()
        mock_client.get_dataset.return_value = mock_dataset
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.get_or_create_dataset("existing-dataset")
            
            mock_client.get_dataset.assert_called_once_with("existing-dataset")
            mock_client.create_dataset.assert_not_called()
            assert result == mock_dataset

    def test_get_or_create_dataset_new(self, enabled_config):
        """Test creating a new dataset when it doesn't exist."""
        mock_client = MagicMock()
        mock_dataset = MagicMock()
        mock_client.get_dataset.side_effect = Exception("Not found")
        mock_client.create_dataset.return_value = mock_dataset
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.get_or_create_dataset("new-dataset", "Description")
            
            mock_client.get_dataset.assert_called_once()
            mock_client.create_dataset.assert_called_once()
            assert result == mock_dataset

    def test_list_datasets(self, enabled_config):
        """Test listing datasets."""
        mock_client = MagicMock()
        
        # Create proper mock objects with explicit attribute values
        mock_dataset1 = MagicMock()
        mock_dataset1.name = "dataset1"
        mock_dataset1.description = "First"
        
        mock_dataset2 = MagicMock()
        mock_dataset2.name = "dataset2"
        mock_dataset2.description = "Second"
        
        mock_datasets = MagicMock()
        mock_datasets.data = [mock_dataset1, mock_dataset2]
        mock_client.get_datasets.return_value = mock_datasets
        
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=mock_client):
            exporter = LangfuseDatasetExporter(enabled_config)
            result = exporter.list_datasets()
            
            assert len(result) == 2
            assert result[0]["name"] == "dataset1"
            assert result[1]["name"] == "dataset2"

    def test_list_datasets_when_disabled(self, disabled_config):
        """Test listing datasets returns empty when disabled."""
        with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
            exporter = LangfuseDatasetExporter(disabled_config)
            result = exporter.list_datasets()
            
            assert result == []
