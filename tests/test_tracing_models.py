"""
Unit Tests for ThreatForest Tracing Data Models

This module tests the Pydantic data models used for tracing ThreatForest workflows,
including input/output models, score models, and Langfuse Dataset item schemas.
"""

from datetime import datetime

import pytest

from threatforest.tracing.models import (
    AttackTreeInput,
    AttackTreeOutput,
    AutomatedMetrics,
    DatasetItem,
    DatasetItemMetadata,
    EvaluationCriteria,
    GenerationMetadata,
    SMEScore,
    ThreatStatementInput,
    ThreatStatementOutput,
    TraceStatus,
    TraceType,
    TTPMapping,
    TTPMatchingInput,
    TTPMatchingOutput,
)


class TestTraceTypeEnum:
    """Tests for TraceType enum."""

    def test_trace_type_values(self):
        """Test that TraceType has the expected values."""
        assert TraceType.THREAT_STATEMENT.value == "threat_statement"
        assert TraceType.ATTACK_TREE.value == "attack_tree"
        assert TraceType.TTP_MATCHING.value == "ttp_matching"

    def test_trace_type_is_string_enum(self):
        """Test that TraceType values can be used as strings."""
        assert TraceType.THREAT_STATEMENT == "threat_statement"
        assert TraceType.ATTACK_TREE == "attack_tree"
        assert TraceType.TTP_MATCHING == "ttp_matching"

    def test_trace_type_from_string(self):
        """Test that TraceType can be created from string values."""
        assert TraceType("threat_statement") == TraceType.THREAT_STATEMENT
        assert TraceType("attack_tree") == TraceType.ATTACK_TREE
        assert TraceType("ttp_matching") == TraceType.TTP_MATCHING


class TestTraceStatusEnum:
    """Tests for TraceStatus enum."""

    def test_trace_status_values(self):
        """Test that TraceStatus has the expected values."""
        assert TraceStatus.PENDING_REVIEW.value == "pending_review"
        assert TraceStatus.REVIEWED.value == "reviewed"
        assert TraceStatus.GROUND_TRUTH.value == "ground_truth"

    def test_trace_status_is_string_enum(self):
        """Test that TraceStatus values can be used as strings."""
        assert TraceStatus.PENDING_REVIEW == "pending_review"
        assert TraceStatus.REVIEWED == "reviewed"
        assert TraceStatus.GROUND_TRUTH == "ground_truth"


class TestGenerationMetadata:
    """Tests for GenerationMetadata model."""

    def test_required_fields(self):
        """Test that required fields must be provided."""
        metadata = GenerationMetadata(
            model_id="anthropic.claude-3-sonnet",
            latency_ms=1500
        )
        assert metadata.model_id == "anthropic.claude-3-sonnet"
        assert metadata.latency_ms == 1500

    def test_optional_fields_default_to_none(self):
        """Test that optional fields default to None."""
        metadata = GenerationMetadata(
            model_id="test-model",
            latency_ms=100
        )
        assert metadata.prompt_version is None
        assert metadata.input_tokens is None
        assert metadata.output_tokens is None
        assert metadata.temperature is None

    def test_all_fields(self):
        """Test creating metadata with all fields."""
        metadata = GenerationMetadata(
            model_id="anthropic.claude-3-sonnet",
            prompt_version="v1.2.0",
            latency_ms=1500,
            input_tokens=500,
            output_tokens=200,
            temperature=0.7
        )
        assert metadata.model_id == "anthropic.claude-3-sonnet"
        assert metadata.prompt_version == "v1.2.0"
        assert metadata.latency_ms == 1500
        assert metadata.input_tokens == 500
        assert metadata.output_tokens == 200
        assert metadata.temperature == 0.7

    def test_serialization(self):
        """Test that metadata can be serialized to dict."""
        metadata = GenerationMetadata(
            model_id="test-model",
            latency_ms=100,
            input_tokens=50
        )
        data = metadata.model_dump()
        assert data["model_id"] == "test-model"
        assert data["latency_ms"] == 100
        assert data["input_tokens"] == 50


class TestThreatStatementModels:
    """Tests for ThreatStatementInput and ThreatStatementOutput models."""

    def test_input_required_fields(self):
        """Test ThreatStatementInput with required fields."""
        input_data = ThreatStatementInput(
            mode="generate_new",
            context={"application_type": "web_api"}
        )
        assert input_data.mode == "generate_new"
        assert input_data.context == {"application_type": "web_api"}
        assert input_data.provided_threats is None

    def test_input_with_provided_threats(self):
        """Test ThreatStatementInput with provided threats."""
        threats = [{"id": "T1", "description": "SQL Injection"}]
        input_data = ThreatStatementInput(
            mode="validate_existing",
            context={"database": "postgresql"},
            provided_threats=threats
        )
        assert input_data.provided_threats == threats

    def test_output_model(self):
        """Test ThreatStatementOutput model."""
        output = ThreatStatementOutput(
            generated_threats=[
                {"id": "T1", "description": "SQL Injection"},
                {"id": "T2", "description": "XSS"}
            ],
            threat_count=2
        )
        assert len(output.generated_threats) == 2
        assert output.threat_count == 2


class TestAttackTreeModels:
    """Tests for AttackTreeInput and AttackTreeOutput models."""

    def test_input_model(self):
        """Test AttackTreeInput model."""
        input_data = AttackTreeInput(
            threat_statement={"id": "T1", "description": "SQL Injection"},
            context={"database": "postgresql", "framework": "django"}
        )
        assert input_data.threat_statement["id"] == "T1"
        assert input_data.context["database"] == "postgresql"

    def test_output_model(self):
        """Test AttackTreeOutput model."""
        output = AttackTreeOutput(
            attack_tree_markdown="# Root Attack\n## Step 1\n- Sub-step 1.1",
            parsed_structure={
                "nodes": ["Root Attack", "Step 1", "Sub-step 1.1"],
                "edges": [(0, 1), (1, 2)]
            }
        )
        assert "# Root Attack" in output.attack_tree_markdown
        assert len(output.parsed_structure["nodes"]) == 3


class TestAutomatedMetrics:
    """Tests for AutomatedMetrics model."""

    def test_required_fields(self):
        """Test AutomatedMetrics with required fields."""
        metrics = AutomatedMetrics(
            structural={"node_count": 10, "max_depth": 3},
            phase_coverage={"coverage_score": 0.75}
        )
        assert metrics.structural["node_count"] == 10
        assert metrics.phase_coverage["coverage_score"] == 0.75
        assert metrics.technique_detection is None

    def test_with_technique_detection(self):
        """Test AutomatedMetrics with technique detection."""
        metrics = AutomatedMetrics(
            structural={"node_count": 5},
            phase_coverage={"coverage_score": 0.5},
            technique_detection={
                "mitre_techniques_found": ["T1059", "T1003"],
                "technique_count": 2
            }
        )
        assert metrics.technique_detection["technique_count"] == 2


class TestTTPMatchingModels:
    """Tests for TTPMatchingInput, TTPMapping, and TTPMatchingOutput models."""

    def test_input_with_defaults(self):
        """Test TTPMatchingInput with default values."""
        input_data = TTPMatchingInput(
            attack_step={"node_id": "1", "label": "Execute PowerShell"}
        )
        assert input_data.attack_matrix == "mitre_attack_enterprise"
        assert input_data.context is None

    def test_input_with_all_fields(self):
        """Test TTPMatchingInput with all fields."""
        input_data = TTPMatchingInput(
            attack_step={"node_id": "1", "label": "Execute PowerShell", "node_type": "action"},
            attack_matrix="mitre_attack_ics",
            context={"environment": "industrial"}
        )
        assert input_data.attack_matrix == "mitre_attack_ics"
        assert input_data.context["environment"] == "industrial"

    def test_ttp_mapping(self):
        """Test TTPMapping model."""
        mapping = TTPMapping(
            rank=1,
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            tactic_id="TA0002",
            confidence=0.95,
            embedding_similarity=0.92,
            explanation="High similarity to PowerShell execution patterns"
        )
        assert mapping.rank == 1
        assert mapping.technique_id == "T1059.001"
        assert mapping.confidence == 0.95
        assert mapping.explanation is not None

    def test_ttp_mapping_without_explanation(self):
        """Test TTPMapping without optional explanation."""
        mapping = TTPMapping(
            rank=2,
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="Credential Access",
            tactic_id="TA0006",
            confidence=0.85,
            embedding_similarity=0.80
        )
        assert mapping.explanation is None

    def test_output_model(self):
        """Test TTPMatchingOutput model."""
        mappings = [
            TTPMapping(
                rank=1,
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                tactic_id="TA0002",
                confidence=0.95,
                embedding_similarity=0.92
            ),
            TTPMapping(
                rank=2,
                technique_id="T1059.003",
                technique_name="Windows Command Shell",
                tactic="Execution",
                tactic_id="TA0002",
                confidence=0.80,
                embedding_similarity=0.78
            )
        ]
        output = TTPMatchingOutput(mappings=mappings, top_k=3)
        assert len(output.mappings) == 2
        assert output.top_k == 3

    def test_output_default_top_k(self):
        """Test TTPMatchingOutput default top_k value."""
        output = TTPMatchingOutput(mappings=[])
        assert output.top_k == 3


class TestSMEScore:
    """Tests for SMEScore model."""

    def test_required_fields(self):
        """Test SMEScore with required fields only."""
        score = SMEScore(name="overall_quality", value=0.85)
        assert score.name == "overall_quality"
        assert score.value == 0.85
        assert score.comment is None
        assert score.reviewer_id is None
        assert score.reviewed_at is None

    def test_all_fields(self):
        """Test SMEScore with all fields."""
        review_time = datetime.now()
        score = SMEScore(
            name="technical_accuracy",
            value=0.9,
            comment="Excellent technical detail",
            reviewer_id="sme_user_123",
            reviewed_at=review_time
        )
        assert score.name == "technical_accuracy"
        assert score.value == 0.9
        assert score.comment == "Excellent technical detail"
        assert score.reviewer_id == "sme_user_123"
        assert score.reviewed_at == review_time

    def test_score_value_range(self):
        """Test that score values can be any float (validation is external)."""
        score = SMEScore(name="test", value=0.0)
        assert score.value == 0.0
        
        score = SMEScore(name="test", value=1.0)
        assert score.value == 1.0


class TestEvaluationCriteria:
    """Tests for EvaluationCriteria model."""

    def test_all_fields_optional(self):
        """Test that all fields in EvaluationCriteria are optional."""
        criteria = EvaluationCriteria()
        assert criteria.structural is None
        assert criteria.required_phases is None
        assert criteria.required_techniques is None
        assert criteria.forbidden_patterns is None
        assert criteria.key_attack_paths is None
        assert criteria.domain_requirements is None

    def test_structural_criteria(self):
        """Test EvaluationCriteria with structural requirements."""
        criteria = EvaluationCriteria(
            structural={
                "min_nodes": 5,
                "min_paths": 2,
                "max_depth": 4,
                "branching_factor_min": 1.5
            }
        )
        assert criteria.structural["min_nodes"] == 5
        assert criteria.structural["min_paths"] == 2
        assert criteria.structural["max_depth"] == 4
        assert criteria.structural["branching_factor_min"] == 1.5

    def test_required_phases(self):
        """Test EvaluationCriteria with required phases."""
        criteria = EvaluationCriteria(
            required_phases=["initial_access", "execution", "persistence", "exfiltration"]
        )
        assert len(criteria.required_phases) == 4
        assert "initial_access" in criteria.required_phases
        assert "execution" in criteria.required_phases

    def test_required_techniques(self):
        """Test EvaluationCriteria with required techniques."""
        techniques = [
            {"technique_id": "T1059", "tactic": "execution", "name": "Command and Scripting Interpreter"},
            {"technique_id": "T1003", "tactic": "credential_access", "name": "OS Credential Dumping"},
            {"technique_id": "T1078", "tactic": "persistence", "name": "Valid Accounts"}
        ]
        criteria = EvaluationCriteria(required_techniques=techniques)
        assert len(criteria.required_techniques) == 3
        assert criteria.required_techniques[0]["technique_id"] == "T1059"
        assert criteria.required_techniques[1]["tactic"] == "credential_access"

    def test_forbidden_patterns(self):
        """Test EvaluationCriteria with forbidden patterns."""
        criteria = EvaluationCriteria(
            forbidden_patterns=[
                "UNKNOWN_TECHNIQUE",
                "TODO",
                "PLACEHOLDER",
                "hallucinated_technique_*"
            ]
        )
        assert len(criteria.forbidden_patterns) == 4
        assert "UNKNOWN_TECHNIQUE" in criteria.forbidden_patterns
        assert "TODO" in criteria.forbidden_patterns

    def test_key_attack_paths(self):
        """Test EvaluationCriteria with key attack paths."""
        criteria = EvaluationCriteria(
            key_attack_paths=[
                "phishing -> execution -> persistence",
                "exploit_public_app -> lateral_movement -> data_exfiltration",
                "supply_chain_compromise -> code_execution"
            ]
        )
        assert len(criteria.key_attack_paths) == 3
        assert "phishing -> execution -> persistence" in criteria.key_attack_paths

    def test_domain_requirements(self):
        """Test EvaluationCriteria with domain requirements."""
        criteria = EvaluationCriteria(
            domain_requirements={
                "industry": "healthcare",
                "compliance": ["HIPAA", "HITECH"],
                "data_sensitivity": "high",
                "threat_actor_profile": "nation_state"
            }
        )
        assert criteria.domain_requirements["industry"] == "healthcare"
        assert "HIPAA" in criteria.domain_requirements["compliance"]
        assert criteria.domain_requirements["data_sensitivity"] == "high"

    def test_serialization_to_dict(self):
        """Test that EvaluationCriteria can be serialized to dict."""
        criteria = EvaluationCriteria(
            structural={"min_nodes": 5},
            required_phases=["initial_access"],
            forbidden_patterns=["TODO"]
        )
        data = criteria.model_dump()
        
        assert data["structural"] == {"min_nodes": 5}
        assert data["required_phases"] == ["initial_access"]
        assert data["forbidden_patterns"] == ["TODO"]
        assert data["required_techniques"] is None
        assert data["key_attack_paths"] is None
        assert data["domain_requirements"] is None


class TestDatasetItemMetadata:
    """Tests for DatasetItemMetadata model."""

    def test_required_fields(self):
        """Test DatasetItemMetadata with required fields."""
        metadata = DatasetItemMetadata(
            langfuse_trace_id="lf_trace_123",
            trace_type="attack_tree"
        )
        assert metadata.langfuse_trace_id == "lf_trace_123"
        assert metadata.trace_type == "attack_tree"
        assert metadata.review_status == "pending_review"  # Default
        assert metadata.is_ground_truth_candidate is False  # Default
        assert metadata.scores == []  # Default

    def test_all_fields(self):
        """Test DatasetItemMetadata with all fields."""
        metadata = DatasetItemMetadata(
            langfuse_trace_id="lf_trace_123",
            trace_type="attack_tree",
            session_id="session_456",
            created_at="2024-01-15T10:30:00",
            review_status="reviewed",
            generation_metadata={"model_id": "claude-3", "latency_ms": 1500},
            scores=[{"name": "quality", "value": 0.85}],
            is_ground_truth_candidate=True,
            evaluation_criteria={"min_nodes": 5}
        )
        assert metadata.session_id == "session_456"
        assert metadata.created_at == "2024-01-15T10:30:00"
        assert metadata.review_status == "reviewed"
        assert metadata.generation_metadata["model_id"] == "claude-3"
        assert len(metadata.scores) == 1
        assert metadata.is_ground_truth_candidate is True
        assert metadata.evaluation_criteria["min_nodes"] == 5


class TestDatasetItem:
    """Tests for DatasetItem model."""

    def test_required_fields(self):
        """Test DatasetItem with required fields."""
        metadata = DatasetItemMetadata(
            langfuse_trace_id="lf_trace_123",
            trace_type="attack_tree"
        )
        item = DatasetItem(
            input={"threat_statement": {"id": "T1", "description": "SQL Injection"}},
            expected_output={"attack_tree_markdown": "# Attack Tree"},
            metadata=metadata
        )
        assert item.input["threat_statement"]["id"] == "T1"
        assert item.expected_output["attack_tree_markdown"] == "# Attack Tree"
        assert item.metadata.langfuse_trace_id == "lf_trace_123"

    def test_serialization(self):
        """Test that DatasetItem can be serialized to dict."""
        metadata = DatasetItemMetadata(
            langfuse_trace_id="lf_trace_123",
            trace_type="attack_tree",
            review_status="reviewed"
        )
        item = DatasetItem(
            input={"test": "input"},
            expected_output={"test": "output"},
            metadata=metadata
        )
        data = item.model_dump()
        
        assert data["input"] == {"test": "input"}
        assert data["expected_output"] == {"test": "output"}
        assert data["metadata"]["langfuse_trace_id"] == "lf_trace_123"
        assert data["metadata"]["trace_type"] == "attack_tree"


class TestModelImports:
    """Tests to verify all models can be imported from the tracing module."""

    def test_import_from_tracing_module(self):
        """Test that all models can be imported from threatforest.tracing."""
        from threatforest.tracing import (
            AttackTreeInput,
            AttackTreeOutput,
            AutomatedMetrics,
            DatasetItem,
            DatasetItemMetadata,
            EvaluationCriteria,
            GenerationMetadata,
            SMEScore,
            ThreatStatementInput,
            ThreatStatementOutput,
            TraceStatus,
            TraceType,
            TTPMapping,
            TTPMatchingInput,
            TTPMatchingOutput,
        )
        
        # Verify they are the correct types
        assert TraceType.ATTACK_TREE.value == "attack_tree"
        assert TraceStatus.PENDING_REVIEW.value == "pending_review"
