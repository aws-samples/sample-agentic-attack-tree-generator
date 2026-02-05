"""
Unit Tests for ThreatForest Tracing Data Models

This module tests the Pydantic data models used for tracing ThreatForest workflows,
including input/output models, score models, and DynamoDB record schemas.

Requirements:
- 7.2: THE Export_Pipeline SHALL transform Langfuse trace data to the DynamoDB
       schema with PK format TRACE#{trace_type}#{trace_id}
"""

from datetime import datetime

import pytest

from threatforest.tracing.models import (
    AttackTreeInput,
    AttackTreeOutput,
    AutomatedMetrics,
    EvaluationCriteria,
    GenerationMetadata,
    GroundTruthRecord,
    SMEScore,
    ThreatStatementInput,
    ThreatStatementOutput,
    TraceRecord,
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
        # str(Enum) returns the enum name, but the value is a string
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
        # str(Enum) returns the enum name, but the value is a string
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
        # Pydantic doesn't enforce range by default - that's handled by score definitions
        score = SMEScore(name="test", value=0.0)
        assert score.value == 0.0
        
        score = SMEScore(name="test", value=1.0)
        assert score.value == 1.0


class TestTraceRecord:
    """Tests for TraceRecord model."""

    def test_required_fields(self):
        """Test TraceRecord with required fields."""
        now = datetime.now()
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz789",
            created_at=now,
            session_id="session_456",
            input={"threat_statement": {"id": "T1"}},
            output={"attack_tree_markdown": "# Root"}
        )
        assert record.PK == "TRACE#attack_tree#abc123"
        assert record.SK == "META"  # Default value
        assert record.trace_id == "abc123"
        assert record.trace_type == TraceType.ATTACK_TREE
        assert record.review_status == TraceStatus.PENDING_REVIEW  # Default
        assert record.is_ground_truth_candidate is False  # Default
        assert record.scores == []  # Default empty list
        assert record.ttl is None  # Default

    def test_pk_format_threat_statement(self):
        """Test PK format for threat statement traces."""
        record = TraceRecord(
            PK="TRACE#threat_statement#ts123",
            trace_id="ts123",
            trace_type=TraceType.THREAT_STATEMENT,
            langfuse_trace_id="lf_abc",
            created_at=datetime.now(),
            session_id="session_1",
            input={"mode": "generate_new"},
            output={"threat_count": 5}
        )
        assert record.PK == "TRACE#threat_statement#ts123"
        assert record.trace_type == TraceType.THREAT_STATEMENT

    def test_pk_format_ttp_matching(self):
        """Test PK format for TTP matching traces."""
        record = TraceRecord(
            PK="TRACE#ttp_matching#ttp456",
            trace_id="ttp456",
            trace_type=TraceType.TTP_MATCHING,
            langfuse_trace_id="lf_def",
            created_at=datetime.now(),
            session_id="session_2",
            input={"attack_step": {"node_id": "1"}},
            output={"mappings": []}
        )
        assert record.PK == "TRACE#ttp_matching#ttp456"
        assert record.trace_type == TraceType.TTP_MATCHING

    def test_with_generation_metadata(self):
        """Test TraceRecord with generation metadata."""
        metadata = GenerationMetadata(
            model_id="anthropic.claude-3-sonnet",
            latency_ms=1500,
            input_tokens=500,
            output_tokens=200
        )
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz",
            created_at=datetime.now(),
            session_id="session_1",
            input={},
            output={},
            generation_metadata=metadata
        )
        assert record.generation_metadata is not None
        assert record.generation_metadata.model_id == "anthropic.claude-3-sonnet"

    def test_with_automated_metrics(self):
        """Test TraceRecord with automated metrics."""
        metrics = AutomatedMetrics(
            structural={"node_count": 10},
            phase_coverage={"coverage_score": 0.75}
        )
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz",
            created_at=datetime.now(),
            session_id="session_1",
            input={},
            output={},
            automated_metrics=metrics
        )
        assert record.automated_metrics is not None
        assert record.automated_metrics.structural["node_count"] == 10

    def test_with_scores(self):
        """Test TraceRecord with SME scores."""
        scores = [
            SMEScore(name="overall_quality", value=0.85),
            SMEScore(name="technical_accuracy", value=0.9)
        ]
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz",
            created_at=datetime.now(),
            session_id="session_1",
            input={},
            output={},
            scores=scores
        )
        assert len(record.scores) == 2
        assert record.scores[0].name == "overall_quality"

    def test_review_status_transitions(self):
        """Test different review status values."""
        base_args = {
            "PK": "TRACE#attack_tree#abc123",
            "trace_id": "abc123",
            "trace_type": TraceType.ATTACK_TREE,
            "langfuse_trace_id": "lf_xyz",
            "created_at": datetime.now(),
            "session_id": "session_1",
            "input": {},
            "output": {}
        }
        
        # Pending review (default)
        record = TraceRecord(**base_args)
        assert record.review_status == TraceStatus.PENDING_REVIEW
        
        # Reviewed
        record = TraceRecord(**base_args, review_status=TraceStatus.REVIEWED)
        assert record.review_status == TraceStatus.REVIEWED
        
        # Ground truth
        record = TraceRecord(**base_args, review_status=TraceStatus.GROUND_TRUTH)
        assert record.review_status == TraceStatus.GROUND_TRUTH

    def test_ground_truth_candidate(self):
        """Test ground truth candidate flag."""
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz",
            created_at=datetime.now(),
            session_id="session_1",
            input={},
            output={},
            is_ground_truth_candidate=True
        )
        assert record.is_ground_truth_candidate is True

    def test_ttl_field(self):
        """Test TTL field for non-ground-truth traces."""
        ttl_timestamp = 1735689600  # Some future Unix timestamp
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz",
            created_at=datetime.now(),
            session_id="session_1",
            input={},
            output={},
            ttl=ttl_timestamp
        )
        assert record.ttl == ttl_timestamp

    def test_serialization_to_dict(self):
        """Test that TraceRecord can be serialized to dict for DynamoDB."""
        now = datetime.now()
        record = TraceRecord(
            PK="TRACE#attack_tree#abc123",
            trace_id="abc123",
            trace_type=TraceType.ATTACK_TREE,
            langfuse_trace_id="lf_xyz",
            created_at=now,
            session_id="session_1",
            input={"test": "input"},
            output={"test": "output"}
        )
        data = record.model_dump()
        
        assert data["PK"] == "TRACE#attack_tree#abc123"
        assert data["SK"] == "META"
        assert data["trace_id"] == "abc123"
        assert data["trace_type"] == "attack_tree"  # Enum serialized as string
        assert data["input"] == {"test": "input"}
        assert data["output"] == {"test": "output"}


class TestModelImports:
    """Tests to verify all models can be imported from the tracing module."""

    def test_import_from_tracing_module(self):
        """Test that all models can be imported from threatforest.tracing."""
        from threatforest.tracing import (
            AttackTreeInput,
            AttackTreeOutput,
            AutomatedMetrics,
            EvaluationCriteria,
            GenerationMetadata,
            GroundTruthRecord,
            SMEScore,
            ThreatStatementInput,
            ThreatStatementOutput,
            TraceRecord,
            TraceStatus,
            TraceType,
            TTPMapping,
            TTPMatchingInput,
            TTPMatchingOutput,
        )
        
        # Verify they are the correct types
        assert TraceType.ATTACK_TREE.value == "attack_tree"
        assert TraceStatus.PENDING_REVIEW.value == "pending_review"


class TestEvaluationCriteria:
    """Tests for EvaluationCriteria model.
    
    Requirements:
    - 10.4: THE Export_Pipeline SHALL preserve SME-defined evaluation_criteria
            including required_phases, required_techniques, and forbidden_patterns
    """

    def test_all_fields_optional(self):
        """Test that all fields in EvaluationCriteria are optional."""
        from threatforest.tracing.models import EvaluationCriteria
        
        criteria = EvaluationCriteria()
        assert criteria.structural is None
        assert criteria.required_phases is None
        assert criteria.required_techniques is None
        assert criteria.forbidden_patterns is None
        assert criteria.key_attack_paths is None
        assert criteria.domain_requirements is None

    def test_structural_criteria(self):
        """Test EvaluationCriteria with structural requirements."""
        from threatforest.tracing.models import EvaluationCriteria
        
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
        from threatforest.tracing.models import EvaluationCriteria
        
        criteria = EvaluationCriteria(
            required_phases=["initial_access", "execution", "persistence", "exfiltration"]
        )
        assert len(criteria.required_phases) == 4
        assert "initial_access" in criteria.required_phases
        assert "execution" in criteria.required_phases

    def test_required_techniques(self):
        """Test EvaluationCriteria with required techniques."""
        from threatforest.tracing.models import EvaluationCriteria
        
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
        from threatforest.tracing.models import EvaluationCriteria
        
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
        from threatforest.tracing.models import EvaluationCriteria
        
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
        from threatforest.tracing.models import EvaluationCriteria
        
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

    def test_all_fields_populated(self):
        """Test EvaluationCriteria with all fields populated."""
        from threatforest.tracing.models import EvaluationCriteria
        
        criteria = EvaluationCriteria(
            structural={"min_nodes": 5, "min_paths": 2},
            required_phases=["initial_access", "execution"],
            required_techniques=[{"technique_id": "T1059", "tactic": "execution"}],
            forbidden_patterns=["UNKNOWN", "TODO"],
            key_attack_paths=["phishing -> execution"],
            domain_requirements={"industry": "finance"}
        )
        assert criteria.structural is not None
        assert criteria.required_phases is not None
        assert criteria.required_techniques is not None
        assert criteria.forbidden_patterns is not None
        assert criteria.key_attack_paths is not None
        assert criteria.domain_requirements is not None

    def test_serialization_to_dict(self):
        """Test that EvaluationCriteria can be serialized to dict."""
        from threatforest.tracing.models import EvaluationCriteria
        
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

    def test_serialization_excludes_none(self):
        """Test that serialization can exclude None values."""
        from threatforest.tracing.models import EvaluationCriteria
        
        criteria = EvaluationCriteria(
            required_phases=["initial_access"]
        )
        data = criteria.model_dump(exclude_none=True)
        
        assert "required_phases" in data
        assert "structural" not in data
        assert "required_techniques" not in data


class TestGroundTruthRecord:
    """Tests for GroundTruthRecord model.
    
    Requirements:
    - 10.2: THE Export_Pipeline SHALL export approved ground truth to
            threatforest-ground-truth table with evaluation_criteria
    - 10.3: THE Export_Pipeline SHALL support dataset versioning with
            dataset_id and split (train/eval/test) attributes
    - 10.4: THE Export_Pipeline SHALL preserve SME-defined evaluation_criteria
    """

    def test_required_fields(self):
        """Test GroundTruthRecord with required fields."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        now = datetime.now()
        criteria = EvaluationCriteria(required_phases=["initial_access"])
        
        record = GroundTruthRecord(
            PK="GT#attack_tree#gt_abc123",
            ground_truth_id="gt_abc123",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_xyz789",
            created_at=now,
            created_by="sme_user_456",
            dataset_id="dataset_v1.0",
            split="train",
            input={"threat_statement": {"id": "T1", "description": "SQL Injection"}},
            reference_output={"attack_tree_markdown": "# SQL Injection Attack Tree"},
            evaluation_criteria=criteria
        )
        
        assert record.PK == "GT#attack_tree#gt_abc123"
        assert record.SK == "META"  # Default value
        assert record.ground_truth_id == "gt_abc123"
        assert record.type == TraceType.ATTACK_TREE
        assert record.source_trace_id == "trace_xyz789"
        assert record.created_at == now
        assert record.created_by == "sme_user_456"
        assert record.dataset_id == "dataset_v1.0"
        assert record.split == "train"
        assert record.metadata == {}  # Default empty dict

    def test_pk_format_threat_statement(self):
        """Test PK format for threat statement ground truth."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        record = GroundTruthRecord(
            PK="GT#threat_statement#gt_ts123",
            ground_truth_id="gt_ts123",
            type=TraceType.THREAT_STATEMENT,
            source_trace_id="trace_ts_orig",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="threats_v2.0",
            split="eval",
            input={"mode": "generate_new", "context": {}},
            reference_output={"generated_threats": [], "threat_count": 0},
            evaluation_criteria=EvaluationCriteria()
        )
        
        assert record.PK == "GT#threat_statement#gt_ts123"
        assert record.type == TraceType.THREAT_STATEMENT

    def test_pk_format_ttp_matching(self):
        """Test PK format for TTP matching ground truth."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        record = GroundTruthRecord(
            PK="GT#ttp_matching#gt_ttp456",
            ground_truth_id="gt_ttp456",
            type=TraceType.TTP_MATCHING,
            source_trace_id="trace_ttp_orig",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="ttp_v1.0",
            split="test",
            input={"attack_step": {"node_id": "1", "label": "Execute PowerShell"}},
            reference_output={"mappings": [], "top_k": 3},
            evaluation_criteria=EvaluationCriteria()
        )
        
        assert record.PK == "GT#ttp_matching#gt_ttp456"
        assert record.type == TraceType.TTP_MATCHING

    def test_split_values(self):
        """Test different split values (train, eval, test)."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        base_args = {
            "PK": "GT#attack_tree#gt_123",
            "ground_truth_id": "gt_123",
            "type": TraceType.ATTACK_TREE,
            "source_trace_id": "trace_orig",
            "created_at": datetime.now(),
            "created_by": "sme_user",
            "dataset_id": "dataset_v1.0",
            "input": {},
            "reference_output": {},
            "evaluation_criteria": EvaluationCriteria()
        }
        
        # Train split
        record = GroundTruthRecord(**base_args, split="train")
        assert record.split == "train"
        
        # Eval split
        record = GroundTruthRecord(**base_args, split="eval")
        assert record.split == "eval"
        
        # Test split
        record = GroundTruthRecord(**base_args, split="test")
        assert record.split == "test"

    def test_with_evaluation_criteria(self):
        """Test GroundTruthRecord with full evaluation criteria."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        criteria = EvaluationCriteria(
            structural={"min_nodes": 5, "min_paths": 2},
            required_phases=["initial_access", "execution", "persistence"],
            required_techniques=[
                {"technique_id": "T1059", "tactic": "execution"},
                {"technique_id": "T1003", "tactic": "credential_access"}
            ],
            forbidden_patterns=["UNKNOWN", "TODO"],
            key_attack_paths=["phishing -> execution -> persistence"],
            domain_requirements={"industry": "finance"}
        )
        
        record = GroundTruthRecord(
            PK="GT#attack_tree#gt_123",
            ground_truth_id="gt_123",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_orig",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="dataset_v1.0",
            split="train",
            input={"threat_statement": {}},
            reference_output={"attack_tree_markdown": "# Tree"},
            evaluation_criteria=criteria
        )
        
        assert record.evaluation_criteria.structural["min_nodes"] == 5
        assert len(record.evaluation_criteria.required_phases) == 3
        assert len(record.evaluation_criteria.required_techniques) == 2
        assert "UNKNOWN" in record.evaluation_criteria.forbidden_patterns

    def test_with_metadata(self):
        """Test GroundTruthRecord with metadata."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        record = GroundTruthRecord(
            PK="GT#attack_tree#gt_123",
            ground_truth_id="gt_123",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_orig",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="dataset_v1.0",
            split="train",
            input={},
            reference_output={},
            evaluation_criteria=EvaluationCriteria(),
            metadata={
                "review_notes": "Excellent example of SQL injection attack tree",
                "quality_score": 0.95,
                "tags": ["sql_injection", "web_application"],
                "version": 2
            }
        )
        
        assert record.metadata["review_notes"] == "Excellent example of SQL injection attack tree"
        assert record.metadata["quality_score"] == 0.95
        assert "sql_injection" in record.metadata["tags"]
        assert record.metadata["version"] == 2

    def test_default_metadata_is_empty_dict(self):
        """Test that metadata defaults to empty dict."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        record = GroundTruthRecord(
            PK="GT#attack_tree#gt_123",
            ground_truth_id="gt_123",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_orig",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="dataset_v1.0",
            split="train",
            input={},
            reference_output={},
            evaluation_criteria=EvaluationCriteria()
        )
        
        assert record.metadata == {}
        assert isinstance(record.metadata, dict)

    def test_serialization_to_dict(self):
        """Test that GroundTruthRecord can be serialized to dict for DynamoDB."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        now = datetime.now()
        criteria = EvaluationCriteria(
            required_phases=["initial_access"],
            structural={"min_nodes": 3}
        )
        
        record = GroundTruthRecord(
            PK="GT#attack_tree#gt_123",
            ground_truth_id="gt_123",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_orig",
            created_at=now,
            created_by="sme_user",
            dataset_id="dataset_v1.0",
            split="train",
            input={"test": "input"},
            reference_output={"test": "output"},
            evaluation_criteria=criteria,
            metadata={"note": "test"}
        )
        
        data = record.model_dump()
        
        assert data["PK"] == "GT#attack_tree#gt_123"
        assert data["SK"] == "META"
        assert data["ground_truth_id"] == "gt_123"
        assert data["type"] == "attack_tree"  # Enum serialized as string
        assert data["source_trace_id"] == "trace_orig"
        assert data["dataset_id"] == "dataset_v1.0"
        assert data["split"] == "train"
        assert data["input"] == {"test": "input"}
        assert data["reference_output"] == {"test": "output"}
        assert data["evaluation_criteria"]["required_phases"] == ["initial_access"]
        assert data["evaluation_criteria"]["structural"] == {"min_nodes": 3}
        assert data["metadata"] == {"note": "test"}

    def test_no_ttl_field(self):
        """Test that GroundTruthRecord does not have a TTL field (ground truth is preserved indefinitely)."""
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        record = GroundTruthRecord(
            PK="GT#attack_tree#gt_123",
            ground_truth_id="gt_123",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_orig",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="dataset_v1.0",
            split="train",
            input={},
            reference_output={},
            evaluation_criteria=EvaluationCriteria()
        )
        
        # GroundTruthRecord should not have a ttl field
        assert not hasattr(record, 'ttl') or 'ttl' not in record.model_fields

    def test_dataset_versioning(self):
        """Test dataset versioning with dataset_id field.
        
        Validates Requirement 10.3: THE Export_Pipeline SHALL support dataset
        versioning with dataset_id and split (train/eval/test) attributes
        """
        from threatforest.tracing.models import (
            EvaluationCriteria,
            GroundTruthRecord,
            TraceType,
        )
        
        # Create records for different dataset versions
        v1_record = GroundTruthRecord(
            PK="GT#attack_tree#gt_v1_001",
            ground_truth_id="gt_v1_001",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_001",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="attack_trees_v1.0",
            split="train",
            input={},
            reference_output={},
            evaluation_criteria=EvaluationCriteria()
        )
        
        v2_record = GroundTruthRecord(
            PK="GT#attack_tree#gt_v2_001",
            ground_truth_id="gt_v2_001",
            type=TraceType.ATTACK_TREE,
            source_trace_id="trace_001",
            created_at=datetime.now(),
            created_by="sme_user",
            dataset_id="attack_trees_v2.0",
            split="train",
            input={},
            reference_output={},
            evaluation_criteria=EvaluationCriteria()
        )
        
        assert v1_record.dataset_id == "attack_trees_v1.0"
        assert v2_record.dataset_id == "attack_trees_v2.0"
        assert v1_record.dataset_id != v2_record.dataset_id
