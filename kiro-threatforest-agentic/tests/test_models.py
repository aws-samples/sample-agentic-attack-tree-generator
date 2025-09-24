"""
Unit tests for ThreatForest data models.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from threatforest.models import (
    ContextInformation,
    ThreatStatement,
    AttackTree,
    AttackStep,
    TTCMapping,
    AnalysisResult,
    SeverityLevel,
    ValidationStatus,
    AttackStepType,
)


class TestContextInformation:
    """Test cases for ContextInformation model."""
    
    def test_context_information_creation(self):
        """Test basic ContextInformation model creation."""
        context = ContextInformation(
            technologies=["AWS", "Docker"],
            programming_languages=["Python", "JavaScript"],
            sector="Financial Services",
            security_objectives=["confidentiality", "integrity"],
            architecture_type="Microservices",
            compliance_frameworks=["SOC2", "PCI-DSS"],
            extracted_from=["README.md", "architecture.png"],
            validation_status=ValidationStatus.APPROVED,
            confidence_score=0.85
        )
        
        assert context.technologies == ["AWS", "Docker"]
        assert context.sector == "Financial Services"
        assert context.validation_status == ValidationStatus.APPROVED
        assert context.confidence_score == 0.85
    
    def test_invalid_security_objectives(self):
        """Test validation of security objectives."""
        with pytest.raises(ValidationError):
            ContextInformation(
                security_objectives=["invalid_objective"]
            )
    
    def test_confidence_score_validation(self):
        """Test confidence score validation."""
        with pytest.raises(ValidationError):
            ContextInformation(confidence_score=1.5)
        
        with pytest.raises(ValidationError):
            ContextInformation(confidence_score=-0.1)
    
    def test_to_dict_conversion(self):
        """Test dictionary conversion."""
        context = ContextInformation(
            technologies=["AWS"],
            programming_languages=["Python"]
        )
        data = context.to_dict()
        assert isinstance(data, dict)
        assert data["technologies"] == ["AWS"]


class TestThreatStatement:
    """Test cases for ThreatStatement model."""
    
    def test_threat_statement_creation(self):
        """Test basic ThreatStatement model creation."""
        threat = ThreatStatement(
            id="threat-001",
            severity=SeverityLevel.HIGH,
            threat_source="external threat actor",
            prerequisites="API access",
            threat_action="harvest responses",
            threat_impact="model distillation",
            impacted_assets=["LLM model"],
            impacted_goals=["confidentiality"],
            raw_statement="External threat actor with API access..."
        )
        
        assert threat.id == "threat-001"
        assert threat.severity == SeverityLevel.HIGH
        assert "LLM model" in threat.impacted_assets
        assert threat.is_high_severity()
    
    def test_invalid_impacted_goals(self):
        """Test validation of impacted goals."""
        with pytest.raises(ValidationError):
            ThreatStatement(
                id="threat-001",
                severity=SeverityLevel.HIGH,
                threat_source="actor",
                prerequisites="access",
                threat_action="action",
                threat_impact="impact",
                impacted_goals=["invalid_goal"],
                raw_statement="test"
            )
    
    def test_severity_check(self):
        """Test severity level checking."""
        high_threat = ThreatStatement(
            id="threat-001",
            severity=SeverityLevel.HIGH,
            threat_source="actor",
            prerequisites="access",
            threat_action="action",
            threat_impact="impact",
            raw_statement="test"
        )
        
        low_threat = ThreatStatement(
            id="threat-002",
            severity=SeverityLevel.LOW,
            threat_source="actor",
            prerequisites="access",
            threat_action="action",
            threat_impact="impact",
            raw_statement="test"
        )
        
        assert high_threat.is_high_severity()
        assert not low_threat.is_high_severity()


class TestAttackStep:
    """Test cases for AttackStep model."""
    
    def test_attack_step_creation(self):
        """Test basic AttackStep model creation."""
        step = AttackStep(
            id="step-001",
            description="Reconnaissance phase",
            step_type=AttackStepType.ATTACK,
            dependencies=["initial-access"],
            ttc_reference="T1595"
        )
        
        assert step.id == "step-001"
        assert step.step_type == AttackStepType.ATTACK
        assert "initial-access" in step.dependencies
        assert step.ttc_reference == "T1595"


class TestTTCMapping:
    """Test cases for TTCMapping model."""
    
    def test_ttc_mapping_creation(self):
        """Test basic TTCMapping model creation."""
        mapping = TTCMapping(
            attack_step_id="step-001",
            ttc_technique_id="T1595",
            ttc_technique_name="Active Scanning",
            alignment_score=0.85,
            stix_data={"type": "attack-pattern"},
            applied=True
        )
        
        assert mapping.attack_step_id == "step-001"
        assert mapping.alignment_score == 0.85
        assert mapping.applied
        assert mapping.is_strong_alignment()
    
    def test_alignment_score_validation(self):
        """Test alignment score validation."""
        with pytest.raises(ValidationError):
            TTCMapping(
                attack_step_id="step-001",
                ttc_technique_id="T1595",
                ttc_technique_name="Active Scanning",
                alignment_score=1.5
            )
    
    def test_strong_alignment_check(self):
        """Test strong alignment threshold checking."""
        strong_mapping = TTCMapping(
            attack_step_id="step-001",
            ttc_technique_id="T1595",
            ttc_technique_name="Active Scanning",
            alignment_score=0.85
        )
        
        weak_mapping = TTCMapping(
            attack_step_id="step-002",
            ttc_technique_id="T1596",
            ttc_technique_name="Search Open Websites",
            alignment_score=0.75
        )
        
        assert strong_mapping.is_strong_alignment()
        assert not weak_mapping.is_strong_alignment()


class TestAttackTree:
    """Test cases for AttackTree model."""
    
    def test_attack_tree_creation(self):
        """Test basic AttackTree model creation."""
        step = AttackStep(
            id="step-001",
            description="Initial access",
            step_type=AttackStepType.ATTACK
        )
        
        tree = AttackTree(
            threat_id="threat-001",
            title="Test Attack Tree",
            mermaid_content="graph TD\n  A --> B",
            attack_steps=[step]
        )
        
        assert tree.threat_id == "threat-001"
        assert tree.title == "Test Attack Tree"
        assert len(tree.attack_steps) == 1
    
    def test_get_step_by_id(self):
        """Test getting attack step by ID."""
        step1 = AttackStep(
            id="step-001",
            description="Step 1",
            step_type=AttackStepType.ATTACK
        )
        step2 = AttackStep(
            id="step-002",
            description="Step 2",
            step_type=AttackStepType.GOAL
        )
        
        tree = AttackTree(
            threat_id="threat-001",
            title="Test Tree",
            mermaid_content="test",
            attack_steps=[step1, step2]
        )
        
        found_step = tree.get_step_by_id("step-001")
        assert found_step is not None
        assert found_step.description == "Step 1"
        
        not_found = tree.get_step_by_id("step-999")
        assert not_found is None
    
    def test_ttc_mapping_operations(self):
        """Test TTC mapping operations."""
        tree = AttackTree(
            threat_id="threat-001",
            title="Test Tree",
            mermaid_content="test"
        )
        
        mapping = TTCMapping(
            attack_step_id="step-001",
            ttc_technique_id="T1595",
            ttc_technique_name="Active Scanning",
            alignment_score=0.85
        )
        
        tree.add_ttc_mapping(mapping)
        assert "step-001" in tree.ttc_mappings
        
        high_confidence = tree.get_high_confidence_mappings()
        assert len(high_confidence) == 1
        assert high_confidence[0].alignment_score == 0.85


class TestAnalysisResult:
    """Test cases for AnalysisResult model."""
    
    def test_analysis_result_creation(self):
        """Test basic AnalysisResult model creation."""
        context = ContextInformation()
        
        threat = ThreatStatement(
            id="threat-001",
            severity=SeverityLevel.HIGH,
            threat_source="actor",
            prerequisites="access",
            threat_action="action",
            threat_impact="impact",
            raw_statement="test"
        )
        
        tree = AttackTree(
            threat_id="threat-001",
            title="Test Tree",
            mermaid_content="test"
        )
        
        result = AnalysisResult(
            context_info=context,
            threat_statements=[threat],
            attack_trees=[tree],
            source_directory="/test/source",
            output_directory="/test/output"
        )
        
        assert result.source_directory == "/test/source"
        assert len(result.threat_statements) == 1
        assert result.get_attack_tree_count() == 1
    
    def test_high_severity_threats_filter(self):
        """Test filtering high-severity threats."""
        context = ContextInformation()
        
        high_threat = ThreatStatement(
            id="threat-001",
            severity=SeverityLevel.HIGH,
            threat_source="actor",
            prerequisites="access",
            threat_action="action",
            threat_impact="impact",
            raw_statement="test"
        )
        
        low_threat = ThreatStatement(
            id="threat-002",
            severity=SeverityLevel.LOW,
            threat_source="actor",
            prerequisites="access",
            threat_action="action",
            threat_impact="impact",
            raw_statement="test"
        )
        
        result = AnalysisResult(
            context_info=context,
            threat_statements=[high_threat, low_threat],
            source_directory="/test",
            output_directory="/test"
        )
        
        high_severity_threats = result.get_high_severity_threats()
        assert len(high_severity_threats) == 1
        assert high_severity_threats[0].id == "threat-001"