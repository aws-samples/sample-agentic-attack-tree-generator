"""
Unit tests for Attack Tree Generator Agent.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime

from threatforest.agents.attack_tree_generator import (
    AttackTreeGeneratorAgent,
    AttackPath,
    GenerationResult
)
from threatforest.models import (
    ThreatStatement,
    AttackTree,
    AttackStep,
    ContextInformation,
    AttackStepType,
    SeverityLevel
)
from threatforest.utils.bedrock_client import BedrockClient, BedrockResponse, BedrockClientError


class TestAttackPath:
    """Test cases for AttackPath."""
    
    def test_get_step_ids(self):
        """Test getting step IDs from attack path."""
        steps = [
            AttackStep(
                id="step1",
                description="desc1",
                step_type=AttackStepType.ATTACK,
                dependencies=[],
                ttc_reference=None
            ),
            AttackStep(
                id="step2",
                description="desc2",
                step_type=AttackStepType.ATTACK,
                dependencies=[],
                ttc_reference=None
            )
        ]
        
        path = AttackPath(
            steps=steps,
            path_id="path1",
            description="Test path",
            likelihood="high",
            impact="medium"
        )
        
        assert path.get_step_ids() == ["step1", "step2"]


class TestGenerationResult:
    """Test cases for GenerationResult."""
    
    def test_is_successful_true(self):
        """Test successful generation result."""
        attack_tree = AttackTree(
            threat_id="test-threat",
            title="Test Tree",
            mermaid_content="graph TD",
            attack_steps=[],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        result = GenerationResult(
            attack_tree=attack_tree,
            generation_errors=[],
            generation_warnings=[],
            skipped_reason=None,
            processing_time_seconds=1.0
        )
        
        assert result.is_successful()
    
    def test_is_successful_false_no_tree(self):
        """Test unsuccessful result with no tree."""
        result = GenerationResult(
            attack_tree=None,
            generation_errors=[],
            generation_warnings=[],
            skipped_reason=None,
            processing_time_seconds=1.0
        )
        
        assert not result.is_successful()
    
    def test_is_successful_false_with_errors(self):
        """Test unsuccessful result with errors."""
        attack_tree = AttackTree(
            threat_id="test-threat",
            title="Test Tree",
            mermaid_content="graph TD",
            attack_steps=[],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        result = GenerationResult(
            attack_tree=attack_tree,
            generation_errors=["Test error"],
            generation_warnings=[],
            skipped_reason=None,
            processing_time_seconds=1.0
        )
        
        assert not result.is_successful()


class TestAttackTreeGeneratorAgent:
    """Test cases for AttackTreeGeneratorAgent."""
    
    @pytest.fixture
    def mock_bedrock_client(self):
        """Create a mock Bedrock client."""
        return Mock(spec=BedrockClient)
    
    @pytest.fixture
    def generator_agent(self, mock_bedrock_client):
        """Create an AttackTreeGeneratorAgent instance."""
        return AttackTreeGeneratorAgent(mock_bedrock_client)
    
    @pytest.fixture
    def sample_threat_statement(self):
        """Create a sample high-severity threat statement."""
        return ThreatStatement(
            id="threat-001",
            severity=SeverityLevel.HIGH,
            threat_source="External Attacker",
            prerequisites="Network access",
            threat_action="SQL Injection Attack",
            threat_impact="Data breach",
            impacted_assets=["Database", "User Data"],
            impacted_goals=["confidentiality", "integrity"],
            raw_statement="Attacker performs SQL injection to access database"
        )
    
    @pytest.fixture
    def sample_low_severity_threat(self):
        """Create a sample low-severity threat statement."""
        return ThreatStatement(
            id="threat-002",
            severity=SeverityLevel.LOW,
            threat_source="Internal User",
            prerequisites="System access",
            threat_action="Password reuse",
            threat_impact="Account compromise",
            impacted_assets=["User Account"],
            impacted_goals=["confidentiality"],
            raw_statement="User reuses password across systems"
        )
    
    @pytest.fixture
    def sample_context_info(self):
        """Create sample context information."""
        return ContextInformation(
            technologies=["React", "Node.js", "PostgreSQL"],
            programming_languages=["JavaScript", "TypeScript"],
            sector="fintech",
            security_objectives=["confidentiality", "integrity"],
            architecture_type="microservices"
        )
    
    @pytest.fixture
    def sample_ai_response(self):
        """Sample AI response for attack tree generation."""
        return {
            "attack_goal": "Compromise database through SQL injection",
            "attack_steps": [
                {
                    "id": "recon_1",
                    "description": "Identify web application endpoints",
                    "type": "attack",
                    "dependencies": [],
                    "likelihood": "high",
                    "impact": "low"
                },
                {
                    "id": "vuln_scan",
                    "description": "Scan for SQL injection vulnerabilities",
                    "type": "attack",
                    "dependencies": ["recon_1"],
                    "likelihood": "medium",
                    "impact": "low"
                },
                {
                    "id": "exploit_sqli",
                    "description": "Execute SQL injection attack",
                    "type": "attack",
                    "dependencies": ["vuln_scan"],
                    "likelihood": "high",
                    "impact": "high"
                },
                {
                    "id": "input_validation",
                    "description": "Implement input validation",
                    "type": "mitigation",
                    "dependencies": [],
                    "likelihood": "high",
                    "impact": "high"
                }
            ],
            "attack_paths": [
                {
                    "path_id": "path_1",
                    "description": "Direct SQL injection path",
                    "steps": ["recon_1", "vuln_scan", "exploit_sqli"],
                    "likelihood": "medium",
                    "impact": "high"
                }
            ],
            "mitigations": [
                {
                    "id": "input_validation",
                    "description": "Implement input validation",
                    "effectiveness": "high",
                    "mitigates_steps": ["exploit_sqli"]
                }
            ]
        }
    
    def test_init(self, mock_bedrock_client):
        """Test agent initialization."""
        agent = AttackTreeGeneratorAgent(mock_bedrock_client)
        
        assert agent.bedrock_client == mock_bedrock_client
        assert AttackStepType.ATTACK in agent.color_scheme
        assert AttackStepType.MITIGATION in agent.color_scheme
        assert "cybersecurity expert" in agent.system_prompt.lower()
    
    def test_generate_attack_tree_success(self, generator_agent, sample_threat_statement, sample_context_info, sample_ai_response):
        """Test successful attack tree generation."""
        # Mock AI response
        mock_response = BedrockResponse(
            content=json.dumps(sample_ai_response),
            model_id="test-model",
            input_tokens=500,
            output_tokens=800
        )
        generator_agent.bedrock_client.invoke_model.return_value = mock_response
        
        # Generate attack tree
        result = generator_agent.generate_attack_tree(sample_threat_statement, sample_context_info)
        
        # Verify result
        assert result.is_successful()
        assert result.attack_tree is not None
        assert result.attack_tree.threat_id == "threat-001"
        assert len(result.attack_tree.attack_steps) == 5  # 4 from AI + 1 goal step
        assert result.skipped_reason is None
        assert len(result.generation_errors) == 0
        
        # Verify Mermaid content
        assert "graph TD" in result.attack_tree.mermaid_content
        assert "recon_1" in result.attack_tree.mermaid_content
        assert "style" in result.attack_tree.mermaid_content  # Styling should be included
    
    def test_generate_attack_tree_low_severity_skipped(self, generator_agent, sample_low_severity_threat):
        """Test that low-severity threats are skipped."""
        result = generator_agent.generate_attack_tree(sample_low_severity_threat)
        
        assert not result.is_successful()
        assert result.attack_tree is None
        assert result.skipped_reason is not None
        assert "severity is low" in result.skipped_reason
        assert len(result.generation_errors) == 0
    
    def test_generate_attack_tree_ai_error(self, generator_agent, sample_threat_statement):
        """Test handling of AI errors."""
        # Mock AI error
        generator_agent.bedrock_client.invoke_model.side_effect = BedrockClientError("API error")
        
        result = generator_agent.generate_attack_tree(sample_threat_statement)
        
        assert not result.is_successful()
        assert result.attack_tree is None
        assert len(result.generation_errors) > 0
        assert "Error generating attack tree" in result.generation_errors[0]
    
    def test_generate_attack_tree_invalid_json(self, generator_agent, sample_threat_statement):
        """Test handling of invalid JSON response."""
        # Mock invalid JSON response
        mock_response = BedrockResponse(
            content="Invalid JSON response",
            model_id="test-model",
            input_tokens=100,
            output_tokens=50
        )
        generator_agent.bedrock_client.invoke_model.return_value = mock_response
        
        result = generator_agent.generate_attack_tree(sample_threat_statement)
        
        assert not result.is_successful()
        assert result.attack_tree is None
        assert len(result.generation_errors) > 0
    
    def test_prepare_context_text(self, generator_agent, sample_threat_statement, sample_context_info):
        """Test context text preparation."""
        context_text = generator_agent._prepare_context_text(sample_threat_statement, sample_context_info)
        
        assert "Technologies: React, Node.js, PostgreSQL" in context_text
        assert "Programming Languages: JavaScript, TypeScript" in context_text
        assert "Business Sector: fintech" in context_text
        assert "Architecture: microservices" in context_text
    
    def test_prepare_context_text_no_context(self, generator_agent, sample_threat_statement):
        """Test context text preparation with no context."""
        context_text = generator_agent._prepare_context_text(sample_threat_statement, None)
        
        assert "No specific context information available" in context_text
    
    def test_validate_attack_structure_valid(self, generator_agent, sample_ai_response):
        """Test validation of valid attack structure."""
        # Should not raise exception
        generator_agent._validate_attack_structure(sample_ai_response)
    
    def test_validate_attack_structure_missing_field(self, generator_agent):
        """Test validation with missing required field."""
        invalid_structure = {"attack_goal": "Test goal"}  # Missing attack_steps
        
        with pytest.raises(ValueError, match="Missing required field: attack_steps"):
            generator_agent._validate_attack_structure(invalid_structure)
    
    def test_validate_attack_structure_invalid_steps(self, generator_agent):
        """Test validation with invalid attack steps."""
        invalid_structure = {
            "attack_goal": "Test goal",
            "attack_steps": "not a list"
        }
        
        with pytest.raises(ValueError, match="attack_steps must be a list"):
            generator_agent._validate_attack_structure(invalid_structure)
    
    def test_validate_attack_structure_empty_steps(self, generator_agent):
        """Test validation with empty attack steps."""
        invalid_structure = {
            "attack_goal": "Test goal",
            "attack_steps": []
        }
        
        with pytest.raises(ValueError, match="attack_steps cannot be empty"):
            generator_agent._validate_attack_structure(invalid_structure)
    
    def test_create_attack_steps(self, generator_agent, sample_ai_response):
        """Test creation of attack steps from AI structure."""
        attack_steps = generator_agent._create_attack_steps(sample_ai_response)
        
        # Should have goal step + AI steps
        assert len(attack_steps) == 5
        
        # First step should be the goal
        assert attack_steps[0].id == "goal_main"
        assert attack_steps[0].step_type == AttackStepType.GOAL
        assert attack_steps[0].description == sample_ai_response["attack_goal"]
        
        # Check other steps
        attack_step_ids = [step.id for step in attack_steps[1:]]
        assert "recon_1" in attack_step_ids
        assert "vuln_scan" in attack_step_ids
        assert "exploit_sqli" in attack_step_ids
        assert "input_validation" in attack_step_ids
        
        # Check step types
        mitigation_steps = [step for step in attack_steps if step.step_type == AttackStepType.MITIGATION]
        assert len(mitigation_steps) == 1
        assert mitigation_steps[0].id == "input_validation"
    
    def test_clean_mermaid_text(self, generator_agent):
        """Test cleaning text for Mermaid diagrams."""
        # Test quote replacement
        assert generator_agent._clean_mermaid_text('Text with "quotes"') == "Text with 'quotes'"
        
        # Test newline replacement
        assert generator_agent._clean_mermaid_text("Text with\nnewlines") == "Text with newlines"
        
        # Test space collapsing
        assert generator_agent._clean_mermaid_text("Text  with   spaces") == "Text with spaces"
        
        # Test truncation
        long_text = "A" * 100
        cleaned = generator_agent._clean_mermaid_text(long_text)
        assert len(cleaned) <= 80
        assert cleaned.endswith("...")
    
    def test_generate_mermaid_diagram(self, generator_agent, sample_ai_response):
        """Test Mermaid diagram generation."""
        attack_steps = generator_agent._create_attack_steps(sample_ai_response)
        mermaid_content = generator_agent._generate_mermaid_diagram(attack_steps, sample_ai_response)
        
        # Check basic structure
        assert mermaid_content.startswith("graph TD")
        
        # Check that all steps are included
        for step in attack_steps:
            assert step.id in mermaid_content
        
        # Check for styling
        assert "style" in mermaid_content
        
        # Check for connections
        assert "-->" in mermaid_content
    
    def test_generate_multiple_trees(self, generator_agent, sample_threat_statement, sample_ai_response):
        """Test generating multiple attack trees."""
        # Create multiple threat statements
        threat_statements = [
            sample_threat_statement,
            ThreatStatement(
                id="threat-003",
                severity=SeverityLevel.HIGH,
                threat_source="Insider",
                prerequisites="System access",
                threat_action="Data exfiltration",
                threat_impact="Data loss",
                impacted_assets=["Database"],
                impacted_goals=["confidentiality"],
                raw_statement="Insider exfiltrates sensitive data"
            )
        ]
        
        # Mock AI responses
        mock_response = BedrockResponse(
            content=json.dumps(sample_ai_response),
            model_id="test-model",
            input_tokens=500,
            output_tokens=800
        )
        generator_agent.bedrock_client.invoke_model.return_value = mock_response
        
        results = generator_agent.generate_multiple_trees(threat_statements)
        
        assert len(results) == 2
        assert all(result.is_successful() for result in results)
    
    def test_save_attack_tree(self, generator_agent, tmp_path):
        """Test saving attack tree to file."""
        # Create sample attack tree
        attack_tree = AttackTree(
            threat_id="test-threat-001",
            title="Test Attack Tree",
            mermaid_content="graph TD\n    A[Start] --> B[End]",
            attack_steps=[
                AttackStep(
                    id="step1",
                    description="Test step",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                )
            ],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        # Save attack tree
        output_file = generator_agent.save_attack_tree(attack_tree, str(tmp_path))
        
        # Verify file was created
        assert Path(output_file).exists()
        assert output_file.endswith(".mmd")
        
        # Verify content
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert "# Attack Tree: Test Attack Tree" in content
        assert "test-threat-001" in content
        assert "```mermaid" in content
        assert "graph TD" in content
        assert "## Attack Steps" in content
    
    def test_get_generation_statistics_empty(self, generator_agent):
        """Test statistics with empty results."""
        stats = generator_agent.get_generation_statistics([])
        
        assert stats["total"] == 0
    
    def test_get_generation_statistics(self, generator_agent):
        """Test generation statistics calculation."""
        # Create sample results
        successful_tree = AttackTree(
            threat_id="test-1",
            title="Test",
            mermaid_content="graph TD",
            attack_steps=[
                AttackStep(
                    id="s1",
                    description="desc",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                ),
                AttackStep(
                    id="s2",
                    description="desc",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                )
            ],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        results = [
            GenerationResult(successful_tree, [], [], None, 1.0),  # Successful
            GenerationResult(None, [], [], "Low severity", 0.5),   # Skipped
            GenerationResult(None, ["Error"], [], None, 2.0)       # Failed
        ]
        
        stats = generator_agent.get_generation_statistics(results)
        
        assert stats["total"] == 3
        assert stats["successful"] == 1
        assert stats["skipped"] == 1
        assert stats["failed"] == 1
        assert stats["success_rate"] == 1/3
        assert stats["total_processing_time_seconds"] == 3.5
        assert stats["average_processing_time_seconds"] == 3.5/3
        assert stats["average_steps_per_tree"] == 2.0
        assert stats["min_steps"] == 2
        assert stats["max_steps"] == 2