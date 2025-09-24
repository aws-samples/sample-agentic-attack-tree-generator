"""
Unit tests for TTC Mapping Agent.
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from threatforest.agents.ttc_mapping import (
    TTCMappingAgent,
    MappingResult
)
from threatforest.models import (
    AttackTree,
    AttackStep,
    TTCMapping,
    AttackStepType
)
from threatforest.utils.stix_processor import (
    STIXProcessor,
    STIXTechnique,
    STIXSearchResult
)


class TestMappingResult:
    """Test cases for MappingResult."""
    
    def test_get_mapping_statistics(self):
        """Test mapping statistics calculation."""
        # Create sample attack tree
        attack_tree = AttackTree(
            threat_id="test-threat",
            title="Test Tree",
            mermaid_content="graph TD",
            attack_steps=[
                AttackStep(
                    id="step1",
                    description="Test step 1",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                ),
                AttackStep(
                    id="step2",
                    description="Test step 2",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                )
            ],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        # Create sample mappings
        applied_mappings = [
            TTCMapping(
                attack_step_id="step1",
                ttc_technique_id="T1001",
                ttc_technique_name="Test Technique",
                alignment_score=0.85,
                stix_data={},
                applied=True
            )
        ]
        
        rejected_mappings = [
            TTCMapping(
                attack_step_id="step2",
                ttc_technique_id="T1002",
                ttc_technique_name="Test Technique 2",
                alignment_score=0.65,
                stix_data={},
                applied=False
            )
        ]
        
        result = MappingResult(
            enhanced_tree=attack_tree,
            applied_mappings=applied_mappings,
            rejected_mappings=rejected_mappings,
            processing_errors=[],
            processing_warnings=["Test warning"],
            processing_time_seconds=1.5
        )
        
        stats = result.get_mapping_statistics()
        
        assert stats["total_steps_processed"] == 2
        assert stats["total_mappings_found"] == 2
        assert stats["applied_mappings"] == 1
        assert stats["rejected_mappings"] == 1
        assert stats["application_rate"] == 0.5
        assert stats["average_confidence"] == 0.85
        assert stats["processing_errors"] == 0
        assert stats["processing_warnings"] == 1


class TestTTCMappingAgent:
    """Test cases for TTCMappingAgent."""
    
    @pytest.fixture
    def mock_stix_processor(self):
        """Create a mock STIX processor."""
        processor = Mock(spec=STIXProcessor)
        processor.loaded = True
        return processor
    
    @pytest.fixture
    def ttc_agent(self, mock_stix_processor):
        """Create a TTCMappingAgent instance."""
        return TTCMappingAgent(mock_stix_processor, alignment_threshold=0.8)
    
    @pytest.fixture
    def sample_attack_tree(self):
        """Create a sample attack tree."""
        return AttackTree(
            threat_id="test-threat",
            title="Test Attack Tree",
            mermaid_content="graph TD\n    step1[SQL Injection]\n    step2[Data Exfiltration]",
            attack_steps=[
                AttackStep(
                    id="step1",
                    description="Perform SQL injection attack",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                ),
                AttackStep(
                    id="step2",
                    description="Exfiltrate sensitive data",
                    step_type=AttackStepType.ATTACK,
                    dependencies=["step1"],
                    ttc_reference=None
                ),
                AttackStep(
                    id="goal1",
                    description="Compromise database",
                    step_type=AttackStepType.GOAL,
                    dependencies=[],
                    ttc_reference=None
                )
            ],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
    
    @pytest.fixture
    def sample_stix_technique(self):
        """Create a sample STIX technique."""
        return STIXTechnique(
            id="attack-pattern--test-123",
            name="SQL Injection",
            description="Adversaries may use SQL injection to compromise databases",
            technique_type="attack-pattern",
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1190",
                    "url": "https://attack.mitre.org/techniques/T1190"
                }
            ],
            kill_chain_phases=[],
            platforms=["Windows", "Linux"],
            tactics=["initial-access"],
            raw_data={}
        )
    
    def test_init(self, mock_stix_processor):
        """Test agent initialization."""
        agent = TTCMappingAgent(mock_stix_processor, alignment_threshold=0.75)
        
        assert agent.stix_processor == mock_stix_processor
        assert agent.alignment_threshold == 0.75
        assert agent._embeddings_model is None
        assert agent._model_name == "all-MiniLM-L6-v2"
    
    def test_enhance_attack_tree_stix_not_loaded(self, sample_attack_tree):
        """Test enhancement when STIX processor is not loaded."""
        mock_processor = Mock(spec=STIXProcessor)
        mock_processor.loaded = False
        
        agent = TTCMappingAgent(mock_processor)
        result = agent.enhance_attack_tree(sample_attack_tree)
        
        assert not result.applied_mappings
        assert not result.rejected_mappings
        assert len(result.processing_errors) > 0
        assert "STIX processor not loaded" in result.processing_errors[0]
    
    @patch('threatforest.agents.ttc_mapping.TTCMappingAgent._get_embeddings_model')
    def test_enhance_attack_tree_success(self, mock_get_model, ttc_agent, sample_attack_tree, sample_stix_technique):
        """Test successful attack tree enhancement."""
        # Mock sentence transformer model
        mock_model = Mock()
        mock_model.encode.return_value = np.array([[0.1, 0.2, 0.3], [0.15, 0.25, 0.35]])
        mock_get_model.return_value = mock_model
        
        # Mock STIX search results
        search_result = STIXSearchResult(
            technique=sample_stix_technique,
            relevance_score=0.8,
            matching_keywords={"sql", "injection"},
            match_reasons=["Keyword match"]
        )
        
        ttc_agent.stix_processor.search_techniques.return_value = [search_result]
        ttc_agent.stix_processor.get_technique_by_id.return_value = sample_stix_technique
        
        # Enhance attack tree
        result = ttc_agent.enhance_attack_tree(sample_attack_tree)
        
        # Verify results
        assert len(result.applied_mappings) > 0
        assert len(result.processing_errors) == 0
        assert result.processing_time_seconds > 0
        
        # Verify mapping was applied to tree
        assert len(sample_attack_tree.ttc_mappings) > 0
    
    @patch('threatforest.agents.ttc_mapping.TTCMappingAgent._calculate_semantic_similarity')
    def test_enhance_attack_tree_low_confidence(self, mock_similarity, ttc_agent, sample_attack_tree, sample_stix_technique):
        """Test enhancement with low confidence mappings."""
        # Mock low semantic similarity
        mock_similarity.return_value = 0.5  # Below threshold of 0.8
        
        # Mock STIX search results
        search_result = STIXSearchResult(
            technique=sample_stix_technique,
            relevance_score=0.3,
            matching_keywords=set(),
            match_reasons=["Low match"]
        )
        
        ttc_agent.stix_processor.search_techniques.return_value = [search_result]
        
        # Enhance attack tree
        result = ttc_agent.enhance_attack_tree(sample_attack_tree)
        
        # Should have rejected mappings due to low confidence
        assert len(result.applied_mappings) == 0
        assert len(result.rejected_mappings) > 0
        assert len(result.processing_errors) == 0
    
    def test_find_ttc_mappings_no_results(self, ttc_agent):
        """Test finding TTC mappings when no STIX techniques are found."""
        attack_step = AttackStep(
            id="test_step",
            description="Unknown attack technique",
            step_type=AttackStepType.ATTACK,
            dependencies=[],
            ttc_reference=None
        )
        
        ttc_agent.stix_processor.search_techniques.return_value = []
        
        mappings = ttc_agent._find_ttc_mappings(attack_step)
        
        assert len(mappings) == 0
    
    @patch('threatforest.agents.ttc_mapping.TTCMappingAgent._calculate_semantic_similarity')
    def test_find_ttc_mappings_success(self, mock_similarity, ttc_agent, sample_stix_technique):
        """Test successful TTC mapping finding."""
        attack_step = AttackStep(
            id="test_step",
            description="SQL injection attack",
            step_type=AttackStepType.ATTACK,
            dependencies=[],
            ttc_reference=None
        )
        
        # Mock search results
        search_result = STIXSearchResult(
            technique=sample_stix_technique,
            relevance_score=0.8,
            matching_keywords={"sql"},
            match_reasons=["Match"]
        )
        
        ttc_agent.stix_processor.search_techniques.return_value = [search_result]
        mock_similarity.return_value = 0.85
        
        mappings = ttc_agent._find_ttc_mappings(attack_step)
        
        assert len(mappings) == 1
        assert mappings[0].attack_step_id == "test_step"
        assert mappings[0].ttc_technique_id == sample_stix_technique.id
        assert mappings[0].alignment_score == 0.85
    
    def test_cosine_similarity(self, ttc_agent):
        """Test cosine similarity calculation."""
        vec1 = np.array([1.0, 0.0, 0.0])
        vec2 = np.array([1.0, 0.0, 0.0])
        
        similarity = ttc_agent._cosine_similarity(vec1, vec2)
        assert abs(similarity - 1.0) < 0.001  # Should be very close to 1.0
        
        vec3 = np.array([1.0, 0.0, 0.0])
        vec4 = np.array([0.0, 1.0, 0.0])
        
        similarity2 = ttc_agent._cosine_similarity(vec3, vec4)
        assert abs(similarity2 - 0.0) < 0.001  # Should be very close to 0.0
    
    def test_calculate_bonus_score(self, ttc_agent, sample_stix_technique):
        """Test bonus score calculation."""
        # Test with exact technique name match
        attack_desc = "Perform SQL injection to access database"
        bonus = ttc_agent._calculate_bonus_score(attack_desc, sample_stix_technique)
        
        assert bonus > 0.0  # Should get bonus for matching "sql" and "injection"
        
        # Test with MITRE ID match
        attack_desc_with_id = "Use T1190 technique for initial access"
        bonus_with_id = ttc_agent._calculate_bonus_score(attack_desc_with_id, sample_stix_technique)
        
        assert bonus_with_id > bonus  # Should get additional bonus for MITRE ID
    
    def test_update_mermaid_with_ttc(self, ttc_agent, sample_stix_technique):
        """Test updating Mermaid content with TTC information."""
        original_content = """graph TD
    step1["SQL Injection Attack"]
    step2["Data Exfiltration"]
    step1 --> step2"""
        
        mapping = TTCMapping(
            attack_step_id="step1",
            ttc_technique_id=sample_stix_technique.id,
            ttc_technique_name=sample_stix_technique.name,
            alignment_score=0.85,
            stix_data={},
            applied=True
        )
        
        ttc_agent.stix_processor.get_technique_by_id.return_value = sample_stix_technique
        
        updated_content = ttc_agent._update_mermaid_with_ttc(original_content, [mapping])
        
        # Should contain TTC information
        assert "T1190" in updated_content or "TTC:" in updated_content
    
    @patch('threatforest.agents.ttc_mapping.TTCMappingAgent._get_embeddings_model')
    def test_enhance_multiple_trees(self, mock_get_model, ttc_agent, sample_attack_tree, sample_stix_technique):
        """Test enhancing multiple attack trees."""
        # Mock sentence transformer
        mock_model = Mock()
        mock_model.encode.return_value = np.array([[0.1, 0.2, 0.3], [0.15, 0.25, 0.35]])
        mock_get_model.return_value = mock_model
        
        # Mock STIX search
        search_result = STIXSearchResult(
            technique=sample_stix_technique,
            relevance_score=0.8,
            matching_keywords={"sql"},
            match_reasons=["Match"]
        )
        
        ttc_agent.stix_processor.search_techniques.return_value = [search_result]
        ttc_agent.stix_processor.get_technique_by_id.return_value = sample_stix_technique
        
        # Create multiple trees
        trees = [sample_attack_tree, sample_attack_tree]
        
        results = ttc_agent.enhance_multiple_trees(trees)
        
        assert len(results) == 2
        assert all(len(r.applied_mappings) > 0 for r in results)
    
    def test_get_mapping_confidence_distribution_empty(self, ttc_agent):
        """Test confidence distribution with empty results."""
        distribution = ttc_agent.get_mapping_confidence_distribution([])
        
        assert distribution["total_mappings"] == 0
    
    def test_get_mapping_confidence_distribution(self, ttc_agent):
        """Test confidence distribution calculation."""
        # Create sample results
        applied_mapping = TTCMapping(
            attack_step_id="step1",
            ttc_technique_id="T1001",
            ttc_technique_name="Test",
            alignment_score=0.9,
            stix_data={},
            applied=True
        )
        
        rejected_mapping = TTCMapping(
            attack_step_id="step2",
            ttc_technique_id="T1002",
            ttc_technique_name="Test2",
            alignment_score=0.6,
            stix_data={},
            applied=False
        )
        
        result = MappingResult(
            enhanced_tree=Mock(),
            applied_mappings=[applied_mapping],
            rejected_mappings=[rejected_mapping],
            processing_errors=[],
            processing_warnings=[],
            processing_time_seconds=1.0
        )
        
        distribution = ttc_agent.get_mapping_confidence_distribution([result])
        
        assert distribution["total_mappings"] == 2
        assert distribution["applied_mappings"] == 1
        assert distribution["rejected_mappings"] == 1
        assert distribution["threshold"] == 0.8
        assert distribution["applied_stats"]["mean"] == 0.9
        assert distribution["rejected_stats"]["mean"] == 0.6
    
    def test_export_mapping_report(self, ttc_agent, tmp_path):
        """Test exporting mapping report."""
        # Create sample result
        applied_mapping = TTCMapping(
            attack_step_id="step1",
            ttc_technique_id="attack-pattern--test",
            ttc_technique_name="Test Technique",
            alignment_score=0.85,
            stix_data={},
            applied=True
        )
        
        attack_tree = AttackTree(
            threat_id="test-threat",
            title="Test Tree",
            mermaid_content="graph TD",
            attack_steps=[],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        result = MappingResult(
            enhanced_tree=attack_tree,
            applied_mappings=[applied_mapping],
            rejected_mappings=[],
            processing_errors=[],
            processing_warnings=[],
            processing_time_seconds=1.0
        )
        
        # Mock STIX processor for report generation
        mock_technique = Mock()
        mock_technique.get_mitre_id.return_value = "T1001"
        ttc_agent.stix_processor.get_technique_by_id.return_value = mock_technique
        
        report_path = ttc_agent.export_mapping_report([result], str(tmp_path))
        
        # Verify report was created
        assert report_path.endswith("ttc_mapping_report.md")
        
        # Verify content
        with open(report_path, 'r') as f:
            content = f.read()
        
        assert "# TTC Mapping Report" in content
        assert "test-threat" in content
        assert "Test Technique" in content
        assert "0.85" in content  # Alignment score
    
    def test_get_embeddings_model_import_error(self, ttc_agent):
        """Test handling of missing sentence-transformers library."""
        with patch('builtins.__import__', side_effect=ImportError("No module named 'sentence_transformers'")):
            with pytest.raises(ImportError, match="sentence-transformers library required"):
                ttc_agent._get_embeddings_model()
    
    @patch('sentence_transformers.SentenceTransformer')
    def test_get_embeddings_model_success(self, mock_transformer, ttc_agent):
        """Test successful embeddings model loading."""
        mock_model = Mock()
        mock_transformer.return_value = mock_model
        
        model = ttc_agent._get_embeddings_model()
        
        assert model == mock_model
        mock_transformer.assert_called_once_with("all-MiniLM-L6-v2")
        
        # Test caching - second call should return cached model
        model2 = ttc_agent._get_embeddings_model()
        assert model2 == mock_model
        assert mock_transformer.call_count == 1  # Should not be called again