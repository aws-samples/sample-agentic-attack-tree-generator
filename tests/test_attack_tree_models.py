"""
Unit tests for attack tree Pydantic models
Tests NodeType enum, AttackNode, AttackTree, TTPMapping, etc.
"""
import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.modules.models import (
    NodeType,
    AttackNode,
    AttackEdge,
    TTPMapping,
    AttackTreeMetadata,
    AttackTree,
    AttackTreeGenerationResult
)


class TestNodeType:
    """Test NodeType enum"""
    
    def test_node_type_values(self):
        """Test all enum values are defined"""
        assert NodeType.ATTACK == "attack"
        assert NodeType.GOAL == "goal"
        assert NodeType.FACT == "fact"
        assert NodeType.TECHNIQUE == "technique"
        assert NodeType.MITIGATION == "mitigation"
    
    def test_node_type_comparison(self):
        """Test enum comparison"""
        assert NodeType.ATTACK != NodeType.GOAL
        assert NodeType.FACT == NodeType.FACT


class TestAttackNode:
    """Test AttackNode model"""
    
    def test_attack_node_with_enum(self):
        """Test creating attack node with NodeType enum"""
        node = AttackNode(
            node_id="N1",
            label="Exploit vulnerability",
            node_type=NodeType.ATTACK
        )
        
        assert node.node_id == "N1"
        assert node.label == "Exploit vulnerability"
        assert node.node_type == NodeType.ATTACK
        assert node.node_type.value == "attack"
    
    def test_attack_node_all_fields(self):
        """Test attack node with all optional fields"""
        node = AttackNode(
            node_id="N2",
            label="Access database",
            node_type=NodeType.GOAL,
            full_label="Gain unauthorized access to database",
            color="#ea580c"
        )
        
        assert node.full_label == "Gain unauthorized access to database"
        assert node.color == "#ea580c"


class TestTTPMapping:
    """Test TTPMapping model"""
    
    def test_ttp_mapping_basic(self):
        """Test creating TTP mapping"""
        mapping = TTPMapping(
            attack_step="Exploit web vulnerability",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            confidence=0.85
        )
        
        assert mapping.technique_id == "T1190"
        assert mapping.confidence == 0.85
        assert 0.0 <= mapping.confidence <= 1.5
    
    def test_ttp_mapping_with_mitigations(self):
        """Test TTP mapping with mitigations"""
        mapping = TTPMapping(
            attack_step="SQL injection",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            confidence=0.92,
            tactics=["Initial Access"],
            technique_url="https://attack.mitre.org/techniques/T1190/",
            mitigations=[{"name": "Input validation", "description": "Validate all inputs"}]
        )
        
        assert len(mapping.tactics) == 1
        assert mapping.technique_url is not None
        assert len(mapping.mitigations) == 1


class TestAttackTree:
    """Test AttackTree model"""
    
    def test_attack_tree_basic(self):
        """Test creating attack tree"""
        tree = AttackTree(
            threat_id="T001",
            threat_statement="Test threat",
            threat_category="Authentication",
            mermaid_code="graph TD\n  A[Start]"
        )
        
        assert tree.threat_id == "T001"
        assert tree.threat_category == "Authentication"
        assert "graph TD" in tree.mermaid_code
    
    def test_attack_tree_with_mappings(self):
        """Test attack tree with TTP mappings"""
        mapping = TTPMapping(
            attack_step="Step 1",
            technique_id="T1190",
            technique_name="Exploit",
            confidence=0.9
        )
        
        tree = AttackTree(
            threat_id="T002",
            threat_statement="Test",
            threat_category="Injection",
            mermaid_code="graph TD\n",
            ttc_mappings=[mapping],
            mapping_count=1
        )
        
        assert len(tree.ttc_mappings) == 1
        assert tree.mapping_count == 1


class TestAttackTreeGenerationResult:
    """Test AttackTreeGenerationResult model"""
    
    def test_generation_result(self):
        """Test attack tree generation result"""
        tree = AttackTree(
            threat_id="T001",
            threat_statement="Test",
            threat_category="Test",
            mermaid_code="graph TD\n"
        )
        
        result = AttackTreeGenerationResult(
            attack_trees=[tree],
            threat_status={"T001": "success"},
            generation_summary={
                "total": 1,
                "successful": 1,
                "failed": 0
            }
        )
        
        assert len(result.attack_trees) == 1
        assert result.threat_status["T001"] == "success"
        assert result.generation_summary["successful"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
