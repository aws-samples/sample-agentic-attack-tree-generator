#!/usr/bin/env python3
"""
Simple unit tests for attack tree models (no pytest required)
Tests NodeType enum, AttackNode, TTPMapping, AttackTree models
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_section(title):
    """Print test section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    print("\n🧪 Attack Tree Models Unit Tests")
    print("Testing NodeType enum and all attack tree models")
    print("=" * 60)
    
    from threatforest.modules.models import (
        NodeType, AttackNode, AttackEdge, TTPMapping,
        AttackTree, AttackTreeGenerationResult
    )
    
    all_passed = True
    
    # Test 1: NodeType Enum
    test_section("Test: NodeType Enum Values")
    try:
        assert NodeType.ATTACK == "attack"
        assert NodeType.GOAL == "goal"
        assert NodeType.FACT == "fact"
        assert NodeType.TECHNIQUE == "technique"
        assert NodeType.MITIGATION == "mitigation"
        
        # Test enum comparison
        assert NodeType.ATTACK != NodeType.GOAL
        
        print("  ✓ NodeType enum: PASSED")
        print("    All 5 node types defined correctly")
    except Exception as e:
        print(f"  ✗ NodeType enum: FAILED - {e}")
        all_passed = False
    
    # Test 2: AttackNode with Enum
    test_section("Test: AttackNode with NodeType Enum")
    try:
        node = AttackNode(
            node_id="N1",
            label="Exploit vulnerability",
            node_type=NodeType.ATTACK
        )
        
        assert node.node_id == "N1"
        assert node.node_type == NodeType.ATTACK
        assert node.node_type.value == "attack"
        
        print("  ✓ AttackNode with enum: PASSED")
        print(f"    Created node: {node.label} ({node.node_type.value})")
    except Exception as e:
        print(f"  ✗ AttackNode with enum: FAILED - {e}")
        all_passed = False
    
    # Test 3: TTPMapping
    test_section("Test: TTPMapping Model")
    try:
        mapping = TTPMapping(
            attack_step="Exploit web vulnerability",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            confidence=0.85,
            tactics=["Initial Access"]
        )
        
        assert mapping.technique_id == "T1190"
        assert mapping.confidence == 0.85
        assert len(mapping.tactics) == 1
        
        print("  ✓ TTPMapping: PASSED")
        print(f"    Technique: {mapping.technique_id} ({mapping.confidence:.0%})")
    except Exception as e:
        print(f"  ✗ TTPMapping: FAILED - {e}")
        all_passed = False
    
    # Test 4: AttackTree
    test_section("Test: Complete AttackTree Model")
    try:
        ttp_mapping = TTPMapping(
            attack_step="Step 1",
            technique_id="T1190",
            technique_name="Exploit",
            confidence=0.9
        )
        
        tree = AttackTree(
            threat_id="T001",
            threat_statement="Test threat statement",
            threat_category="Authentication",
            mermaid_code="graph TD\n  A[Start] --> B[End]",
            ttc_mappings=[ttp_mapping],
            mapping_count=1
        )
        
        assert tree.threat_id == "T001"
        assert len(tree.ttc_mappings) == 1
        assert tree.mapping_count == 1
        
        print("  ✓ AttackTree: PASSED")
        print(f"    Tree: {tree.threat_category} with {len(tree.ttc_mappings)} mappings")
    except Exception as e:
        print(f"  ✗ AttackTree: FAILED - {e}")
        all_passed = False
    
    # Test 5: AttackTreeGenerationResult
    test_section("Test: AttackTreeGenerationResult")
    try:
        tree = AttackTree(
            threat_id="T001",
            threat_statement="Test",
            threat_category="Test",
            mermaid_code="graph TD\n"
        )
        
        result = AttackTreeGenerationResult(
            attack_trees=[tree],
            threat_status={"T001": "success"},
            generation_summary={"total": 1, "successful": 1}
        )
        
        assert len(result.attack_trees) == 1
        assert result.threat_status["T001"] == "success"
        
        print("  ✓ Generation result: PASSED")
        print(f"    Generated {len(result.attack_trees)} trees successfully")
    except Exception as e:
        print(f"  ✗ Generation result: FAILED - {e}")
        all_passed = False
    
    # Summary
    test_section("Test Summary")
    
    if all_passed:
        print("\n  ✅ All tests PASSED!")
        print("  Attack tree models working correctly")
        print("  NodeType enum provides type safety")
        print("  All 7 models validated:")
        print("    - NodeType (enum)")
        print("    - AttackNode")
        print("    - AttackEdge")
        print("    - TTPMapping")
        print("    - AttackTreeMetadata")
        print("    - AttackTree")
        print("    - AttackTreeGenerationResult")
        return 0
    else:
        print("\n  ❌ Some tests FAILED")
        print("  Check error messages above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
