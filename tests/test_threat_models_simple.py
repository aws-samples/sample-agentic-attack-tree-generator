#!/usr/bin/env python3
"""
Simple unit tests for Pydantic threat models (no pytest required)
Tests the structured output data models
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
    print("\n🧪 Pydantic Threat Models Unit Tests")
    print("Testing ThreatModel and ThreatList validation")
    print("=" * 60)
    
    from threatforest.modules.models import ThreatModel, ThreatList
    
    all_passed = True
    
    # Test 1: Minimum required fields
    test_section("Test: Minimum Required Fields")
    try:
        threat = ThreatModel(
            id="T001",
            statement="Test threat statement",
            priority="High"
        )
        
        assert threat.id == "T001"
        assert threat.statement == "Test threat statement"
        assert threat.priority == "High"
        assert threat.category == "General"
        
        print("  ✓ Minimum fields: PASSED")
    except Exception as e:
        print(f"  ✗ Minimum fields: FAILED - {e}")
        all_passed = False
    
    # Test 2: All fields
    test_section("Test: All Fields Populated")
    try:
        threat = ThreatModel(
            id="T002",
            statement="Complete threat statement",
            priority="Medium",
            category="Authentication",
            threatSource="External attacker",
            prerequisites="Network access",
            threatAction="Exploit weak authentication",
            threatImpact="Unauthorized access",
            impactedGoal="Confidentiality",
            impactedAssets=["User data", "Credentials"]
        )
        
        assert threat.threatSource == "External attacker"
        assert threat.prerequisites == "Network access"
        assert len(threat.impactedAssets) == 2
        
        print("  ✓ All fields: PASSED")
    except Exception as e:
        print(f"  ✗ All fields: FAILED - {e}")
        all_passed = False
    
    # Test 3: Missing required field (should fail)
    test_section("Test: Missing Required Field (Should Fail)")
    try:
        threat = ThreatModel(
            id="T003",
            # Missing 'statement' - should fail
            priority="Low"
        )
        
        print("  ✗ Validation check: FAILED - Should have raised exception")
        all_passed = False
    except Exception:
        print("  ✓ Validation check: PASSED - Correctly raised exception")
    
    # Test 4: ThreatList with multiple threats
    test_section("Test: ThreatList with Multiple Threats")
    try:
        threats = [
            ThreatModel(id="T001", statement="Threat 1", priority="High"),
            ThreatModel(id="T002", statement="Threat 2", priority="Medium"),
            ThreatModel(id="T003", statement="Threat 3", priority="Low")
        ]
        
        threat_list = ThreatList(threats=threats)
        
        assert len(threat_list.threats) == 3
        assert threat_list.threats[0].id == "T001"
        assert threat_list.threats[1].priority == "Medium"
        
        print("  ✓ ThreatList: PASSED")
    except Exception as e:
        print(f"  ✗ ThreatList: FAILED - {e}")
        all_passed = False
    
    # Test 5: ThreatComposer structure
    test_section("Test: ThreatComposer Format Compatibility")
    try:
        threat = ThreatModel(
            id="uuid-001",
            statement="A threat actor with network access can exploit weak authentication",
            priority="High",
            category="Authentication",
            threatSource="threat actor",
            prerequisites="with network access",
            threatAction="exploit weak authentication",
            threatImpact="unauthorized access",
            impactedGoal="confidentiality",
            impactedAssets=["user credentials", "session tokens"]
        )
        
        assert "uuid" in threat.id
        assert "weak authentication" in threat.statement
        assert len(threat.impactedAssets) == 2
        
        print("  ✓ ThreatComposer format: PASSED")
    except Exception as e:
        print(f"  ✗ ThreatComposer format: FAILED - {e}")
        all_passed = False
    
    # Summary
    test_section("Test Summary")
    
    if all_passed:
        print("\n  ✅ All tests PASSED!")
        print("  Pydantic models are working correctly")
        print("  Ready for structured output with Strands")
        return 0
    else:
        print("\n  ❌ Some tests FAILED")
        print("  Check error messages above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
