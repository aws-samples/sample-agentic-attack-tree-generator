#!/usr/bin/env python3
"""
Simple unit tests for project information models (no pytest required)
Tests ProjectInfo, ExtractionSummary, and ExtractedInfo models
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
    print("\n🧪 Project Models Unit Tests")
    print("Testing ProjectInfo, ExtractionSummary, and ExtractedInfo")
    print("=" * 60)
    
    from threatforest.modules.models import ProjectInfo, ExtractionSummary, ExtractedInfo
    
    all_passed = True
    
    # Test 1: ProjectInfo with defaults
    test_section("Test: ProjectInfo with Defaults")
    try:
        info = ProjectInfo()
        
        assert info.application_name == "Unknown Application"
        assert info.technologies == []
        assert info.security_objectives == []
        assert isinstance(info.security_objectives, list)
        
        print("  ✓ ProjectInfo defaults: PASSED")
    except Exception as e:
        print(f"  ✗ ProjectInfo defaults: FAILED - {e}")
        all_passed = False
    
    # Test 2: ProjectInfo with full data
    test_section("Test: ProjectInfo with Full Data")
    try:
        info = ProjectInfo(
            application_name="Test App",
            technologies=["Python", "FastAPI", "PostgreSQL"],
            architecture_type="Microservices",
            deployment_environment="AWS",
            sector="Healthcare",
            security_objectives=["Protect PII", "Ensure availability"],
            data_assets=["Patient records"],
            entry_points=["REST API"],
            trust_boundaries=["User to API"],
            summary="Test application"
        )
        
        assert info.application_name == "Test App"
        assert len(info.technologies) == 3
        assert info.architecture_type == "Microservices"
        assert len(info.security_objectives) == 2
        assert isinstance(info.security_objectives, list)
        
        print("  ✓ ProjectInfo full data: PASSED")
    except Exception as e:
        print(f"  ✗ ProjectInfo full data: FAILED - {e}")
        all_passed = False
    
    # Test 3: Critical - security_objectives as list (the bug we fixed!)
    test_section("Test: Security Objectives as List (Bug Fix)")
    try:
        info = ProjectInfo(
            security_objectives=["Obj1", "Obj2", "Obj3"]
        )
        
        # This is what was causing the bug - must be a list
        assert isinstance(info.security_objectives, list)
        assert len(info.security_objectives) == 3
        
        # Should be iterable
        for obj in info.security_objectives:
            assert isinstance(obj, str)
        
        print("  ✓ Security objectives as list: PASSED")
        print("    This validates the fix for 'list' object has no attribute 'items'")
    except Exception as e:
        print(f"  ✗ Security objectives as list: FAILED - {e}")
        all_passed = False
    
    # Test 4: ExtractionSummary
    test_section("Test: ExtractionSummary")
    try:
        summary = ExtractionSummary(
            total_threats=15,
            high_severity_count=5,
            technologies_identified=8,
            has_security_objectives=True,
            threat_source="user_provided"
        )
        
        assert summary.total_threats == 15
        assert summary.high_severity_count == 5
        assert summary.threat_source == "user_provided"
        
        print("  ✓ ExtractionSummary: PASSED")
    except Exception as e:
        print(f"  ✗ ExtractionSummary: FAILED - {e}")
        all_passed = False
    
    # Test 5: ExtractedInfo with nested models
    test_section("Test: ExtractedInfo with Nested Models")
    try:
        project = ProjectInfo(
            application_name="Nested Test",
            technologies=["Python"]
        )
        
        summary = ExtractionSummary(
            total_threats=10,
            high_severity_count=3
        )
        
        info = ExtractedInfo(
            project_info=project,
            extraction_summary=summary
        )
        
        assert info.project_info.application_name == "Nested Test"
        assert info.extraction_summary.total_threats == 10
        
        print("  ✓ Nested models: PASSED")
    except Exception as e:
        print(f"  ✗ Nested models: FAILED - {e}")
        all_passed = False
    
    # Test 6: ExtractedInfo with threat data
    test_section("Test: ExtractedInfo with Threat Data")
    try:
        threat1 = {"id": "T001", "description": "Test", "severity": "High"}
        threat2 = {"id": "T002", "description": "Test2", "severity": "Medium"}
        
        info = ExtractedInfo(
            threat_statements=[threat1, threat2],
            high_severity_threats=[threat1]
        )
        
        assert len(info.threat_statements) == 2
        assert len(info.high_severity_threats) == 1
        assert info.threat_statements[0]["id"] == "T001"
        
        print("  ✓ Threat data handling: PASSED")
    except Exception as e:
        print(f"  ✗ Threat data handling: FAILED - {e}")
        all_passed = False
    
    # Summary
    test_section("Test Summary")
    
    if all_passed:
        print("\n  ✅ All tests PASSED!")
        print("  Project models are working correctly")
        print("  security_objectives list/dict bug is FIXED")
        return 0
    else:
        print("\n  ❌ Some tests FAILED")
        print("  Check error messages above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
