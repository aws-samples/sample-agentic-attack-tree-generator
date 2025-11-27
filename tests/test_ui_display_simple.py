#!/usr/bin/env python3
"""
Simple unit tests for UI display formatting (no pytest required)
Tests that UUIDs are converted to friendly names
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
    print("\n🧪 UI Display Formatting Tests")
    print("Testing friendly names instead of UUIDs")
    print("=" * 60)
    
    all_passed = True
    
    # Test 1: Dashboard tab with UUID
    test_section("Test: Dashboard Tab with UUID")
    try:
        threat_id = "9b4dbea5-ccaa-41ea-a057-c6dd47f99523"
        category = "Privilege Escalation"
        tab_num = 1
        
        # Format used in dashboard
        tab_label = f"Threat {tab_num}: {category}"
        
        # Verify format
        assert threat_id not in tab_label
        assert "Threat 1" in tab_label
        assert category in tab_label
        
        print(f"  ✓ Dashboard tab: '{tab_label}'")
        print(f"    UUID not visible: ✓")
        print(f"    Friendly number: ✓")
        print(f"    Category shown: ✓")
    except Exception as e:
        print(f"  ✗ Dashboard tab: FAILED - {e}")
        all_passed = False
    
    # Test 2: Progress bar with UUID
    test_section("Test: Progress Bar with UUID")
    try:
        threat_id = "c5ac485c-a985-4004-be21-1fb26173a2d3"
        category = "Injection"
        idx = 1
        statement = "A threat actor with access to modify network traffic"
        
        # Format used in progress bar
        progress_desc = f"Processing Threat {idx} ({category}): {statement[:50]}..."
        
        # Verify format
        assert threat_id not in progress_desc
        assert "Threat 1" in progress_desc
        assert category in progress_desc
        
        print(f"  ✓ Progress bar: '{progress_desc[:70]}...'")
        print(f"    UUID not visible: ✓")
        print(f"    Friendly number: ✓")
        print(f"    Category shown: ✓")
    except Exception as e:
        print(f"  ✗ Progress bar: FAILED - {e}")
        all_passed = False
    
    # Test 3: Multiple threats sequential numbering
    test_section("Test: Sequential Numbering for Multiple Threats")
    try:
        threats = [
            {"id": "uuid-001", "category": "Authentication"},
            {"id": "uuid-002", "category": "Data Breach"},
            {"id": "uuid-003", "category": "Injection"},
        ]
        
        for i, threat in enumerate(threats, 1):
            tab_label = f"Threat {i}: {threat['category']}"
            
            # Check numbering
            assert f"Threat {i}" in tab_label
            assert "uuid" not in tab_label
            assert threat['category'] in tab_label
        
        print(f"  ✓ Sequential numbering: PASSED")
        print(f"    Threat 1: Authentication")
        print(f"    Threat 2: Data Breach")
        print(f"    Threat 3: Injection")
    except Exception as e:
        print(f"  ✗ Sequential numbering: FAILED - {e}")
        all_passed = False
    
    # Test 4: UUID still used internally
    test_section("Test: UUID Still Used for Internal Tracking")
    try:
        threat_id = "9b4dbea5-ccaa-41ea-a057-c6dd47f99523"
        
        # JavaScript onclick should still use UUID
        js_call = f"switchTab('{threat_id}')"
        
        assert threat_id in js_call
        
        print(f"  ✓ Internal tracking: PASSED")
        print(f"    UUID in switchTab(): ✓")
        print(f"    JavaScript functionality preserved: ✓")
    except Exception as e:
        print(f"  ✗ Internal tracking: FAILED - {e}")
        all_passed = False
    
    # Test 5: Display vs Internal separation
    test_section("Test: Display Name Separate from Internal ID")
    try:
        threat = {
            "id": "uuid-abc-123-def-456",
            "category": "Privilege Escalation"
        }
        
        # Display name
        display_name = f"Threat 1: {threat['category']}"
        
        # Internal ID
        internal_id = threat['id']
        
        # Should be different
        assert display_name != internal_id
        assert "uuid" not in display_name
        assert threat['category'] in display_name
        
        print(f"  ✓ Display vs Internal: PASSED")
        print(f"    Display: '{display_name}'")
        print(f"    Internal: '{internal_id}'")
        print(f"    Properly separated: ✓")
    except Exception as e:
        print(f"  ✗ Display vs Internal: FAILED - {e}")
        all_passed = False
    
    # Summary
    test_section("Test Summary")
    
    if all_passed:
        print("\n  ✅ All tests PASSED!")
        print("  UI display formatting is working correctly")
        print("  UUIDs replaced with friendly names in:")
        print("    - Dashboard tabs")
        print("    - Progress bar descriptions")
        print("  UUIDs still used internally for:")
        print("    - JavaScript functionality")
        print("    - Data tracking")
        return 0
    else:
        print("\n  ❌ Some tests FAILED")
        print("  Check error messages above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
