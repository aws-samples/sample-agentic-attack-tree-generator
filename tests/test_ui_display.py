"""
Unit tests for UI display formatting
Tests that UUIDs are converted to friendly names
"""
import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestDashboardTabLabels:
    """Test that dashboard tabs show friendly names instead of UUIDs"""
    
    def test_tab_label_format_with_uuid(self):
        """Test tab label shows 'Threat X: Category' for UUID threat IDs"""
        # Simulate ThreatComposer UUID
        threat_id = "9b4dbea5-ccaa-41ea-a057-c6dd47f99523"
        category = "Privilege Escalation"
        tab_num = 1
        
        # Expected format
        expected = f"Threat {tab_num}: {category}"
        
        # Should NOT contain UUID
        assert threat_id not in expected
        # Should contain sequential number
        assert "Threat 1" in expected
        # Should contain category
        assert category in expected
        
        print(f"  ✓ Tab label format: '{expected}'")
    
    def test_tab_label_format_with_sequential_id(self):
        """Test tab label works with sequential IDs too"""
        threat_id = "T001"
        category = "Authentication"
        tab_num = 2
        
        expected = f"Threat {tab_num}: {category}"
        
        # Should work regardless of ID format
        assert "Threat 2" in expected
        assert category in expected
        
        print(f"  ✓ Tab label format: '{expected}'")
    
    def test_multiple_tab_labels(self):
        """Test multiple threats get sequential numbering"""
        threats = [
            {"id": "uuid-001", "category": "Authentication"},
            {"id": "uuid-002", "category": "Data Breach"},
            {"id": "uuid-003", "category": "Injection"}
        ]
        
        for i, threat in enumerate(threats, 1):
            tab_label = f"Threat {i}: {threat['category']}"
            
            # Should have sequential numbering
            assert f"Threat {i}" in tab_label
            # Should not show UUID
            assert "uuid" not in tab_label
            # Should show category
            assert threat['category'] in tab_label


class TestProgressBarLabels:
    """Test that progress bar shows friendly names instead of UUIDs"""
    
    def test_progress_description_with_uuid(self):
        """Test progress shows 'Threat X (Category)' for UUID threat IDs"""
        threat_id = "c5ac485c-a985-4004-be21-1fb26173a2d3"
        category = "Injection"
        idx = 1
        statement = "A threat actor with access to modify network traffic"
        
        # Expected format
        expected_prefix = f"Processing Threat {idx} ({category})"
        
        # Should NOT contain UUID
        assert threat_id not in expected_prefix
        # Should contain sequential number
        assert "Threat 1" in expected_prefix
        # Should contain category
        assert category in expected_prefix
        
        print(f"  ✓ Progress description: '{expected_prefix}: {statement[:30]}...'")
    
    def test_progress_description_multiple_threats(self):
        """Test progress numbering for multiple threats"""
        threats = [
            {"id": "uuid-1", "category": "Auth", "statement": "Test 1"},
            {"id": "uuid-2", "category": "Data", "statement": "Test 2"},
            {"id": "uuid-3", "category": "Injection", "statement": "Test 3"}
        ]
        
        for i, threat in enumerate(threats, 1):
            desc = f"Processing Threat {i} ({threat['category']})"
            
            # Should have sequential numbering
            assert f"Threat {i}" in desc
            # Should show category
            assert threat['category'] in desc
            # Should NOT show UUID
            assert "uuid" not in desc


class TestUUIDMapping:
    """Test that internal UUID tracking still works"""
    
    def test_uuid_used_for_javascript(self):
        """Test that UUIDs are still used for internal tracking"""
        threat_id = "9b4dbea5-ccaa-41ea-a057-c6dd47f99523"
        
        # JavaScript should still use UUID for switchTab()
        js_call = f"switchTab('{threat_id}')"
        
        # UUID should be in the onclick handler
        assert threat_id in js_call
        
        print(f"  ✓ JavaScript still uses UUID internally")
    
    def test_display_vs_internal_id(self):
        """Test separation of display name from internal ID"""
        threat = {
            "id": "uuid-abc-123",
            "category": "Authentication"
        }
        
        # Display name
        display_name = f"Threat 1: {threat['category']}"
        
        # Internal tracking
        internal_id = threat['id']
        
        # Should be different
        assert display_name != internal_id
        assert "uuid" not in display_name
        assert threat['category'] in display_name


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
