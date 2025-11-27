"""
Unit tests for Pydantic threat models
Tests the structured output data models
"""
import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.modules.models import ThreatModel, ThreatList


class TestThreatModel:
    """Test individual ThreatModel validation"""
    
    def test_threat_model_minimum_fields(self):
        """Test creating threat with only required fields"""
        threat = ThreatModel(
            id="T001",
            statement="Test threat statement",
            priority="High"
        )
        
        assert threat.id == "T001"
        assert threat.statement == "Test threat statement"
        assert threat.priority == "High"
        assert threat.category == "General"  # Default value
        assert threat.threatSource is None
        assert threat.prerequisites is None
    
    def test_threat_model_all_fields(self):
        """Test creating threat with all fields"""
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
        
        assert threat.id == "T002"
        assert threat.statement == "Complete threat statement"
        assert threat.priority == "Medium"
        assert threat.category == "Authentication"
        assert threat.threatSource == "External attacker"
        assert threat.prerequisites == "Network access"
        assert threat.threatAction == "Exploit weak authentication"
        assert threat.threatImpact == "Unauthorized access"
        assert threat.impactedGoal == "Confidentiality"
        assert threat.impactedAssets == ["User data", "Credentials"]
    
    def test_threat_model_missing_required_field(self):
        """Test that missing required fields raise validation error"""
        with pytest.raises(Exception):  # Pydantic ValidationError
            ThreatModel(
                id="T003",
                # Missing 'statement' - should fail
                priority="Low"
            )
    
    def test_threat_model_dict_conversion(self):
        """Test converting threat model to dict"""
        threat = ThreatModel(
            id="T004",
            statement="Test statement",
            priority="High",
            category="Injection"
        )
        
        threat_dict = threat.model_dump()
        
        assert threat_dict["id"] == "T004"
        assert threat_dict["statement"] == "Test statement"
        assert threat_dict["priority"] == "High"
        assert threat_dict["category"] == "Injection"


class TestThreatList:
    """Test ThreatList collection model"""
    
    def test_empty_threat_list(self):
        """Test creating empty threat list"""
        threat_list = ThreatList(threats=[])
        
        assert threat_list.threats == []
        assert len(threat_list.threats) == 0
    
    def test_threat_list_single_threat(self):
        """Test threat list with one threat"""
        threat = ThreatModel(
            id="T001",
            statement="Test threat",
            priority="High"
        )
        
        threat_list = ThreatList(threats=[threat])
        
        assert len(threat_list.threats) == 1
        assert threat_list.threats[0].id == "T001"
    
    def test_threat_list_multiple_threats(self):
        """Test threat list with multiple threats"""
        threats = [
            ThreatModel(id="T001", statement="Threat 1", priority="High"),
            ThreatModel(id="T002", statement="Threat 2", priority="Medium"),
            ThreatModel(id="T003", statement="Threat 3", priority="Low")
        ]
        
        threat_list = ThreatList(threats=threats)
        
        assert len(threat_list.threats) == 3
        assert threat_list.threats[0].id == "T001"
        assert threat_list.threats[1].id == "T002"
        assert threat_list.threats[2].id == "T003"
    
    def test_threat_list_iteration(self):
        """Test iterating over threat list"""
        threats = [
            ThreatModel(id=f"T00{i}", statement=f"Threat {i}", priority="Medium")
            for i in range(1, 6)
        ]
        
        threat_list = ThreatList(threats=threats)
        
        for i, threat in enumerate(threat_list.threats, 1):
            assert threat.id == f"T00{i}"
            assert threat.statement == f"Threat {i}"


class TestThreatModelIntegration:
    """Integration tests for threat models"""
    
    def test_threatcomposer_structure(self):
        """Test structure matching ThreatComposer format"""
        # Simulate ThreatComposer threat
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
        
        # Verify all fields
        assert threat.id == "uuid-001"
        assert "exploit weak authentication" in threat.statement
        assert threat.priority == "High"
        assert threat.category == "Authentication"
    
    def test_json_format_compatibility(self):
        """Test structure matching simple JSON format"""
        threat = ThreatModel(
            id="T001",
            statement="SQL injection vulnerability",
            priority="High",
            category="Injection"
        )
        
        assert threat.id == "T001"
        assert threat.statement == "SQL injection vulnerability"
        assert threat.priority == "High"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
