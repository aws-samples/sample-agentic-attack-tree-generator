"""
Unit tests for project information Pydantic models
Tests ProjectInfo, ExtractionSummary, and ExtractedInfo models
"""
import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.modules.models import ProjectInfo, ExtractionSummary, ExtractedInfo


class TestProjectInfo:
    """Test ProjectInfo model validation"""
    
    def test_project_info_defaults(self):
        """Test creating ProjectInfo with all defaults"""
        info = ProjectInfo()
        
        assert info.application_name == "Unknown Application"
        assert info.technologies == []
        assert info.architecture_type == "Unknown"
        assert info.deployment_environment == "Unknown"
        assert info.sector == "Unknown"
        assert info.security_objectives == []
        assert info.data_assets == []
        assert info.entry_points == []
        assert info.trust_boundaries == []
        assert info.summary is None
    
    def test_project_info_full_data(self):
        """Test creating ProjectInfo with complete data"""
        info = ProjectInfo(
            application_name="Test App",
            technologies=["Python", "FastAPI", "PostgreSQL"],
            architecture_type="Microservices",
            deployment_environment="AWS",
            sector="Healthcare",
            security_objectives=["Protect PII", "Ensure availability"],
            data_assets=["Patient records", "Medical images"],
            entry_points=["REST API", "Web portal"],
            trust_boundaries=["User to API", "API to database"],
            summary="Test application for healthcare"
        )
        
        assert info.application_name == "Test App"
        assert len(info.technologies) == 3
        assert info.architecture_type == "Microservices"
        assert info.deployment_environment == "AWS"
        assert info.sector == "Healthcare"
        assert len(info.security_objectives) == 2
        assert len(info.data_assets) == 2
        assert len(info.entry_points) == 2
        assert len(info.trust_boundaries) == 2
        assert info.summary == "Test application for healthcare"
    
    def test_project_info_security_objectives_as_list(self):
        """Test that security_objectives is properly handled as a list"""
        info = ProjectInfo(
            security_objectives=["Objective 1", "Objective 2", "Objective 3"]
        )
        
        assert isinstance(info.security_objectives, list)
        assert len(info.security_objectives) == 3
        assert "Objective 1" in info.security_objectives


class TestExtractionSummary:
    """Test ExtractionSummary model validation"""
    
    def test_extraction_summary_defaults(self):
        """Test creating ExtractionSummary with defaults"""
        summary = ExtractionSummary()
        
        assert summary.total_threats == 0
        assert summary.high_severity_count == 0
        assert summary.technologies_identified == 0
        assert summary.has_security_objectives is False
        assert summary.agent_based is True
        assert summary.threat_source == "ai_generated"
    
    def test_extraction_summary_full_data(self):
        """Test creating ExtractionSummary with complete data"""
        summary = ExtractionSummary(
            total_threats=15,
            high_severity_count=5,
            technologies_identified=8,
            has_security_objectives=True,
            agent_based=True,
            threat_source="user_provided"
        )
        
        assert summary.total_threats == 15
        assert summary.high_severity_count == 5
        assert summary.technologies_identified == 8
        assert summary.has_security_objectives is True
        assert summary.agent_based is True
        assert summary.threat_source == "user_provided"


class TestExtractedInfo:
    """Test ExtractedInfo model validation"""
    
    def test_extracted_info_defaults(self):
        """Test creating ExtractedInfo with defaults"""
        info = ExtractedInfo()
        
        assert info.threat_statements == []
        assert info.high_severity_threats == []
        assert isinstance(info.project_info, ProjectInfo)
        assert isinstance(info.extraction_summary, ExtractionSummary)
    
    def test_extracted_info_with_threats(self):
        """Test creating ExtractedInfo with threat data"""
        threat1 = {
            "id": "T001",
            "description": "Test threat",
            "severity": "High"
        }
        threat2 = {
            "id": "T002",
            "description": "Another threat",
            "severity": "Medium"
        }
        
        info = ExtractedInfo(
            threat_statements=[threat1, threat2],
            high_severity_threats=[threat1]
        )
        
        assert len(info.threat_statements) == 2
        assert len(info.high_severity_threats) == 1
        assert info.threat_statements[0]["id"] == "T001"
        assert info.high_severity_threats[0]["severity"] == "High"
    
    def test_extracted_info_with_nested_models(self):
        """Test ExtractedInfo with nested Pydantic models"""
        project = ProjectInfo(
            application_name="Test Project",
            technologies=["Python", "AWS"]
        )
        
        summary = ExtractionSummary(
            total_threats=10,
            high_severity_count=3
        )
        
        info = ExtractedInfo(
            project_info=project,
            extraction_summary=summary
        )
        
        assert info.project_info.application_name == "Test Project"
        assert len(info.project_info.technologies) == 2
        assert info.extraction_summary.total_threats == 10
        assert info.extraction_summary.high_severity_count == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
