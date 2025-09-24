"""
Unit tests for Information Extraction Agent.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime

from threatforest.agents.information_extraction import (
    InformationExtractionAgent,
    ExtractionResult
)
from threatforest.agents.context_detection import DetectedFile, FileType, FileFormat
from threatforest.models import ContextInformation, ValidationStatus
from threatforest.utils.bedrock_client import BedrockClient, BedrockResponse, BedrockClientError


class TestInformationExtractionAgent:
    """Test cases for InformationExtractionAgent."""
    
    @pytest.fixture
    def mock_bedrock_client(self):
        """Create a mock Bedrock client."""
        return Mock(spec=BedrockClient)
    
    @pytest.fixture
    def extraction_agent(self, mock_bedrock_client):
        """Create an InformationExtractionAgent instance."""
        return InformationExtractionAgent(mock_bedrock_client)
    
    @pytest.fixture
    def sample_detected_files(self):
        """Create sample detected files for testing."""
        return [
            DetectedFile(
                path=Path("README.md"),
                file_type=FileType.README,
                file_format=FileFormat.MARKDOWN,
                size_bytes=1024,
                confidence_score=0.9,
                metadata={},
                validation_errors=[]
            ),
            DetectedFile(
                path=Path("threats.json"),
                file_type=FileType.THREAT_STATEMENT,
                file_format=FileFormat.JSON,
                size_bytes=512,
                confidence_score=0.8,
                metadata={},
                validation_errors=[]
            )
        ]
    
    @pytest.fixture
    def sample_ai_response(self):
        """Sample AI response for testing."""
        return {
            "technologies": ["React", "Node.js", "PostgreSQL"],
            "programming_languages": ["JavaScript", "TypeScript"],
            "sector": "fintech",
            "security_objectives": ["confidentiality", "integrity"],
            "architecture_type": "microservices",
            "compliance_frameworks": ["pci-dss", "sox"],
            "confidence_score": 0.85,
            "reasoning": "Extracted from README and architecture documentation"
        }
    
    def test_init(self, mock_bedrock_client):
        """Test agent initialization."""
        agent = InformationExtractionAgent(mock_bedrock_client)
        
        assert agent.bedrock_client == mock_bedrock_client
        assert "security analyst assistant" in agent.system_prompt.lower()
        assert "json object" in agent.system_prompt.lower()
    
    def test_extract_information_success(self, extraction_agent, sample_detected_files, sample_ai_response):
        """Test successful information extraction."""
        # Mock file reading for both files
        def mock_file_open(filename, *args, **kwargs):
            if "README.md" in str(filename):
                return mock_open(read_data="Sample README content").return_value
            elif "threats.json" in str(filename):
                return mock_open(read_data='{"threats": []}').return_value
            else:
                return mock_open(read_data="Default content").return_value
        
        # Mock file system checks to make files appear valid and readable
        with patch('builtins.open', side_effect=mock_file_open), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_file', return_value=True), \
             patch('os.access', return_value=True):
            
            # Mock AI response
            mock_response = BedrockResponse(
                content=json.dumps(sample_ai_response),
                model_id="test-model",
                input_tokens=100,
                output_tokens=200
            )
            extraction_agent.bedrock_client.invoke_model.return_value = mock_response
            
            # Execute extraction
            result = extraction_agent.extract_information(sample_detected_files)
            
            # Verify result
            assert isinstance(result, ExtractionResult)
            assert result.extraction_confidence == 0.85
            assert len(result.source_files) == 2
            assert len(result.processing_errors) == 0
            
            # Verify context info
            context_info = result.context_info
            assert context_info.technologies == ["React", "Node.js", "PostgreSQL"]
            assert context_info.programming_languages == ["JavaScript", "TypeScript"]
            assert context_info.sector == "fintech"
            assert context_info.security_objectives == ["confidentiality", "integrity"]
            assert context_info.architecture_type == "microservices"
            assert context_info.compliance_frameworks == ["pci-dss", "sox"]
            assert context_info.validation_status == ValidationStatus.PENDING
    
    def test_extract_information_no_valid_files(self, extraction_agent):
        """Test extraction with no valid files."""
        invalid_files = [
            DetectedFile(
                path=Path("invalid.txt"),
                file_type=FileType.UNKNOWN,
                file_format=FileFormat.TEXT,
                size_bytes=0,
                confidence_score=0.1,
                metadata={},
                validation_errors=["File is empty"]
            )
        ]
        
        result = extraction_agent.extract_information(invalid_files)
        
        assert result.extraction_confidence == 0.0
        assert len(result.processing_errors) > 0
        assert "No valid files available" in result.processing_errors[0]
    
    def test_extract_information_ai_error(self, extraction_agent, sample_detected_files):
        """Test extraction with AI error."""
        def mock_file_open(filename, *args, **kwargs):
            return mock_open(read_data="Sample content").return_value
        
        with patch('builtins.open', side_effect=mock_file_open):
            # Mock AI error
            extraction_agent.bedrock_client.invoke_model.side_effect = BedrockClientError("API error")
            
            result = extraction_agent.extract_information(sample_detected_files)
            
            assert result.extraction_confidence == 0.0
            assert len(result.processing_errors) > 0
            assert "Error during AI extraction" in result.processing_errors[0]
    
    def test_prepare_content_for_analysis(self, extraction_agent, sample_detected_files):
        """Test content preparation for AI analysis."""
        def mock_file_open(filename, *args, **kwargs):
            return mock_open(read_data="Sample file content").return_value
        
        with patch('builtins.open', side_effect=mock_file_open):
            content = extraction_agent._prepare_content_for_analysis(sample_detected_files)
            
            assert "README:" in content
            assert "THREAT_STATEMENT:" in content
            assert "Sample file content" in content
    
    def test_extract_file_content_text_file(self, extraction_agent):
        """Test extracting content from text file."""
        file_info = DetectedFile(
            path=Path("test.md"),
            file_type=FileType.README,
            file_format=FileFormat.MARKDOWN,
            size_bytes=100,
            confidence_score=0.9,
            metadata={},
            validation_errors=[]
        )
        
        with patch('builtins.open', mock_open(read_data="Test content")):
            content = extraction_agent._extract_file_content(file_info)
            assert content == "Test content"
    
    def test_extract_file_content_binary_file(self, extraction_agent):
        """Test extracting content from binary file."""
        file_info = DetectedFile(
            path=Path("diagram.png"),
            file_type=FileType.ARCHITECTURE_DIAGRAM,
            file_format=FileFormat.PNG,
            size_bytes=2048,
            confidence_score=0.8,
            metadata={},
            validation_errors=[]
        )
        
        content = extraction_agent._extract_file_content(file_info)
        assert "Binary file: png" in content
        assert "2048 bytes" in content
    
    def test_extract_file_content_large_file(self, extraction_agent):
        """Test extracting content from large file."""
        file_info = DetectedFile(
            path=Path("large.md"),
            file_type=FileType.DOCUMENTATION,
            file_format=FileFormat.MARKDOWN,
            size_bytes=20000,
            confidence_score=0.7,
            metadata={},
            validation_errors=[]
        )
        
        large_content = "A" * 15000
        with patch('builtins.open', mock_open(read_data=large_content)):
            content = extraction_agent._extract_file_content(file_info)
            assert "MIDDLE CONTENT TRUNCATED" in content
            assert len(content) < len(large_content)
    
    def test_extract_with_ai_success(self, extraction_agent, sample_ai_response):
        """Test successful AI extraction."""
        mock_response = BedrockResponse(
            content=json.dumps(sample_ai_response),
            model_id="test-model",
            input_tokens=100,
            output_tokens=200
        )
        extraction_agent.bedrock_client.invoke_model.return_value = mock_response
        
        result = extraction_agent._extract_with_ai("Test content")
        
        assert result["technologies"] == ["React", "Node.js", "PostgreSQL"]
        assert result["confidence_score"] == 0.85
        assert "reasoning" in result
    
    def test_extract_with_ai_invalid_json(self, extraction_agent):
        """Test AI extraction with invalid JSON response."""
        mock_response = BedrockResponse(
            content="Invalid JSON response",
            model_id="test-model",
            input_tokens=100,
            output_tokens=50
        )
        extraction_agent.bedrock_client.invoke_model.return_value = mock_response
        
        with pytest.raises(BedrockClientError, match="Invalid JSON response"):
            extraction_agent._extract_with_ai("Test content")
    
    def test_validate_and_clean_extraction(self, extraction_agent):
        """Test validation and cleaning of extraction results."""
        raw_result = {
            "technologies": ["React", "", "Node.js", None],
            "programming_languages": "JavaScript",  # Wrong type
            "security_objectives": ["Confidentiality", "INTEGRITY", "invalid"],
            "compliance_frameworks": ["PCI-DSS", "SOX"],
            "confidence_score": "0.85",  # String instead of float
            "sector": "  fintech  ",  # Extra whitespace
            "reasoning": ""
        }
        
        cleaned = extraction_agent._validate_and_clean_extraction(raw_result)
        
        assert cleaned["technologies"] == ["React", "Node.js"]
        assert cleaned["programming_languages"] == []
        assert cleaned["security_objectives"] == ["confidentiality", "integrity"]
        assert cleaned["compliance_frameworks"] == ["pci-dss", "sox"]
        assert cleaned["confidence_score"] == 0.85
        assert cleaned["sector"] == "fintech"
        assert cleaned["reasoning"] == "No reasoning provided"
    
    def test_validate_with_user_high_confidence(self, extraction_agent):
        """Test user validation with high confidence extraction."""
        context_info = ContextInformation(
            technologies=["React"],
            confidence_score=0.9,
            validation_status=ValidationStatus.PENDING
        )
        
        extraction_result = ExtractionResult(
            context_info=context_info,
            extraction_confidence=0.9,
            source_files=[],
            processing_errors=[],
            ai_reasoning="High confidence"
        )
        
        validated = extraction_agent.validate_with_user(extraction_result)
        
        assert validated.validation_status == ValidationStatus.APPROVED
    
    def test_validate_with_user_low_confidence(self, extraction_agent):
        """Test user validation with low confidence extraction."""
        context_info = ContextInformation(
            technologies=["React"],
            confidence_score=0.5,
            validation_status=ValidationStatus.PENDING
        )
        
        extraction_result = ExtractionResult(
            context_info=context_info,
            extraction_confidence=0.5,
            source_files=[],
            processing_errors=[],
            ai_reasoning="Low confidence"
        )
        
        validated = extraction_agent.validate_with_user(extraction_result)
        
        assert validated.validation_status == ValidationStatus.PENDING
    
    def test_save_extracted_information(self, extraction_agent, tmp_path):
        """Test saving extracted information to file."""
        context_info = ContextInformation(
            technologies=["React", "Node.js"],
            programming_languages=["JavaScript"],
            sector="fintech",
            security_objectives=["confidentiality", "integrity"],
            architecture_type="microservices",
            compliance_frameworks=["pci-dss"],
            extracted_from=["README.md", "threats.json"],
            validation_status=ValidationStatus.APPROVED,
            confidence_score=0.85
        )
        
        output_file = extraction_agent.save_extracted_information(
            context_info, str(tmp_path)
        )
        
        assert output_file.exists()
        assert output_file.name == "extracted_context_info.md"
        
        content = output_file.read_text()
        assert "# Extracted Context Information" in content
        assert "React" in content
        assert "JavaScript" in content
        assert "fintech" in content
        assert "Confidentiality" in content
        assert "microservices" in content
        assert "PCI-DSS" in content
        assert "README.md" in content
    
    def test_save_extracted_information_minimal(self, extraction_agent, tmp_path):
        """Test saving minimal extracted information."""
        context_info = ContextInformation(
            validation_status=ValidationStatus.APPROVED,
            confidence_score=0.5
        )
        
        output_file = extraction_agent.save_extracted_information(
            context_info, str(tmp_path), include_metadata=False
        )
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "# Extracted Context Information" in content
        assert "README.md" not in content  # No source files section
    
    def test_update_extraction(self, extraction_agent):
        """Test updating extraction based on user feedback."""
        original_info = ContextInformation(
            technologies=["React"],
            programming_languages=["JavaScript"],
            validation_status=ValidationStatus.PENDING
        )
        
        updates = {
            "technologies": ["React", "Vue.js"],
            "sector": "healthcare"
        }
        
        updated_info = extraction_agent.update_extraction(original_info, updates)
        
        assert updated_info.technologies == ["React", "Vue.js"]
        assert updated_info.sector == "healthcare"
        assert updated_info.programming_languages == ["JavaScript"]  # Unchanged
        assert updated_info.validation_status == ValidationStatus.MODIFIED
    
    def test_create_empty_result(self, extraction_agent):
        """Test creating empty result with errors."""
        errors = ["Test error 1", "Test error 2"]
        
        result = extraction_agent._create_empty_result(errors)
        
        assert result.extraction_confidence == 0.0
        assert result.processing_errors == errors
        assert result.context_info.validation_status == ValidationStatus.REJECTED
        assert result.context_info.confidence_score == 0.0
    
    def test_extraction_result_is_high_confidence(self):
        """Test ExtractionResult confidence checking."""
        # High confidence
        high_confidence_result = ExtractionResult(
            context_info=ContextInformation(),
            extraction_confidence=0.8,
            source_files=[],
            processing_errors=[],
            ai_reasoning=""
        )
        assert high_confidence_result.is_high_confidence()
        
        # Low confidence
        low_confidence_result = ExtractionResult(
            context_info=ContextInformation(),
            extraction_confidence=0.6,
            source_files=[],
            processing_errors=[],
            ai_reasoning=""
        )
        assert not low_confidence_result.is_high_confidence()
        
        # Custom threshold
        assert low_confidence_result.is_high_confidence(threshold=0.5)