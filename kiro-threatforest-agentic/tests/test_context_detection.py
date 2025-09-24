"""
Unit tests for Context Detection Agent.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest
import yaml

from threatforest.config import FileConfig
from threatforest.agents.context_detection import (
    ContextDetectionAgent,
    DetectedFile,
    ContextScanResult,
    FileType,
    FileFormat
)


class TestDetectedFile:
    """Test cases for DetectedFile dataclass."""
    
    def test_detected_file_creation(self):
        """Test basic DetectedFile creation."""
        file_path = Path("/test/README.md")
        detected_file = DetectedFile(
            path=file_path,
            file_type=FileType.README,
            file_format=FileFormat.MARKDOWN,
            size_bytes=1024,
            confidence_score=0.9,
            metadata={},
            validation_errors=[]
        )
        
        assert detected_file.path == file_path
        assert detected_file.file_type == FileType.README
        assert detected_file.file_format == FileFormat.MARKDOWN
        assert detected_file.confidence_score == 0.9
        assert detected_file.is_valid()
    
    def test_detected_file_invalid(self):
        """Test DetectedFile with validation errors."""
        detected_file = DetectedFile(
            path=Path("/test/invalid.md"),
            file_type=FileType.README,
            file_format=FileFormat.MARKDOWN,
            size_bytes=1024,
            confidence_score=0.9,
            metadata={},
            validation_errors=["File is corrupted"]
        )
        
        assert not detected_file.is_valid()
    
    def test_detected_file_low_confidence(self):
        """Test DetectedFile with low confidence score."""
        detected_file = DetectedFile(
            path=Path("/test/unknown.txt"),
            file_type=FileType.UNKNOWN,
            file_format=FileFormat.TEXT,
            size_bytes=1024,
            confidence_score=0.3,
            metadata={},
            validation_errors=[]
        )
        
        assert not detected_file.is_valid()


class TestContextScanResult:
    """Test cases for ContextScanResult dataclass."""
    
    def test_context_scan_result_creation(self):
        """Test basic ContextScanResult creation."""
        directory = Path("/test/project")
        detected_files = [
            DetectedFile(
                path=Path("/test/project/README.md"),
                file_type=FileType.README,
                file_format=FileFormat.MARKDOWN,
                size_bytes=1024,
                confidence_score=0.9,
                metadata={},
                validation_errors=[]
            )
        ]
        
        result = ContextScanResult(
            directory=directory,
            detected_files=detected_files,
            scan_patterns=["README*"],
            total_files_scanned=5,
            processing_errors=[]
        )
        
        assert result.directory == directory
        assert len(result.detected_files) == 1
        assert result.total_files_scanned == 5
    
    def test_get_files_by_type(self):
        """Test filtering files by type."""
        detected_files = [
            DetectedFile(
                path=Path("/test/README.md"),
                file_type=FileType.README,
                file_format=FileFormat.MARKDOWN,
                size_bytes=1024,
                confidence_score=0.9,
                metadata={},
                validation_errors=[]
            ),
            DetectedFile(
                path=Path("/test/threats.md"),
                file_type=FileType.THREAT_STATEMENT,
                file_format=FileFormat.MARKDOWN,
                size_bytes=2048,
                confidence_score=0.8,
                metadata={},
                validation_errors=[]
            )
        ]
        
        result = ContextScanResult(
            directory=Path("/test"),
            detected_files=detected_files,
            scan_patterns=["*"],
            total_files_scanned=2,
            processing_errors=[]
        )
        
        readme_files = result.get_files_by_type(FileType.README)
        threat_files = result.get_files_by_type(FileType.THREAT_STATEMENT)
        
        assert len(readme_files) == 1
        assert len(threat_files) == 1
        assert readme_files[0].file_type == FileType.README
        assert threat_files[0].file_type == FileType.THREAT_STATEMENT
    
    def test_get_valid_files(self):
        """Test filtering valid files."""
        detected_files = [
            DetectedFile(
                path=Path("/test/valid.md"),
                file_type=FileType.README,
                file_format=FileFormat.MARKDOWN,
                size_bytes=1024,
                confidence_score=0.9,
                metadata={},
                validation_errors=[]
            ),
            DetectedFile(
                path=Path("/test/invalid.md"),
                file_type=FileType.README,
                file_format=FileFormat.MARKDOWN,
                size_bytes=1024,
                confidence_score=0.9,
                metadata={},
                validation_errors=["Validation error"]
            )
        ]
        
        result = ContextScanResult(
            directory=Path("/test"),
            detected_files=detected_files,
            scan_patterns=["*"],
            total_files_scanned=2,
            processing_errors=[]
        )
        
        valid_files = result.get_valid_files()
        assert len(valid_files) == 1
        assert valid_files[0].path.name == "valid.md"
    
    def test_has_required_files(self):
        """Test checking for required files."""
        # Test with README file
        readme_result = ContextScanResult(
            directory=Path("/test"),
            detected_files=[
                DetectedFile(
                    path=Path("/test/README.md"),
                    file_type=FileType.README,
                    file_format=FileFormat.MARKDOWN,
                    size_bytes=1024,
                    confidence_score=0.9,
                    metadata={},
                    validation_errors=[]
                )
            ],
            scan_patterns=["*"],
            total_files_scanned=1,
            processing_errors=[]
        )
        
        assert readme_result.has_required_files()
        
        # Test with threat statement file
        threat_result = ContextScanResult(
            directory=Path("/test"),
            detected_files=[
                DetectedFile(
                    path=Path("/test/threats.md"),
                    file_type=FileType.THREAT_STATEMENT,
                    file_format=FileFormat.MARKDOWN,
                    size_bytes=1024,
                    confidence_score=0.9,
                    metadata={},
                    validation_errors=[]
                )
            ],
            scan_patterns=["*"],
            total_files_scanned=1,
            processing_errors=[]
        )
        
        assert threat_result.has_required_files()
        
        # Test without required files
        empty_result = ContextScanResult(
            directory=Path("/test"),
            detected_files=[],
            scan_patterns=["*"],
            total_files_scanned=0,
            processing_errors=[]
        )
        
        assert not empty_result.has_required_files()


class TestContextDetectionAgent:
    """Test cases for ContextDetectionAgent class."""
    
    def setup_method(self):
        """Set up test environment."""
        self.config = FileConfig(
            context_patterns=[
                "README*",
                "readme*",
                "architecture.*",
                "dataflow.*",
                "threats.*",
                "threat-*.json"
            ]
        )
        self.agent = ContextDetectionAgent(self.config)
    
    def test_agent_initialization(self):
        """Test agent initialization."""
        assert self.agent.config == self.config
        assert len(self.agent.readme_patterns) > 0
        assert len(self.agent.architecture_patterns) > 0
        assert len(self.agent.dataflow_patterns) > 0
        assert len(self.agent.threat_patterns) > 0
    
    def test_detect_file_format(self):
        """Test file format detection."""
        test_cases = [
            ("README.md", FileFormat.MARKDOWN),
            ("config.json", FileFormat.JSON),
            ("data.yaml", FileFormat.YAML),
            ("diagram.png", FileFormat.PNG),
            ("flow.svg", FileFormat.SVG),
            ("chart.mmd", FileFormat.MERMAID),
            ("doc.pdf", FileFormat.PDF),
            ("notes.txt", FileFormat.TEXT),
            ("unknown.xyz", FileFormat.UNKNOWN),
        ]
        
        for filename, expected_format in test_cases:
            file_path = Path(filename)
            detected_format = self.agent._detect_file_format(file_path)
            assert detected_format == expected_format, f"Failed for {filename}"
    
    def test_classify_readme_file(self):
        """Test README file classification."""
        test_cases = [
            "README.md",
            "readme.txt",
            "README",
            "Readme.markdown"
        ]
        
        for filename in test_cases:
            file_path = Path(filename)
            file_format = self.agent._detect_file_format(file_path)
            file_type, confidence, metadata = self.agent._classify_file(file_path, file_format)
            
            assert file_type == FileType.README
            assert confidence > 0.5
    
    def test_classify_architecture_file(self):
        """Test architecture file classification."""
        test_cases = [
            "architecture.png",
            "system-architecture.svg",
            "arch-diagram.jpg",
            "system.design.pdf"
        ]
        
        for filename in test_cases:
            file_path = Path(filename)
            file_format = self.agent._detect_file_format(file_path)
            file_type, confidence, metadata = self.agent._classify_file(file_path, file_format)
            
            assert file_type == FileType.ARCHITECTURE_DIAGRAM
    
    def test_classify_dataflow_file(self):
        """Test data flow file classification."""
        test_cases = [
            "dataflow.png",
            "data-flow-diagram.svg",
            "dfd.mmd",
            "data.flow.md"
        ]
        
        for filename in test_cases:
            file_path = Path(filename)
            file_format = self.agent._detect_file_format(file_path)
            file_type, confidence, metadata = self.agent._classify_file(file_path, file_format)
            
            assert file_type == FileType.DATA_FLOW_DIAGRAM
    
    def test_classify_threat_file(self):
        """Test threat file classification."""
        test_cases = [
            "threats.md",
            "threat-model.json",
            "security-threats.yaml",
            "threat-analysis.yml"
        ]
        
        for filename in test_cases:
            file_path = Path(filename)
            file_format = self.agent._detect_file_format(file_path)
            file_type, confidence, metadata = self.agent._classify_file(file_path, file_format)
            
            assert file_type == FileType.THREAT_STATEMENT
    
    @patch('builtins.open', new_callable=mock_open, read_data="# Architecture Overview\nThis document describes the system architecture with microservices and databases.")
    def test_calculate_content_confidence(self, mock_file):
        """Test content-based confidence calculation."""
        file_path = Path("architecture.md")
        
        confidence = self.agent._calculate_content_confidence(file_path, self.agent.architecture_keywords)
        
        assert confidence > 0.5  # Should find architecture keywords
        mock_file.assert_called_once()
    
    @patch('builtins.open', new_callable=mock_open, read_data="# Threat Analysis\nThis document contains security threats and vulnerabilities.")
    def test_classify_by_content(self, mock_file):
        """Test content-based classification."""
        file_path = Path("security.md")
        
        file_type, confidence = self.agent._classify_by_content(file_path)
        
        assert file_type == FileType.THREAT_STATEMENT
        assert confidence > 0.4
        mock_file.assert_called_once()
    
    def test_validate_json_file_valid(self):
        """Test JSON file validation with valid content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"test": "data"}, f)
            f.flush()
            
            file_path = Path(f.name)
            errors = self.agent._validate_json_file(file_path)
            
            assert len(errors) == 0
            
            # Clean up
            file_path.unlink()
    
    def test_validate_json_file_invalid(self):
        """Test JSON file validation with invalid content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": json}')  # Missing quotes around json
            f.flush()
            
            file_path = Path(f.name)
            errors = self.agent._validate_json_file(file_path)
            
            assert len(errors) > 0
            assert "Invalid JSON format" in errors[0]
            
            # Clean up
            file_path.unlink()
    
    def test_validate_yaml_file_valid(self):
        """Test YAML file validation with valid content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({"test": "data"}, f)
            f.flush()
            
            file_path = Path(f.name)
            errors = self.agent._validate_yaml_file(file_path)
            
            assert len(errors) == 0
            
            # Clean up
            file_path.unlink()
    
    def test_validate_yaml_file_invalid(self):
        """Test YAML file validation with invalid content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('invalid: yaml: content: [')  # Invalid YAML
            f.flush()
            
            file_path = Path(f.name)
            errors = self.agent._validate_yaml_file(file_path)
            
            assert len(errors) > 0
            assert "Invalid YAML format" in errors[0]
            
            # Clean up
            file_path.unlink()
    
    @patch('builtins.open', new_callable=mock_open, read_data="This is a valid text file with sufficient content.")
    def test_validate_text_file_valid(self, mock_file):
        """Test text file validation with valid content."""
        file_path = Path("test.txt")
        
        errors = self.agent._validate_text_file(file_path)
        
        assert len(errors) == 0
        mock_file.assert_called()
    
    @patch('builtins.open', new_callable=mock_open, read_data="short")
    def test_validate_text_file_too_short(self, mock_file):
        """Test text file validation with content too short."""
        file_path = Path("test.txt")
        
        errors = self.agent._validate_text_file(file_path)
        
        assert len(errors) > 0
        assert "too short" in errors[0]
    
    @patch('builtins.open', new_callable=mock_open, read_data="# Threat Model\nThis document contains security threats and attack vectors.")
    def test_validate_threat_file_valid(self, mock_file):
        """Test threat file validation with valid content."""
        file_path = Path("threats.md")
        
        errors = self.agent._validate_threat_file(file_path, FileFormat.MARKDOWN)
        
        assert len(errors) == 0
        mock_file.assert_called()
    
    @patch('builtins.open', new_callable=mock_open, read_data="This file has no threat-related content.")
    def test_validate_threat_file_no_threats(self, mock_file):
        """Test threat file validation without threat content."""
        file_path = Path("threats.md")
        
        errors = self.agent._validate_threat_file(file_path, FileFormat.MARKDOWN)
        
        assert len(errors) > 0
        assert "threat-related content" in errors[0]
    
    def test_scan_directory_nonexistent(self):
        """Test scanning nonexistent directory."""
        with pytest.raises(ValueError, match="Directory does not exist"):
            self.agent.scan_directory("/nonexistent/directory")
    
    def test_scan_directory_empty(self):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.agent.scan_directory(temp_dir)
            
            assert result.directory == Path(temp_dir).resolve()
            assert len(result.detected_files) == 0
            assert result.total_files_scanned == 0
            assert len(result.processing_errors) == 0
    
    def test_scan_directory_with_files(self):
        """Test scanning directory with context files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files
            readme_file = temp_path / "README.md"
            readme_file.write_text("# Test Project\nThis is a test project.")
            
            threats_file = temp_path / "threats.md"
            threats_file.write_text("# Threats\nSecurity threats and vulnerabilities.")
            
            # Create a file that doesn't match patterns
            other_file = temp_path / "other.txt"
            other_file.write_text("Other content")
            
            result = self.agent.scan_directory(temp_dir)
            
            assert result.directory == Path(temp_dir).resolve()
            assert len(result.detected_files) == 2  # README and threats
            assert result.total_files_scanned == 2
            
            # Check file types
            file_types = {f.file_type for f in result.detected_files}
            assert FileType.README in file_types
            assert FileType.THREAT_STATEMENT in file_types
            
            # Check that result has required files
            assert result.has_required_files()
    
    @patch('pathlib.Path.glob')
    def test_scan_directory_with_errors(self, mock_glob):
        """Test scanning directory with processing errors."""
        # Mock glob to raise an exception
        mock_glob.side_effect = Exception("Glob error")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.agent.scan_directory(temp_dir)
            
            assert len(result.processing_errors) > 0
            assert "Glob error" in str(result.processing_errors)