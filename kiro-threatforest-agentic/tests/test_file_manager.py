"""
Unit tests for File Manager.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime

from threatforest.utils.file_manager import (
    FileManager,
    OutputSummary,
    FileManagerError
)
from threatforest.models import (
    AttackTree,
    AttackStep,
    ThreatStatement,
    ContextInformation,
    AnalysisResult,
    TTCMapping,
    AttackStepType,
    SeverityLevel,
    ValidationStatus
)
from threatforest.agents.context_detection import DetectedFile, FileType, FileFormat


class TestOutputSummary:
    """Test cases for OutputSummary."""
    
    def test_get_file_count_by_type(self, tmp_path):
        """Test file count calculation by type."""
        summary = OutputSummary(
            output_directory=tmp_path,
            attack_tree_files=[tmp_path / "tree1.mmd", tmp_path / "tree2.mmd"],
            summary_report_file=tmp_path / "summary.md",
            context_info_file=tmp_path / "context.md",
            threat_statements_file=tmp_path / "threats.json",
            total_files_created=5,
            generation_timestamp=datetime.now()
        )
        
        counts = summary.get_file_count_by_type()
        
        assert counts["attack_trees"] == 2
        assert counts["summary_report"] == 1
        assert counts["context_info"] == 1
        assert counts["threat_statements"] == 1
    
    def test_get_file_count_by_type_partial(self, tmp_path):
        """Test file count with some missing files."""
        summary = OutputSummary(
            output_directory=tmp_path,
            attack_tree_files=[tmp_path / "tree1.mmd"],
            summary_report_file=None,
            context_info_file=tmp_path / "context.md",
            threat_statements_file=None,
            total_files_created=2,
            generation_timestamp=datetime.now()
        )
        
        counts = summary.get_file_count_by_type()
        
        assert counts["attack_trees"] == 1
        assert counts["summary_report"] == 0
        assert counts["context_info"] == 1
        assert counts["threat_statements"] == 0


class TestFileManager:
    """Test cases for FileManager."""
    
    @pytest.fixture
    def file_manager(self, tmp_path):
        """Create a FileManager instance with temporary directory."""
        return FileManager(str(tmp_path / "tf-output"))
    
    @pytest.fixture
    def sample_attack_tree(self):
        """Create a sample attack tree."""
        return AttackTree(
            threat_id="test-threat-001",
            title="SQL Injection Attack",
            mermaid_content="graph TD\n    A[Reconnaissance] --> B[SQL Injection]",
            attack_steps=[
                AttackStep(
                    id="step1",
                    description="Perform reconnaissance",
                    step_type=AttackStepType.ATTACK,
                    dependencies=[],
                    ttc_reference=None
                ),
                AttackStep(
                    id="step2",
                    description="Execute SQL injection",
                    step_type=AttackStepType.ATTACK,
                    dependencies=["step1"],
                    ttc_reference="T1190"
                )
            ],
            ttc_mappings={
                "step2": TTCMapping(
                    attack_step_id="step2",
                    ttc_technique_id="attack-pattern--test",
                    ttc_technique_name="SQL Injection",
                    alignment_score=0.9,
                    stix_data={},
                    applied=True
                )
            },
            generated_timestamp=datetime.now()
        )
    
    @pytest.fixture
    def sample_context_info(self):
        """Create sample context information."""
        return ContextInformation(
            technologies=["React", "Node.js", "PostgreSQL"],
            programming_languages=["JavaScript", "TypeScript"],
            sector="fintech",
            security_objectives=["confidentiality", "integrity"],
            architecture_type="microservices",
            compliance_frameworks=["pci-dss"],
            extracted_from=["README.md", "threats.json"],
            validation_status=ValidationStatus.APPROVED,
            confidence_score=0.85
        )
    
    @pytest.fixture
    def sample_threat_statements(self):
        """Create sample threat statements."""
        return [
            ThreatStatement(
                id="threat-001",
                severity=SeverityLevel.HIGH,
                threat_source="External Attacker",
                prerequisites="Network access",
                threat_action="SQL Injection Attack",
                threat_impact="Data breach",
                impacted_assets=["Database"],
                impacted_goals=["confidentiality"],
                raw_statement="Attacker performs SQL injection"
            ),
            ThreatStatement(
                id="threat-002",
                severity=SeverityLevel.MEDIUM,
                threat_source="Insider",
                prerequisites="System access",
                threat_action="Data exfiltration",
                threat_impact="Data loss",
                impacted_assets=["Files"],
                impacted_goals=["confidentiality"],
                raw_statement="Insider exfiltrates data"
            )
        ]
    
    @pytest.fixture
    def sample_analysis_result(self, sample_context_info, sample_threat_statements, sample_attack_tree):
        """Create sample analysis result."""
        return AnalysisResult(
            context_info=sample_context_info,
            threat_statements=sample_threat_statements,
            attack_trees=[sample_attack_tree],
            analysis_timestamp=datetime.now(),
            source_directory="/test/source",
            output_directory="/test/output"
        )
    
    def test_init(self, tmp_path):
        """Test FileManager initialization."""
        fm = FileManager(str(tmp_path))
        
        assert fm.base_output_dir == tmp_path
        assert fm.current_session_dir is None
        assert '.md' in fm.supported_formats
        assert '.json' in fm.supported_formats
    
    def test_create_session_directory(self, file_manager):
        """Test session directory creation."""
        session_dir = file_manager.create_session_directory("test_session")
        
        assert session_dir.exists()
        assert session_dir.is_dir()
        assert session_dir.name == "test_session"
        assert file_manager.current_session_dir == session_dir
    
    def test_create_session_directory_auto_name(self, file_manager):
        """Test session directory creation with auto-generated name."""
        session_dir = file_manager.create_session_directory()
        
        assert session_dir.exists()
        assert session_dir.name.startswith("session_")
        assert file_manager.current_session_dir == session_dir
    
    def test_get_session_directory_existing(self, file_manager):
        """Test getting existing session directory."""
        created_dir = file_manager.create_session_directory("existing")
        retrieved_dir = file_manager.get_session_directory()
        
        assert retrieved_dir == created_dir
    
    def test_get_session_directory_create_new(self, file_manager):
        """Test getting session directory when none exists."""
        session_dir = file_manager.get_session_directory()
        
        assert session_dir.exists()
        assert session_dir.name.startswith("session_")
    
    def test_read_context_file_markdown(self, file_manager, tmp_path):
        """Test reading markdown context file."""
        test_file = tmp_path / "test.md"
        test_content = "# Test README\n\nThis is a test file."
        
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        content, metadata = file_manager.read_context_file(test_file)
        
        assert content == test_content
        assert metadata['file_format'] == 'markdown'
        assert metadata['file_size'] > 0
        assert 'read_timestamp' in metadata
    
    def test_read_context_file_json(self, file_manager, tmp_path):
        """Test reading JSON context file."""
        test_file = tmp_path / "test.json"
        test_data = {"threats": [{"id": "T1", "severity": "high"}]}
        
        with open(test_file, 'w') as f:
            json.dump(test_data, f)
        
        content, metadata = file_manager.read_context_file(test_file)
        
        assert json.loads(content) == test_data
        assert metadata['file_format'] == 'json'
        assert metadata['parsed_data'] == test_data
    
    def test_read_context_file_not_found(self, file_manager, tmp_path):
        """Test reading non-existent file."""
        test_file = tmp_path / "nonexistent.md"
        
        with pytest.raises(FileManagerError, match="Context file not found"):
            file_manager.read_context_file(test_file)
    
    def test_read_multiple_context_files(self, file_manager, tmp_path):
        """Test reading multiple context files."""
        # Create test files
        file1 = tmp_path / "README.md"
        file2 = tmp_path / "threats.json"
        
        with open(file1, 'w') as f:
            f.write("# README")
        
        with open(file2, 'w') as f:
            json.dump({"threats": []}, f)
        
        # Create DetectedFile objects
        detected_files = [
            DetectedFile(
                path=file1,
                file_type=FileType.README,
                file_format=FileFormat.MARKDOWN,
                size_bytes=100,
                confidence_score=0.9,
                metadata={},
                validation_errors=[]
            ),
            DetectedFile(
                path=file2,
                file_type=FileType.THREAT_STATEMENT,
                file_format=FileFormat.JSON,
                size_bytes=50,
                confidence_score=0.8,
                metadata={},
                validation_errors=[]
            )
        ]
        
        # Mock file system checks
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_file', return_value=True), \
             patch('os.access', return_value=True):
            
            results = file_manager.read_multiple_context_files(detected_files)
        
        assert len(results) == 2
        assert str(file1) in results
        assert str(file2) in results
    
    def test_write_attack_tree(self, file_manager, sample_attack_tree, tmp_path):
        """Test writing attack tree to file."""
        output_file = file_manager.write_attack_tree(sample_attack_tree, tmp_path)
        
        assert output_file.exists()
        assert output_file.suffix == '.mmd'
        
        content = output_file.read_text()
        assert "# Attack Tree: SQL Injection Attack" in content
        assert "test-threat-001" in content
        assert "```mermaid" in content
        assert "graph TD" in content
        assert "## Attack Steps Details" in content
        assert "## TTC Mappings" in content
    
    def test_write_multiple_attack_trees(self, file_manager, sample_attack_tree, tmp_path):
        """Test writing multiple attack trees."""
        # Create second attack tree
        attack_tree2 = AttackTree(
            threat_id="test-threat-002",
            title="XSS Attack",
            mermaid_content="graph TD\n    A[XSS] --> B[Data Theft]",
            attack_steps=[],
            ttc_mappings={},
            generated_timestamp=datetime.now()
        )
        
        attack_trees = [sample_attack_tree, attack_tree2]
        output_files = file_manager.write_multiple_attack_trees(attack_trees, tmp_path)
        
        assert len(output_files) == 2
        assert all(f.exists() for f in output_files)
        assert all(f.suffix == '.mmd' for f in output_files)
    
    def test_write_context_information(self, file_manager, sample_context_info, tmp_path):
        """Test writing context information."""
        output_file = file_manager.write_context_information(sample_context_info, tmp_path)
        
        assert output_file.exists()
        assert output_file.name == "context_information.md"
        
        content = output_file.read_text()
        assert "# Context Information" in content
        assert "React" in content
        assert "JavaScript" in content
        assert "fintech" in content
        assert "Confidentiality" in content
        assert "PCI-DSS" in content
    
    def test_write_threat_statements(self, file_manager, sample_threat_statements, tmp_path):
        """Test writing threat statements."""
        output_file = file_manager.write_threat_statements(sample_threat_statements, tmp_path)
        
        assert output_file.exists()
        assert output_file.name == "threat_statements.json"
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert len(data) == 2
        assert data[0]['id'] == 'threat-001'
        assert data[0]['severity'] == 'high'
        assert data[1]['severity'] == 'medium'
    
    def test_generate_summary_report(self, file_manager, sample_analysis_result, tmp_path):
        """Test generating summary report."""
        output_file = file_manager.generate_summary_report(sample_analysis_result, tmp_path)
        
        assert output_file.exists()
        assert output_file.name == "analysis_summary.md"
        
        content = output_file.read_text()
        assert "# ThreatForest Analysis Summary" in content
        assert "**Total Threat Statements:** 2" in content
        assert "**High-Severity Threats:** 1" in content
        assert "**Attack Trees Generated:** 1" in content
        assert "SQL Injection Attack" in content
        assert "React, Node.js, PostgreSQL" in content
    
    def test_generate_complete_output(self, file_manager, sample_analysis_result, tmp_path):
        """Test generating complete output."""
        output_summary = file_manager.generate_complete_output(sample_analysis_result, tmp_path)
        
        assert isinstance(output_summary, OutputSummary)
        assert output_summary.output_directory == tmp_path
        assert len(output_summary.attack_tree_files) == 1
        assert output_summary.summary_report_file is not None
        assert output_summary.context_info_file is not None
        assert output_summary.threat_statements_file is not None
        assert output_summary.total_files_created == 4
        
        # Verify all files exist
        assert all(f.exists() for f in output_summary.attack_tree_files)
        assert output_summary.summary_report_file.exists()
        assert output_summary.context_info_file.exists()
        assert output_summary.threat_statements_file.exists()
    
    def test_sanitize_filename(self, file_manager):
        """Test filename sanitization."""
        # Test invalid characters
        assert file_manager._sanitize_filename("test<>file") == "test_file"
        assert file_manager._sanitize_filename("test/file") == "test_file"
        assert file_manager._sanitize_filename("test file") == "test_file"
        
        # Test multiple underscores
        assert file_manager._sanitize_filename("test___file") == "test_file"
        
        # Test empty string
        assert file_manager._sanitize_filename("") == "unnamed"
        
        # Test long filename
        long_name = "a" * 150
        sanitized = file_manager._sanitize_filename(long_name)
        assert len(sanitized) <= 100
    
    def test_cleanup_old_sessions(self, file_manager, tmp_path):
        """Test cleaning up old session directories."""
        # Create multiple session directories
        base_dir = file_manager.base_output_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        
        session_dirs = []
        for i in range(5):
            session_dir = base_dir / f"session_{i:04d}"
            session_dir.mkdir()
            session_dirs.append(session_dir)
        
        # Clean up, keeping only 3 recent
        removed_count = file_manager.cleanup_old_sessions(keep_recent=3)
        
        assert removed_count == 2
        
        # Check that 3 directories remain
        remaining_dirs = [d for d in base_dir.iterdir() if d.is_dir() and d.name.startswith('session_')]
        assert len(remaining_dirs) == 3
    
    def test_cleanup_old_sessions_no_sessions(self, file_manager):
        """Test cleanup when no session directories exist."""
        removed_count = file_manager.cleanup_old_sessions()
        assert removed_count == 0
    
    def test_write_attack_tree_error_handling(self, file_manager, sample_attack_tree):
        """Test error handling in attack tree writing."""
        # Try to write to a read-only directory
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with pytest.raises(FileManagerError, match="Error writing attack tree"):
                file_manager.write_attack_tree(sample_attack_tree)
    
    def test_read_context_file_invalid_json(self, file_manager, tmp_path):
        """Test reading invalid JSON file."""
        test_file = tmp_path / "invalid.json"
        
        with open(test_file, 'w') as f:
            f.write("invalid json content")
        
        # Should still read the content but warn about invalid JSON
        content, metadata = file_manager.read_context_file(test_file)
        
        assert content == "invalid json content"
        assert metadata['file_format'] == 'json'
        assert metadata['parsed_data'] is None  # Should be None due to parse error
    
    def test_write_context_information_custom_filename(self, file_manager, sample_context_info, tmp_path):
        """Test writing context information with custom filename."""
        custom_filename = "custom_context.md"
        output_file = file_manager.write_context_information(
            sample_context_info, tmp_path, custom_filename
        )
        
        assert output_file.name == custom_filename
        assert output_file.exists()
    
    def test_write_threat_statements_custom_filename(self, file_manager, sample_threat_statements, tmp_path):
        """Test writing threat statements with custom filename."""
        custom_filename = "custom_threats.json"
        output_file = file_manager.write_threat_statements(
            sample_threat_statements, tmp_path, custom_filename
        )
        
        assert output_file.name == custom_filename
        assert output_file.exists()
    
    def test_generate_summary_report_custom_filename(self, file_manager, sample_analysis_result, tmp_path):
        """Test generating summary report with custom filename."""
        custom_filename = "custom_summary.md"
        output_file = file_manager.generate_summary_report(
            sample_analysis_result, tmp_path, custom_filename
        )
        
        assert output_file.name == custom_filename
        assert output_file.exists()