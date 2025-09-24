"""
Enhanced unit tests for ThreatForest CLI user experience features.
Tests for Task 14: Enhanced CLI with user experience features.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from threatforest.cli import main, cli_app
from threatforest.models import ContextInformation


class TestEnhancedCLIFeatures:
    """Test cases for enhanced CLI user experience features."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
    
    def test_welcome_screen(self):
        """Test welcome screen display."""
        result = self.runner.invoke(main, [])
        
        assert result.exit_code == 0
        assert 'Welcome to ThreatForest' in result.output
        assert '🌳' in result.output
        assert 'Quick Start:' in result.output
        assert 'tf analyze' in result.output
    
    def test_status_command(self):
        """Test status command functionality."""
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert 'System Status' in result.output
        assert 'Python Version' in result.output
        assert 'AWS Credentials' in result.output
        assert 'Configuration' in result.output
        assert 'Dependencies' in result.output
    
    def test_examples_flag(self):
        """Test --examples flag in analyze command."""
        result = self.runner.invoke(main, ['analyze', '--examples'])
        
        assert result.exit_code == 0
        assert 'Usage Examples' in result.output
        assert 'Basic Usage:' in result.output
        assert 'Configuration Options:' in result.output
        assert 'Automation & CI/CD:' in result.output
        assert 'Required Files in Project:' in result.output
    
    @patch('threatforest.cli.Confirm.ask')
    def test_init_command_new_directory(self, mock_confirm):
        """Test init command with new directory."""
        mock_confirm.return_value = True
        new_dir = Path(self.temp_dir) / "new_project"
        
        result = self.runner.invoke(main, ['init', str(new_dir)])
        
        assert result.exit_code == 0
        assert 'Initializing ThreatForest project' in result.output
        assert 'Created files:' in result.output
        assert new_dir.exists()
        assert (new_dir / 'README.md').exists()
        assert (new_dir / 'threats.md').exists()
        assert (new_dir / '.tf' / 'config.yaml').exists()
    
    @patch('threatforest.cli.Confirm.ask')
    def test_init_command_existing_directory(self, mock_confirm):
        """Test init command with existing directory."""
        mock_confirm.return_value = False  # Don't overwrite existing files
        
        # Create existing files
        existing_readme = Path(self.temp_dir) / "README.md"
        existing_readme.write_text("Existing content")
        
        result = self.runner.invoke(main, ['init', self.temp_dir])
        
        assert result.exit_code == 0
        assert 'Skipped existing files:' in result.output
        assert 'README.md' in result.output
        
        # Verify existing file wasn't overwritten
        assert existing_readme.read_text() == "Existing content"
    
    @patch('threatforest.cli.Confirm.ask')
    def test_init_command_templates(self, mock_confirm):
        """Test that init command creates proper template content."""
        mock_confirm.return_value = True  # Confirm directory creation
        new_dir = Path(self.temp_dir) / "template_test"
        
        result = self.runner.invoke(main, ['init', str(new_dir)])
        
        assert result.exit_code == 0
        
        # Check README template
        readme_content = (new_dir / 'README.md').read_text()
        assert '# Project Name' in readme_content
        assert '## Technologies' in readme_content
        assert '## Security Considerations' in readme_content
        
        # Check threats template
        threats_content = (new_dir / 'threats.md').read_text()
        assert '# Threat Statements' in threats_content
        assert 'T001: Unauthorized Data Access' in threats_content
        assert '**Severity**: High' in threats_content
        
        # Check config template
        config_content = (new_dir / '.tf' / 'config.yaml').read_text()
        assert 'bedrock:' in config_content
        assert 'processing:' in config_content
        assert 'severity_threshold: high' in config_content


class TestInteractiveValidation:
    """Test cases for interactive validation features."""
    
    def setup_method(self):
        """Set up test environment."""
        self.cli_app = cli_app
        self.cli_app.interactive_mode = True
    
    @patch('threatforest.cli.Prompt.ask')
    @patch('threatforest.cli.console.print')
    def test_validate_extracted_information_approve(self, mock_print, mock_prompt):
        """Test approving extracted information."""
        mock_prompt.return_value = "approve"
        
        context_info = ContextInformation(
            technologies=["Python", "Docker"],
            programming_languages=["Python"],
            sector="Technology",
            security_objectives=["Confidentiality", "Integrity"],
            architecture_type="Microservices",
            compliance_frameworks=["SOC2"],
            extracted_from=["README.md"],
            validation_status="pending",
            confidence_score=0.85
        )
        
        result = self.cli_app.validate_extracted_information(context_info)
        
        assert result.validation_status == "approved"
        mock_print.assert_called()
        mock_prompt.assert_called()
    
    @patch('threatforest.cli.Prompt.ask')
    def test_validate_extracted_information_reject(self, mock_prompt):
        """Test rejecting extracted information."""
        mock_prompt.return_value = "reject"
        
        context_info = ContextInformation(
            technologies=["Python"],
            programming_languages=["Python"],
            sector="Technology",
            security_objectives=["Confidentiality"],
            architecture_type="Monolith",
            compliance_frameworks=[],
            extracted_from=["README.md"],
            validation_status="pending",
            confidence_score=0.45
        )
        
        result = self.cli_app.validate_extracted_information(context_info)
        
        assert result.validation_status == "rejected"
    
    @patch('threatforest.cli.Prompt.ask')
    def test_validate_extracted_information_help(self, mock_prompt):
        """Test help option in validation."""
        mock_prompt.side_effect = ["help", "approve"]
        
        context_info = ContextInformation(
            technologies=["Python"],
            programming_languages=["Python"],
            sector="Technology",
            security_objectives=["Confidentiality"],
            architecture_type="Monolith",
            compliance_frameworks=[],
            extracted_from=["README.md"],
            validation_status="pending",
            confidence_score=0.75
        )
        
        result = self.cli_app.validate_extracted_information(context_info)
        
        assert result.validation_status == "approved"
        assert mock_prompt.call_count == 2
    
    @patch('threatforest.cli.Prompt.ask')
    def test_modify_context_information(self, mock_prompt):
        """Test modifying context information."""
        # Mock user inputs for modification
        mock_prompt.side_effect = [
            "modify",  # Choose to modify
            "Python, JavaScript, Docker",  # Technologies
            "Python, JavaScript",  # Programming languages
            "Financial Services",  # Sector
            "Confidentiality, Integrity, Availability",  # Security objectives
            "Microservices",  # Architecture type
            "PCI-DSS, SOC2"  # Compliance frameworks
        ]
        
        context_info = ContextInformation(
            technologies=["Python"],
            programming_languages=["Python"],
            sector="Technology",
            security_objectives=["Confidentiality"],
            architecture_type="Monolith",
            compliance_frameworks=[],
            extracted_from=["README.md"],
            validation_status="pending",
            confidence_score=0.65
        )
        
        result = self.cli_app.validate_extracted_information(context_info)
        
        assert result.validation_status == "modified"
        assert "JavaScript" in result.technologies
        assert "Docker" in result.technologies
        assert result.sector == "Financial Services"
        assert "Availability" in result.security_objectives
        assert result.architecture_type == "Microservices"
        assert "PCI-DSS" in result.compliance_frameworks
    
    def test_non_interactive_mode(self):
        """Test non-interactive mode skips validation."""
        self.cli_app.interactive_mode = False
        
        context_info = ContextInformation(
            technologies=["Python"],
            programming_languages=["Python"],
            sector="Technology",
            security_objectives=["Confidentiality"],
            architecture_type="Monolith",
            compliance_frameworks=[],
            extracted_from=["README.md"],
            validation_status="pending",
            confidence_score=0.65
        )
        
        result = self.cli_app.validate_extracted_information(context_info)
        
        # Should return unchanged in non-interactive mode
        assert result.validation_status == "pending"
        assert result == context_info


class TestProgressReporting:
    """Test cases for enhanced progress reporting."""
    
    def setup_method(self):
        """Set up test environment."""
        self.cli_app = cli_app
    
    def test_show_progress_creation(self):
        """Test progress tracker creation."""
        phases = ["Context Detection", "Information Extraction", "Attack Tree Generation"]
        
        progress, workflow_task, phase_tasks = self.cli_app.show_progress(phases)
        
        assert progress is not None
        assert workflow_task is not None
        assert len(phase_tasks) == len(phases)
        assert "Context Detection" in phase_tasks
        assert "Information Extraction" in phase_tasks
        assert "Attack Tree Generation" in phase_tasks
    
    def test_update_phase_progress(self):
        """Test phase progress updates."""
        phases = ["Context Detection"]
        progress, workflow_task, phase_tasks = self.cli_app.show_progress(phases)
        
        # Test progress update
        self.cli_app.update_phase_progress(
            progress, phase_tasks, "Context Detection", 50, "Scanning files..."
        )
        
        # Verify the task was updated (we can't easily test the visual output)
        assert "Context Detection" in phase_tasks
    
    def test_show_analysis_summary(self):
        """Test analysis summary display."""
        results = {
            'status': 'completed',
            'duration_seconds': 45.2,
            'results': {
                'context_files': [
                    {'path': 'README.md', 'type': 'readme'},
                    {'path': 'threats.md', 'type': 'threats'}
                ],
                'attack_trees': [
                    {'threat_id': 'T001', 'title': 'Test Attack Tree', 'severity': 'High'}
                ],
                'summary_file': '/tmp/summary.md',
                'context_information': ContextInformation(
                    technologies=["Python"],
                    programming_languages=["Python"],
                    sector="Technology",
                    security_objectives=["Confidentiality"],
                    architecture_type="Monolith",
                    compliance_frameworks=[],
                    extracted_from=["README.md"],
                    validation_status="approved",
                    confidence_score=0.85
                )
            },
            'errors': [],
            'error_summary': {'total_errors': 0, 'by_severity': {}}
        }
        
        # This should not raise an exception
        self.cli_app.show_analysis_summary(results)
    
    def test_show_analysis_summary_with_errors(self):
        """Test analysis summary with errors."""
        results = {
            'status': 'completed_with_errors',
            'duration_seconds': 30.1,
            'results': {
                'context_files': [],
                'attack_trees': [],
                'context_information': ContextInformation(
                    technologies=[],
                    programming_languages=[],
                    sector="",
                    security_objectives=[],
                    architecture_type="",
                    compliance_frameworks=[],
                    extracted_from=[],
                    validation_status="pending",
                    confidence_score=0.0
                )
            },
            'errors': [
                {'type': 'ValidationError', 'message': 'Test error', 'phase': 'extraction'}
            ],
            'error_summary': {
                'total_errors': 1,
                'by_severity': {'error': 1}
            }
        }
        
        # This should not raise an exception
        self.cli_app.show_analysis_summary(results)


class TestDryRunFeatures:
    """Test cases for dry run functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        (Path(self.temp_dir) / "README.md").write_text("Test project")
        (Path(self.temp_dir) / "threats.md").write_text("Test threats")
        (Path(self.temp_dir) / "architecture.png").write_text("fake image")
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    def test_dry_run_shows_files(self, mock_validate):
        """Test dry run shows files that would be processed."""
        mock_validate.return_value = True
        
        result = self.runner.invoke(main, [
            'analyze', self.temp_dir, '--dry-run'
        ])
        
        assert result.exit_code == 0
        assert 'Dry run mode' in result.output
        assert 'Files found' in result.output
        assert 'README.md' in result.output
        assert 'threats.md' in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    def test_dry_run_no_files(self, mock_validate):
        """Test dry run with no matching files."""
        mock_validate.return_value = True
        empty_dir = Path(self.temp_dir) / "empty"
        empty_dir.mkdir()
        
        result = self.runner.invoke(main, [
            'analyze', str(empty_dir), '--dry-run'
        ])
        
        assert result.exit_code == 0
        assert 'No matching context files found' in result.output