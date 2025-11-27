"""Integration tests for CLI docs commands

**Validates: Requirements 5.1, 5.2, 5.3**
"""
import pytest
from pathlib import Path
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from threatforest.cli import cli, docs_build, docs_serve
from threatforest.modules.workflow.summary_generator.tool import MKDOCS_AVAILABLE


@pytest.fixture
def sample_output_dir():
    """Create a sample output directory with required files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "threatforest" / "attack_trees"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create required files
        project_info = {
            "application_name": "CLI Test Application",
            "description": "Testing CLI commands"
        }
        
        threat_statements = [
            {
                "id": "T001",
                "category": "Test Category",
                "severity": "High",
                "statement": "Test threat statement"
            }
        ]
        
        (output_dir / "threatforest_data.json").write_text(json.dumps({
            "project_info": project_info,
            "threat_statements": threat_statements
        }))
        
        (output_dir / "threatforest_analysis_report.md").write_text("# Test Report\n\nTest content")
        (output_dir / "attack_tree_T001_test_category.md").write_text("# Attack Tree T001")
        (output_dir / "attack_trees_dashboard.html").write_text("<html><body>Dashboard</body></html>")
        
        yield output_dir


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_build_command_success(sample_output_dir):
    """Test that 'docs build' command produces site directory
    
    **Validates: Requirements 5.1, 1.4**
    """
    runner = CliRunner()
    
    # Mock subprocess.run to avoid actually running mkdocs build
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        
        result = runner.invoke(cli, ['docs', 'build', str(sample_output_dir)])
        
        # Check command succeeded
        assert result.exit_code == 0, f"Command failed: {result.output}"
        
        # Verify mkdocs build was called
        assert mock_run.called, "mkdocs build should be called"
        
        # Verify MkDocs structure was generated (at output_dir level)
        assert (sample_output_dir / "mkdocs.yml").exists(), "mkdocs.yml should be generated"
        assert (sample_output_dir / "docs").exists(), "docs directory should be created"
        
        # Verify success message in output
        assert "successfully" in result.output.lower() or "success" in result.output.lower()
        
        print("✓ docs build command test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_build_command_with_missing_files():
    """Test error handling when required files are missing
    
    **Validates: Requirements 5.3**
    """
    runner = CliRunner()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create empty output directory (missing required files)
        output_dir = Path(tmpdir) / "empty_output"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Mock mkdocs availability check
        with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=True):
            result = runner.invoke(cli, ['docs', 'build', str(output_dir)])
        
        # Command should fail
        assert result.exit_code != 0, "Command should fail with missing files"
        
        # Verify error message mentions missing files
        assert "missing" in result.output.lower() or "required" in result.output.lower()
        
        print("✓ docs build error handling test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_build_command_with_mkdocs_failure(sample_output_dir):
    """Test error handling when mkdocs build fails
    
    **Validates: Requirements 5.1**
    """
    runner = CliRunner()
    
    # Mock mkdocs availability and subprocess.run to simulate mkdocs build failure
    with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=True):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="Error: Invalid configuration",
                stdout=""
            )
            
            result = runner.invoke(cli, ['docs', 'build', str(sample_output_dir)])
            
            # Command should fail
            assert result.exit_code != 0, "Command should fail when mkdocs build fails"
            
            # Verify error message is displayed
            assert "error" in result.output.lower() or "failed" in result.output.lower()
            
            print("✓ docs build mkdocs failure test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_serve_command_starts_server(sample_output_dir):
    """Test that 'docs serve' command starts server
    
    **Validates: Requirements 5.2, 2.1, 2.2**
    """
    runner = CliRunner()
    
    # Mock mkdocs availability and subprocess.run to avoid actually starting server
    with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=True):
        with patch('subprocess.run') as mock_run:
            # Simulate KeyboardInterrupt to stop server
            mock_run.side_effect = KeyboardInterrupt()
            
            result = runner.invoke(cli, ['docs', 'serve', str(sample_output_dir)])
            
            # Command should handle KeyboardInterrupt gracefully
            assert "stopped" in result.output.lower() or result.exit_code == 0
            
            # Verify mkdocs serve was called
            assert mock_run.called, "mkdocs serve should be called"
            
            # Verify server URL is displayed
            assert "127.0.0.1" in result.output or "localhost" in result.output
            assert "8000" in result.output  # Default port
            
            print("✓ docs serve command test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_serve_command_with_custom_port(sample_output_dir):
    """Test that 'docs serve' command accepts custom port
    
    **Validates: Requirements 2.1**
    """
    runner = CliRunner()
    
    # Mock mkdocs availability and subprocess.run to avoid actually starting server
    with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=True):
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = KeyboardInterrupt()
            
            result = runner.invoke(cli, ['docs', 'serve', str(sample_output_dir), '--port', '9000'])
            
            # Verify custom port is used
            assert "9000" in result.output
            
            # Verify mkdocs serve was called with correct port
            assert mock_run.called
            call_args = mock_run.call_args[0][0]
            assert "9000" in str(call_args), "Custom port should be passed to mkdocs serve"
            
            print("✓ docs serve custom port test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_serve_command_with_missing_files():
    """Test error handling when required files are missing
    
    **Validates: Requirements 5.3**
    """
    runner = CliRunner()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create empty output directory
        output_dir = Path(tmpdir) / "empty_output"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Mock mkdocs availability check
        with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=True):
            result = runner.invoke(cli, ['docs', 'serve', str(output_dir)])
        
        # Command should fail
        assert result.exit_code != 0, "Command should fail with missing files"
        
        # Verify error message mentions missing files
        assert "missing" in result.output.lower() or "required" in result.output.lower()
        
        print("✓ docs serve error handling test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_serve_generates_structure_if_missing(sample_output_dir):
    """Test that 'docs serve' generates MkDocs structure if not present
    
    **Validates: Requirements 5.2**
    """
    runner = CliRunner()
    
    # Ensure mkdocs.yml doesn't exist initially (at output_dir level)
    mkdocs_yml = sample_output_dir / "mkdocs.yml"
    if mkdocs_yml.exists():
        mkdocs_yml.unlink()
    
    # Mock mkdocs availability and subprocess.run to avoid actually starting server
    with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=True):
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = KeyboardInterrupt()
            
            result = runner.invoke(cli, ['docs', 'serve', str(sample_output_dir)])
            
            # Verify mkdocs.yml was generated
            assert mkdocs_yml.exists(), "mkdocs.yml should be generated if missing"
            
            # Verify docs directory was created
            assert (sample_output_dir / "docs").exists(), "docs directory should be created"
            
            print("✓ docs serve auto-generation test passed")


def test_docs_command_group_exists():
    """Test that docs command group is registered
    
    **Validates: Requirements 5.1**
    """
    runner = CliRunner()
    
    # Test that docs command exists
    result = runner.invoke(cli, ['docs', '--help'])
    
    assert result.exit_code == 0, "docs command should exist"
    assert "build" in result.output, "build subcommand should be listed"
    assert "serve" in result.output, "serve subcommand should be listed"
    
    print("✓ docs command group test passed")


def test_mkdocs_availability_check(sample_output_dir):
    """Test that commands fail gracefully when mkdocs is not available
    
    **Validates: Requirements 5.3**
    """
    runner = CliRunner()
    
    # Mock mkdocs as not available
    with patch('threatforest.modules.visualization.docs_generator.DocsGenerator.is_mkdocs_available', return_value=False):
        
        # Test build command
        result = runner.invoke(cli, ['docs', 'build', str(sample_output_dir)])
        assert result.exit_code != 0, "Command should fail when mkdocs not available"
        assert "MkDocs" in result.output or "mkdocs" in result.output, "Should mention mkdocs in error"
        
        # Test serve command
        result = runner.invoke(cli, ['docs', 'serve', str(sample_output_dir)])
        assert result.exit_code != 0, "Command should fail when mkdocs not available"
        assert "MkDocs" in result.output or "mkdocs" in result.output, "Should mention mkdocs in error"
    
    print("✓ mkdocs availability check test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_docs_build_with_vehicle_platform_sample():
    """Test docs build command with real vehicle-platform sample
    
    **Validates: Requirements 5.1, 1.4**
    """
    # Path to vehicle-platform sample docs (source files are in docs directory)
    sample_docs_dir = Path(__file__).parent.parent / "sample-applications" / "vehicle-platform" / "threatforest" / "attack_trees" / "docs"
    
    # Skip if sample doesn't exist
    if not sample_docs_dir.exists():
        pytest.skip("Vehicle platform sample not available")
    
    runner = CliRunner()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy sample source files to temp directory
        temp_output = Path(tmpdir) / "threatforest" / "attack_trees"
        temp_output.mkdir(parents=True, exist_ok=True)
        
        # Copy the required source files from docs directory
        shutil.copy2(sample_docs_dir / "threatforest_analysis_report.md", temp_output)
        shutil.copy2(sample_docs_dir / "data" / "threatforest_data.json", temp_output)
        
        # Copy attack tree markdown files
        attack_trees_dir = sample_docs_dir / "attack_trees"
        if attack_trees_dir.exists():
            for file in attack_trees_dir.glob("*.md"):
                shutil.copy2(file, temp_output)
        
        # Mock subprocess.run to avoid actually running mkdocs build
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            
            result = runner.invoke(cli, ['docs', 'build', str(temp_output)])
            
            # Check command succeeded
            assert result.exit_code == 0, f"Command failed: {result.output}"
            
            # Verify structure was created (at output_dir level)
            assert (temp_output / "mkdocs.yml").exists()
            assert (temp_output / "docs").exists()
            
            print("✓ docs build with vehicle platform sample test passed")
