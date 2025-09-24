"""
Unit tests for ThreatForest CLI interface.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from threatforest.cli import main, cli_app, _convert_config_value


class TestThreatForestCLI:
    """Test cases for ThreatForestCLI class."""
    
    def test_cli_initialization(self):
        """Test CLI initialization."""
        assert cli_app.config_manager is not None
        assert cli_app.config is None
    
    def test_load_config_success(self):
        """Test successful configuration loading."""
        config = cli_app.load_config()
        assert config is not None
        assert cli_app.config is not None
    
    @patch('threatforest.cli.console.print')
    @patch('sys.exit')
    def test_load_config_failure(self, mock_exit, mock_print):
        """Test configuration loading failure."""
        with patch.object(cli_app.config_manager, 'load_config', side_effect=Exception("Test error")):
            cli_app.load_config()
            mock_print.assert_called()
            mock_exit.assert_called_with(1)
    
    def test_validate_aws_credentials_with_keys(self):
        """Test AWS credential validation with access keys."""
        with patch.dict(os.environ, {
            'AWS_ACCESS_KEY_ID': 'test_key',
            'AWS_SECRET_ACCESS_KEY': 'test_secret'
        }):
            assert cli_app.validate_aws_credentials() is True
    
    def test_validate_aws_credentials_with_profile(self):
        """Test AWS credential validation with profile."""
        with patch.dict(os.environ, {'AWS_PROFILE': 'test_profile'}, clear=True):
            assert cli_app.validate_aws_credentials() is True
    
    @patch('threatforest.cli.console.print')
    def test_validate_aws_credentials_missing(self, mock_print):
        """Test AWS credential validation when missing."""
        with patch.dict(os.environ, {}, clear=True):
            assert cli_app.validate_aws_credentials() is False
            mock_print.assert_called()


class TestMainCommand:
    """Test cases for main CLI command."""
    
    def test_main_version(self):
        """Test version flag."""
        runner = CliRunner()
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert 'ThreatForest version' in result.output
    
    def test_main_no_command(self):
        """Test main command without subcommand."""
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code == 0
        assert 'Welcome to ThreatForest' in result.output


class TestAnalyzeCommand:
    """Test cases for analyze command."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        readme_path = Path(self.temp_dir) / "README.md"
        readme_path.write_text("# Test Project\nThis is a test project.")
        
        threats_path = Path(self.temp_dir) / "threats.md"
        threats_path.write_text("## Threats\nTest threat content.")
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    def test_analyze_dry_run(self, mock_validate):
        """Test analyze command in dry run mode."""
        mock_validate.return_value = True
        
        result = self.runner.invoke(main, [
            'analyze', self.temp_dir, '--dry-run'
        ])
        
        assert result.exit_code == 0
        assert 'Dry run mode' in result.output
        assert 'README.md' in result.output
        assert 'threats.md' in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    def test_analyze_verbose(self, mock_validate):
        """Test analyze command with verbose output."""
        mock_validate.return_value = True
        
        result = self.runner.invoke(main, [
            'analyze', self.temp_dir, '--verbose', '--dry-run'
        ])
        
        assert result.exit_code == 0
        assert 'Configuration loaded' in result.output
        assert 'Output directory' in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    def test_analyze_with_options(self, mock_validate):
        """Test analyze command with various options."""
        mock_validate.return_value = True
        
        result = self.runner.invoke(main, [
            'analyze', self.temp_dir,
            '--output', '/tmp/test-output',
            '--region', 'us-west-2',
            '--model', 'anthropic.claude-3-haiku-20240307-v1:0',
            '--severity', 'medium',
            '--dry-run'
        ])
        
        assert result.exit_code == 0
        assert 'us-west-2' in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    def test_analyze_aws_validation_failure(self, mock_validate):
        """Test analyze command when AWS validation fails."""
        mock_validate.return_value = False
        
        result = self.runner.invoke(main, [
            'analyze', self.temp_dir
        ])
        
        assert result.exit_code == 1
    
    def test_analyze_nonexistent_directory(self):
        """Test analyze command with nonexistent directory."""
        result = self.runner.invoke(main, [
            'analyze', '/nonexistent/directory'
        ])
        
        assert result.exit_code != 0


class TestConfigCommands:
    """Test cases for config commands."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
    
    def test_config_show(self):
        """Test config show command."""
        result = self.runner.invoke(main, ['config', 'show'])
        
        assert result.exit_code == 0
        assert 'Bedrock Configuration' in result.output
        assert 'Processing Configuration' in result.output
        assert 'Output Configuration' in result.output
    
    @patch('threatforest.cli.cli_app.config_manager.save_config')
    def test_config_set_valid(self, mock_save):
        """Test config set command with valid key."""
        result = self.runner.invoke(main, [
            'config', 'set', 'bedrock.region', 'us-west-2'
        ])
        
        assert result.exit_code == 0
        assert 'Configuration updated' in result.output
        mock_save.assert_called_once()
    
    def test_config_set_invalid_key(self):
        """Test config set command with invalid key format."""
        result = self.runner.invoke(main, [
            'config', 'set', 'invalid_key', 'value'
        ])
        
        assert result.exit_code == 1
        assert 'Key must be in format' in result.output
    
    @patch('threatforest.cli.cli_app.config_manager.save_config')
    def test_config_set_user_level(self, mock_save):
        """Test config set command with user level flag."""
        result = self.runner.invoke(main, [
            'config', 'set', 'bedrock.region', 'eu-west-1', '--user'
        ])
        
        assert result.exit_code == 0
        assert 'user-level configuration' in result.output
        mock_save.assert_called_once()


class TestUtilityFunctions:
    """Test cases for utility functions."""
    
    def test_convert_config_value_boolean_true(self):
        """Test converting boolean true values."""
        assert _convert_config_value('true') is True
        assert _convert_config_value('True') is True
        assert _convert_config_value('yes') is True
        assert _convert_config_value('1') is True
        assert _convert_config_value('on') is True
    
    def test_convert_config_value_boolean_false(self):
        """Test converting boolean false values."""
        assert _convert_config_value('false') is False
        assert _convert_config_value('False') is False
        assert _convert_config_value('no') is False
        assert _convert_config_value('0') is False
        assert _convert_config_value('off') is False
    
    def test_convert_config_value_integer(self):
        """Test converting integer values."""
        assert _convert_config_value('42') == 42
        assert _convert_config_value('0') == 0
        assert _convert_config_value('-10') == -10
    
    def test_convert_config_value_float(self):
        """Test converting float values."""
        assert _convert_config_value('3.14') == 3.14
        assert _convert_config_value('0.0') == 0.0
        assert _convert_config_value('-2.5') == -2.5
    
    def test_convert_config_value_string(self):
        """Test converting string values."""
        assert _convert_config_value('hello') == 'hello'
        assert _convert_config_value('us-east-1') == 'us-east-1'
        assert _convert_config_value('') == ''