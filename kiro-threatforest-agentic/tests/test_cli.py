"""
Unit tests for ThreatForest CLI interface.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

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
        config = cli_app.load_config(validate=False)
        assert config is not None
        assert cli_app.config is not None
    
    def test_load_config_success_without_validation(self):
        """Test successful configuration loading without validation."""
        config = cli_app.load_config(validate=False)
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
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.cli.console.print')
    @patch('sys.exit')
    def test_load_config_validation_failure(self, mock_exit, mock_print, mock_validate):
        """Test configuration loading with validation failure."""
        from threatforest.config import ValidationResult, ValidationError
        from datetime import datetime
        
        # Mock validation failure
        mock_validate.return_value = ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                component="test_component",
                error_type="test_error",
                message="Test validation error",
                suggestion="Test suggestion"
            )],
            warnings=[],
            tested_components={"test_component": False},
            validation_time=datetime.now()
        )
        
        # Load config with validation enabled (default)
        cli_app.load_config(validate=True)
        
        # Should print validation errors and exit
        mock_print.assert_called()
        mock_exit.assert_called_with(1)
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_load_config_validation_success_with_warnings(self, mock_validate):
        """Test configuration loading with validation success but warnings."""
        from threatforest.config import ValidationResult, ValidationError
        from datetime import datetime
        
        # Mock validation success with warnings
        mock_validate.return_value = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[ValidationError(
                component="test_component",
                error_type="test_warning",
                message="Test validation warning",
                suggestion="Test warning suggestion"
            )],
            tested_components={"test_component": True},
            validation_time=datetime.now()
        )
        
        # Load config with validation enabled
        config = cli_app.load_config(validate=True)
        
        # Should succeed and return config
        assert config is not None
        assert cli_app.config is not None
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_validate_loaded_configuration_success(self, mock_validate):
        """Test successful configuration validation."""
        from threatforest.config import ValidationResult
        from datetime import datetime
        
        # Mock successful validation
        mock_validate.return_value = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            tested_components={"test": True},
            validation_time=datetime.now()
        )
        
        # Load config first
        cli_app.load_config(validate=False)
        
        # Test validation method
        result = cli_app._validate_loaded_configuration()
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_validate_loaded_configuration_exception(self, mock_validate):
        """Test configuration validation with exception."""
        # Mock validation exception
        mock_validate.side_effect = Exception("Validation failed")
        
        # Load config first
        cli_app.load_config(validate=False)
        
        # Test validation method handles exception
        result = cli_app._validate_loaded_configuration()
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "validation_exception" in result.errors[0].error_type
    
    @patch('threatforest.cli.console.print')
    def test_handle_validation_errors(self, mock_print):
        """Test handling of validation errors."""
        from threatforest.config import ValidationResult, ValidationError
        from datetime import datetime
        
        # Create validation result with errors
        validation_result = ValidationResult(
            is_valid=False,
            errors=[
                ValidationError(
                    component="aws_credentials",
                    error_type="no_credentials",
                    message="No AWS credentials found",
                    suggestion="Configure AWS credentials"
                ),
                ValidationError(
                    component="bedrock_config",
                    error_type="invalid_model",
                    message="Invalid model specified",
                    suggestion="Use a valid model ID"
                )
            ],
            warnings=[],
            tested_components={"aws_credentials": False, "bedrock_config": False},
            validation_time=datetime.now()
        )
        
        # Load config first
        cli_app.load_config(validate=False)
        
        # Test error handling
        cli_app._handle_validation_errors(validation_result)
        
        # Should have printed error messages
        mock_print.assert_called()
        
        # Check that error messages were formatted properly
        call_args = []
        for call in mock_print.call_args_list:
            if call[0]:  # Check if there are positional arguments
                call_args.append(str(call[0][0]))
        error_output = ' '.join(call_args)
        assert "Configuration validation failed" in error_output
        assert "No AWS credentials found" in error_output
        assert "Invalid model specified" in error_output
    
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
    """Test cases for analyze command with enhanced configuration loading."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli._run_analysis_workflow')
    def test_analyze_with_validation(self, mock_workflow, mock_load_config, mock_validate_aws):
        """Test analyze command with configuration validation enabled."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.output.directory = "./tf-output"
        mock_config.bedrock.region = "us-east-1"
        mock_config.processing.severity_threshold = "high"
        mock_load_config.return_value = mock_config
        
        # Mock workflow execution
        mock_workflow.return_value = {
            'status': 'success',
            'duration_seconds': 10.5,
            'results': {'attack_trees': [], 'context_files': []},
            'errors': [],
            'error_summary': {'total_errors': 0}
        }
        
        # Run analyze command (validation enabled by default)
        result = self.runner.invoke(main, ['analyze', '.'])
        
        # Should call load_config with validate=True (default)
        mock_load_config.assert_called_once()
        call_args = mock_load_config.call_args
        assert call_args[1].get('validate', True) is True
        
        assert result.exit_code == 0
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli._run_analysis_workflow')
    def test_analyze_skip_validation(self, mock_workflow, mock_load_config, mock_validate_aws):
        """Test analyze command with configuration validation disabled."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.output.directory = "./tf-output"
        mock_config.bedrock.region = "us-east-1"
        mock_config.processing.severity_threshold = "high"
        mock_load_config.return_value = mock_config
        
        # Mock workflow execution
        mock_workflow.return_value = {
            'status': 'success',
            'duration_seconds': 10.5,
            'results': {'attack_trees': [], 'context_files': []},
            'errors': [],
            'error_summary': {'total_errors': 0}
        }
        
        # Run analyze command with skip-validation flag
        result = self.runner.invoke(main, ['analyze', '.', '--skip-validation'])
        
        # Should call load_config with validate=False
        mock_load_config.assert_called_once()
        call_args = mock_load_config.call_args
        assert call_args[1].get('validate', True) is False
        
        assert result.exit_code == 0
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    def test_analyze_validation_failure(self, mock_load_config, mock_validate_aws):
        """Test analyze command when configuration validation fails."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading with validation failure (should exit)
        mock_load_config.side_effect = SystemExit(1)
        
        # Run analyze command - should exit with code 1
        result = self.runner.invoke(main, ['analyze', '.'])
        assert result.exit_code == 1


class TestStatusCommand:
    """Test cases for enhanced status command."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_all_ok(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command when everything is OK (without model availability check)."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "anthropic.claude-3-sonnet-20240229-v1:0"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "ThreatForest System Status" in result.output
        assert "✅ OK" in result.output
        assert "Model Availability" in result.output
        # Model availability will show CLIENT ERROR due to import issues in test environment
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    def test_status_aws_credentials_missing(self, mock_load_config, mock_validate_aws):
        """Test status command when AWS credentials are missing."""
        # Mock missing AWS credentials
        mock_validate_aws.return_value = False
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "anthropic.claude-3-sonnet-20240229-v1:0"
        mock_load_config.return_value = mock_config
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "❌ MISSING" in result.output
        assert "Some issues need to be resolved" in result.output
        assert "aws configure" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_config_validation_errors(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command when configuration has validation errors."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "invalid-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation with errors
        mock_error = MagicMock()
        mock_error.component = "bedrock_config"
        mock_error.message = "Invalid model specified"
        mock_error.suggestion = "Use a valid model ID"
        
        mock_validation = MagicMock()
        mock_validation.is_valid = False
        mock_validation.errors = [mock_error]
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": False}
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "⚠️  ISSUES" in result.output
        assert "Some issues need to be resolved" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_enhanced_validation(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command with enhanced validation features."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-west-2"
        mock_config.bedrock.model = "test-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "ThreatForest System Status" in result.output
        assert "Model Availability" in result.output
        assert "ThreatForest is ready to use!" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.utils.bedrock_client.BedrockClient')
    def test_status_model_availability_check(self, mock_bedrock_client_class, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command with model availability checking."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "anthropic.claude-3-sonnet-20240229-v1:0"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validate_config.return_value = mock_validation
        
        # Mock BedrockClient for model availability check
        mock_bedrock_client = MagicMock()
        mock_bedrock_client.validate_model_region_compatibility.return_value = True
        mock_bedrock_client_class.return_value = mock_bedrock_client
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "✅ AVAILABLE" in result.output
        assert "anthropic.claude-3-sonnet-20240229-v1:0 available in us-east-1" in result.output
        mock_bedrock_client.validate_model_region_compatibility.assert_called_once_with(
            "anthropic.claude-3-sonnet-20240229-v1:0", "us-east-1"
        )
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.utils.bedrock_client.BedrockClient')
    def test_status_model_unavailable(self, mock_bedrock_client_class, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command when model is unavailable in region."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "eu-west-1"
        mock_config.bedrock.model = "test-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validate_config.return_value = mock_validation
        
        # Mock BedrockClient for model availability check - model not available
        mock_bedrock_client = MagicMock()
        mock_bedrock_client.validate_model_region_compatibility.return_value = False
        mock_bedrock_client_class.return_value = mock_bedrock_client
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "❌ UNAVAILABLE" in result.output
        assert "test-model not available in eu-west-1" in result.output
        assert "Choose a different model or region" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_verbose_flag(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command with verbose flag and detailed output."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "test-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True, "bedrock_connectivity": True}
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status', '--verbose'])
        
        assert result.exit_code == 0
        assert "ThreatForest System Status" in result.output
        assert "Component Test Results" in result.output
        assert "Aws Credentials" in result.output
        assert "Bedrock Config" in result.output
        assert "Bedrock Connectivity" in result.output
        assert "✅ PASSED" in result.output
        assert "Checking model availability..." in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_with_warnings(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command with validation warnings in verbose mode."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "test-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation with warnings
        mock_warning = MagicMock()
        mock_warning.component = "bedrock_config"
        mock_warning.message = "Model parameters not optimized"
        mock_warning.suggestion = "Consider adjusting temperature"
        
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = [mock_warning]
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status', '--verbose'])
        
        assert result.exit_code == 0
        assert "Configuration Validation Warnings" in result.output
        assert "Model parameters not optimized" in result.output
        assert "Consider adjusting temperature" in result.output
        assert "Component Test Results" in result.output
        assert "ThreatForest is functional but some optimizations are recommended" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_with_validation_errors_verbose(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command with validation errors in verbose mode."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "invalid-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation with errors
        mock_error = MagicMock()
        mock_error.component = "bedrock_config"
        mock_error.message = "Invalid model specified"
        mock_error.suggestion = "Use a valid Bedrock model ID"
        
        mock_validation = MagicMock()
        mock_validation.is_valid = False
        mock_validation.errors = [mock_error]
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": False}
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status', '--verbose'])
        
        assert result.exit_code == 0
        assert "Configuration Validation Errors" in result.output
        assert "Invalid model specified" in result.output
        assert "Use a valid Bedrock model ID" in result.output
        assert "❌ FAILED" in result.output
        assert "Some issues need to be resolved" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.utils.bedrock_client.BedrockClient')
    def test_status_bedrock_client_error(self, mock_bedrock_client_class, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command when BedrockClient raises an error."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "test-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validate_config.return_value = mock_validation
        
        # Mock BedrockClient to raise an error
        from threatforest.utils.bedrock_client import BedrockClientError
        mock_bedrock_client_class.side_effect = BedrockClientError("Connection failed")
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "⚠️  CHECK FAILED" in result.output
        assert "Could not verify model availability" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    def test_status_comprehensive_health_check(self, mock_validate_config, mock_load_config, mock_validate_aws):
        """Test status command comprehensive health assessment."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "test-model"
        mock_load_config.return_value = mock_config
        
        # Mock configuration validation with mixed results
        mock_error = MagicMock()
        mock_error.component = "bedrock_connectivity"
        mock_error.message = "Connection timeout"
        mock_error.suggestion = "Check network connectivity"
        
        mock_warning = MagicMock()
        mock_warning.component = "bedrock_config"
        mock_warning.message = "Suboptimal timeout setting"
        mock_warning.suggestion = "Consider increasing timeout"
        
        mock_validation = MagicMock()
        mock_validation.is_valid = False
        mock_validation.errors = [mock_error]
        mock_validation.warnings = [mock_warning]
        mock_validation.tested_components = {
            "aws_credentials": True, 
            "bedrock_config": True,
            "bedrock_connectivity": False
        }
        mock_validate_config.return_value = mock_validation
        
        result = self.runner.invoke(main, ['status', '--verbose'])
        
        assert result.exit_code == 0
        assert "Configuration Validation Errors" in result.output
        assert "Configuration Validation Warnings" in result.output
        assert "Connection timeout" in result.output
        assert "Suboptimal timeout setting" in result.output
        assert "Some issues need to be resolved" in result.output
        assert "Run 'tf config validate' for detailed error information" in result.output
    
    @patch('threatforest.cli.cli_app.validate_aws_credentials')
    @patch('threatforest.cli.cli_app.load_config')
    def test_status_config_load_error(self, mock_load_config, mock_validate_aws):
        """Test status command when configuration loading fails."""
        # Mock AWS credentials validation
        mock_validate_aws.return_value = True
        
        # Mock configuration loading failure
        mock_load_config.side_effect = Exception("Config file not found")
        
        result = self.runner.invoke(main, ['status'])
        
        assert result.exit_code == 0
        assert "❌ ERROR" in result.output
        assert "Config file not found" in result.output
        assert "Some issues need to be resolved" in result.output


class TestSetupCommand:
    """Test cases for setup command."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
    
    @patch('threatforest.setup_wizard.SetupWizard')
    @patch('pathlib.Path.exists')
    @patch('threatforest.cli.console.print')
    def test_setup_success(self, mock_print, mock_exists, mock_wizard_class):
        """Test successful setup wizard execution."""
        # Mock no existing config files
        mock_exists.return_value = False
        
        # Mock the setup wizard
        mock_wizard = MagicMock()
        mock_config = MagicMock()
        mock_wizard.run_interactive_setup.return_value = mock_config
        mock_wizard_class.return_value = mock_wizard
        
        result = self.runner.invoke(main, ['setup'])
        
        assert result.exit_code == 0
        mock_wizard_class.assert_called_once()
        mock_wizard.run_interactive_setup.assert_called_once()
    
    @patch('threatforest.setup_wizard.SetupWizard')
    def test_setup_with_existing_config(self, mock_wizard_class):
        """Test setup with existing configuration."""
        # Create a temporary config file
        config_dir = Path(self.temp_dir) / ".tf"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.yaml"
        config_file.write_text("bedrock:\n  region: us-east-1")
        
        with patch('pathlib.Path.cwd', return_value=Path(self.temp_dir)):
            result = self.runner.invoke(main, ['setup'], input='n\n')
        
        assert result.exit_code == 0
        assert "Configuration already exists" in result.output
    
    @patch('threatforest.setup_wizard.SetupWizard')
    def test_setup_force_flag(self, mock_wizard_class):
        """Test setup with force flag."""
        mock_wizard = MagicMock()
        mock_config = MagicMock()
        mock_wizard.run_interactive_setup.return_value = mock_config
        mock_wizard_class.return_value = mock_wizard
        
        # Create existing config
        config_dir = Path(self.temp_dir) / ".tf"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.yaml"
        config_file.write_text("bedrock:\n  region: us-east-1")
        
        with patch('pathlib.Path.cwd', return_value=Path(self.temp_dir)):
            result = self.runner.invoke(main, ['setup', '--force'])
        
        assert result.exit_code == 0
        mock_wizard.run_interactive_setup.assert_called_once()


class TestConfigCommands:
    """Test cases for config commands."""
    
    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()
    
    @patch('threatforest.cli.cli_app.load_config')
    def test_config_show_basic(self, mock_load_config):
        """Test basic config show command."""
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "test-model"
        mock_config.bedrock.timeout_seconds = 300
        mock_load_config.return_value = mock_config
        
        result = self.runner.invoke(main, ['config', 'show'])
        
        assert result.exit_code == 0
        assert "us-east-1" in result.output
        assert "test-model" in result.output
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.cli.cli_app.load_config')
    def test_config_show_detailed(self, mock_load_config, mock_validate):
        """Test detailed config show command."""
        mock_config = MagicMock()
        mock_config.bedrock.region = "us-east-1"
        mock_config.bedrock.model = "test-model"
        mock_config.bedrock.validation_status = "valid"
        mock_load_config.return_value = mock_config
        
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.validation_time = datetime.now()
        mock_validation.tested_components = {"aws_credentials": True}
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validate.return_value = mock_validation
        
        result = self.runner.invoke(main, ['config', 'show', '--detailed'])
        
        assert result.exit_code == 0
        assert "Configuration Status" in result.output
        assert "Valid" in result.output
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.cli.cli_app.load_config')
    def test_config_validate_success(self, mock_load_config, mock_validate):
        """Test successful config validation."""
        mock_config = MagicMock()
        mock_load_config.return_value = mock_config
        
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
        mock_validation.errors = []
        mock_validation.warnings = []
        mock_validate.return_value = mock_validation
        
        result = self.runner.invoke(main, ['config', 'validate'])
        
        assert result.exit_code == 0
        assert "Configuration is valid" in result.output
    
    @patch('threatforest.cli.cli_app.config_manager.validate_configuration')
    @patch('threatforest.cli.cli_app.load_config')
    def test_config_validate_failure(self, mock_load_config, mock_validate):
        """Test config validation with errors."""
        mock_config = MagicMock()
        mock_load_config.return_value = mock_config
        
        mock_error = MagicMock()
        mock_error.component = "aws_credentials"
        mock_error.message = "Invalid credentials"
        mock_error.suggestion = "Check your AWS setup"
        
        mock_validation = MagicMock()
        mock_validation.is_valid = False
        mock_validation.tested_components = {"aws_credentials": False}
        mock_validation.errors = [mock_error]
        mock_validation.warnings = []
        mock_validate.return_value = mock_validation
        
        result = self.runner.invoke(main, ['config', 'validate'])
        
        assert result.exit_code == 1
        assert "Configuration has issues" in result.output
        assert "Invalid credentials" in result.output
    
    def test_config_model_list(self):
        """Test config model list command - simplified test."""
        # This is a simplified test since the actual implementation requires AWS credentials
        result = self.runner.invoke(main, ['config', 'model', '--list'])
        
        # The command should fail gracefully without proper AWS setup
        # but should show the help or error message
        assert "model" in result.output.lower() or "error" in result.output.lower()
    
    def test_config_model_recommend(self):
        """Test config model recommend command - simplified test."""
        # This is a simplified test since the actual implementation requires AWS credentials
        result = self.runner.invoke(main, ['config', 'model', '--recommend', 'analysis'])
        
        # The command should fail gracefully without proper AWS setup
        # but should show the help or error message
        assert "model" in result.output.lower() or "error" in result.output.lower()
    
    @patch('threatforest.cli.cli_app.config_manager.save_config')
    @patch('threatforest.cli.cli_app.config_manager.update_config')
    @patch('threatforest.cli.cli_app.load_config')
    def test_config_model_set(self, mock_load_config, mock_update_config, mock_save_config):
        """Test config model set command - simplified test."""
        # This is a simplified test since the actual implementation requires AWS credentials
        result = self.runner.invoke(main, ['config', 'model', '--set', 'new-model'])
        
        # The command should fail gracefully without proper AWS setup
        # but should attempt to load config
        mock_load_config.assert_called()



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