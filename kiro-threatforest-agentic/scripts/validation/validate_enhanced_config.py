#!/usr/bin/env python3
"""
Validation script for enhanced model provider configuration features.

This script validates that the enhanced configuration features are working
correctly by testing the key components without circular import issues.
"""

import sys
import tempfile
import yaml
from pathlib import Path
from datetime import datetime

def test_setup_wizard_import():
    """Test that SetupWizard can be imported and initialized."""
    try:
        from threatforest.setup_wizard import SetupWizard, CredentialStatus
        
        # Test initialization
        temp_dir = tempfile.mkdtemp()
        wizard = SetupWizard(temp_dir)
        
        # Test basic attributes
        assert wizard.project_dir == Path(temp_dir)
        assert wizard.config_manager is not None
        assert wizard._aws_credentials_valid is False
        assert wizard._available_models == []
        
        print("✅ SetupWizard import and initialization: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ SetupWizard import and initialization: FAILED - {e}")
        return False

def test_enhanced_config_models():
    """Test enhanced configuration models."""
    try:
        from threatforest.config import ThreatForestConfig, BedrockConfig, ValidationResult
        from datetime import datetime
        
        # Test enhanced BedrockConfig
        config = BedrockConfig(
            region="us-west-2",
            model="anthropic.claude-3-haiku-20240307-v1:0",
            temperature=0.7,
            max_tokens=8000,
            top_p=0.85,
            custom_parameters={"stop_sequences": ["Human:", "Assistant:"]},
            validation_status="valid",
            last_validated=datetime.now()
        )
        
        # Verify enhanced parameters
        assert config.temperature == 0.7
        assert config.max_tokens == 8000
        assert config.top_p == 0.85
        assert config.custom_parameters == {"stop_sequences": ["Human:", "Assistant:"]}
        assert config.validation_status == "valid"
        assert config.last_validated is not None
        
        # Test ThreatForestConfig with enhanced parameters
        full_config = ThreatForestConfig(bedrock=config)
        assert full_config.bedrock.temperature == 0.7
        
        print("✅ Enhanced configuration models: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced configuration models: FAILED - {e}")
        return False

def test_config_manager_validation():
    """Test ConfigManager validation functionality."""
    try:
        from threatforest.config import ConfigManager, ThreatForestConfig, BedrockConfig
        
        # Test ConfigManager initialization
        temp_dir = tempfile.mkdtemp()
        manager = ConfigManager(temp_dir)
        
        # Test configuration loading
        config = manager.load_config()
        assert isinstance(config, ThreatForestConfig)
        
        # Test enhanced parameter validation
        test_config = BedrockConfig(
            region="us-east-1",
            model="anthropic.claude-3-sonnet-20240229-v1:0",
            temperature=0.5,
            max_tokens=6000,
            top_p=0.8
        )
        
        # Test validation method exists
        assert hasattr(manager, 'validate_configuration')
        assert hasattr(manager, '_validate_bedrock_configuration')
        
        # Test Bedrock configuration validation
        result = manager._validate_bedrock_configuration(test_config)
        assert isinstance(result, dict)
        assert 'is_valid' in result
        assert 'errors' in result
        assert 'warnings' in result
        
        print("✅ ConfigManager validation functionality: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ ConfigManager validation functionality: FAILED - {e}")
        return False

def test_bedrock_client_methods():
    """Test BedrockClient enhanced methods."""
    try:
        # Import locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient
        
        # Test initialization
        client = BedrockClient(region="us-east-1")
        
        # Test that enhanced methods exist
        assert hasattr(client, 'list_available_models')
        assert hasattr(client, 'validate_model_region_compatibility')
        assert hasattr(client, 'get_model_recommendations')
        
        # Test method signatures (without calling them to avoid AWS dependencies)
        import inspect
        
        # Check list_available_models signature
        sig = inspect.signature(client.list_available_models)
        assert len(sig.parameters) == 0  # No required parameters
        
        # Check validate_model_region_compatibility signature
        sig = inspect.signature(client.validate_model_region_compatibility)
        assert len(sig.parameters) == 2  # model_id and region
        
        # Check get_model_recommendations signature
        sig = inspect.signature(client.get_model_recommendations)
        assert len(sig.parameters) == 1  # use_case
        
        print("✅ BedrockClient enhanced methods: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ BedrockClient enhanced methods: FAILED - {e}")
        return False

def test_cli_integration():
    """Test CLI integration with enhanced features."""
    try:
        from threatforest.cli import cli_app
        
        # Test that CLI app has enhanced methods
        assert hasattr(cli_app, 'load_config')
        assert hasattr(cli_app, 'validate_aws_credentials')
        
        # Test method signatures
        import inspect
        
        # Check load_config signature
        sig = inspect.signature(cli_app.load_config)
        param_names = list(sig.parameters.keys())
        assert 'validate' in param_names  # Should have validate parameter
        
        print("✅ CLI integration with enhanced features: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ CLI integration with enhanced features: FAILED - {e}")
        return False

def test_configuration_file_format():
    """Test enhanced configuration file format."""
    try:
        from threatforest.config import ThreatForestConfig, BedrockConfig
        
        # Create enhanced configuration
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-west-2",
                model="anthropic.claude-3-haiku-20240307-v1:0",
                temperature=0.6,
                max_tokens=7000,
                top_p=0.92,
                custom_parameters={
                    'stop_sequences': ['Human:', 'Assistant:'],
                    'repetition_penalty': 1.05
                },
                validation_status='valid'
            )
        )
        
        # Test serialization to dict
        config_dict = config.model_dump()
        
        # Verify enhanced parameters are included
        bedrock_config = config_dict['bedrock']
        assert bedrock_config['temperature'] == 0.6
        assert bedrock_config['max_tokens'] == 7000
        assert bedrock_config['top_p'] == 0.92
        assert bedrock_config['custom_parameters'] == {
            'stop_sequences': ['Human:', 'Assistant:'],
            'repetition_penalty': 1.05
        }
        assert bedrock_config['validation_status'] == 'valid'
        
        # Test YAML serialization
        yaml_content = yaml.dump(config_dict)
        assert 'temperature: 0.6' in yaml_content
        assert 'max_tokens: 7000' in yaml_content
        assert 'top_p: 0.92' in yaml_content
        
        print("✅ Enhanced configuration file format: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced configuration file format: FAILED - {e}")
        return False

def test_validation_result_structure():
    """Test ValidationResult structure and functionality."""
    try:
        from threatforest.config import ValidationResult, ValidationError
        from datetime import datetime
        
        # Test ValidationError creation
        error = ValidationError(
            component="bedrock_config",
            error_type="invalid_temperature",
            message="Temperature must be between 0.0 and 1.0",
            suggestion="Set temperature to a value between 0.0 and 1.0"
        )
        
        assert error.component == "bedrock_config"
        assert error.error_type == "invalid_temperature"
        assert error.message == "Temperature must be between 0.0 and 1.0"
        assert error.suggestion == "Set temperature to a value between 0.0 and 1.0"
        
        # Test ValidationResult creation
        result = ValidationResult(
            is_valid=False,
            errors=[error],
            warnings=[],
            tested_components={"bedrock_config": False},
            validation_time=datetime.now()
        )
        
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert len(result.warnings) == 0
        assert result.tested_components["bedrock_config"] is False
        assert result.validation_time is not None
        
        print("✅ ValidationResult structure and functionality: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ ValidationResult structure and functionality: FAILED - {e}")
        return False

def main():
    """Run all validation tests."""
    print("Enhanced Model Provider Configuration - Validation Tests")
    print("=" * 60)
    
    tests = [
        ("SetupWizard Import and Initialization", test_setup_wizard_import),
        ("Enhanced Configuration Models", test_enhanced_config_models),
        ("ConfigManager Validation Functionality", test_config_manager_validation),
        ("BedrockClient Enhanced Methods", test_bedrock_client_methods),
        ("CLI Integration with Enhanced Features", test_cli_integration),
        ("Enhanced Configuration File Format", test_configuration_file_format),
        ("ValidationResult Structure and Functionality", test_validation_result_structure),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {passed/len(tests):.1%}")
    
    if failed == 0:
        print("\n🎉 All validation tests passed!")
        print("Enhanced model provider configuration features are working correctly.")
        return 0
    else:
        print(f"\n⚠️  {failed} validation test(s) failed.")
        print("Some enhanced configuration features may not be working correctly.")
        return 1

if __name__ == '__main__':
    sys.exit(main())