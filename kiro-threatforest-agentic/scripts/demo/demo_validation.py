#!/usr/bin/env python3
"""
Demo script showing the configuration validation functionality.
"""

from threatforest.config import ConfigManager, BedrockConfig, ThreatForestConfig

def main():
    print("🔍 ThreatForest Configuration Validation Demo")
    print("=" * 50)
    
    # Create a ConfigManager
    manager = ConfigManager()
    
    # Load the current configuration
    print("\n1. Loading configuration...")
    config = manager.load_config()
    print(f"   ✓ Configuration loaded successfully")
    
    # Validate the configuration
    print("\n2. Validating configuration...")
    result = manager.validate_configuration(config)
    
    print(f"   Overall validation result: {'✅ VALID' if result.is_valid else '❌ INVALID'}")
    print(f"   Errors found: {len(result.errors)}")
    print(f"   Warnings found: {len(result.warnings)}")
    print(f"   Validation time: {result.validation_time}")
    
    # Show tested components
    print("\n3. Tested components:")
    for component, status in result.tested_components.items():
        status_icon = "✅" if status else "❌"
        print(f"   {status_icon} {component}")
    
    # Show errors if any
    if result.errors:
        print("\n4. Errors found:")
        for error in result.errors:
            print(f"   ❌ {error.component}: {error.message}")
            if error.suggestion:
                print(f"      💡 Suggestion: {error.suggestion}")
    
    # Show warnings if any
    if result.warnings:
        print("\n5. Warnings found:")
        for warning in result.warnings:
            print(f"   ⚠️  {warning.component}: {warning.message}")
            if warning.suggestion:
                print(f"      💡 Suggestion: {warning.suggestion}")
    
    # Test with invalid configuration
    print("\n" + "=" * 50)
    print("6. Testing with invalid configuration...")
    
    # Create an invalid config
    invalid_config = BedrockConfig()
    invalid_config.__dict__['model'] = ""  # Invalid model
    invalid_config.__dict__['temperature'] = 1.5  # Invalid temperature
    
    invalid_result = manager._validate_bedrock_configuration(invalid_config)
    
    print(f"   Invalid config validation: {'✅ VALID' if invalid_result['is_valid'] else '❌ INVALID'}")
    print(f"   Errors: {len(invalid_result['errors'])}")
    
    for error in invalid_result['errors']:
        print(f"   ❌ {error['error_type']}: {error['message']}")
    
    print("\n✨ Validation demo completed!")

if __name__ == "__main__":
    main()