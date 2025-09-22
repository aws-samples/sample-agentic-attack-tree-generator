#!/usr/bin/env python3
"""
Complete integration test for ThreatForest with Bedrock.
"""

import os
import sys
from pathlib import Path

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    
    try:
        from threat_forest.config import ConfigManager, ThreatForestConfig
        from threat_forest.llm_client import LLMClient
        from threat_forest.file_scanner import FileScanner
        from threat_forest.context_parser import ContextParser
        from threat_forest.info_extractor import InfoExtractor
        from threat_forest.user_validator import UserValidator
        from threat_forest.info_saver import InfoSaver
        from threat_forest.threat_parser import ThreatParser
        from threat_forest.attack_tree_generator import AttackTreeGenerator
        from threat_forest.stix_processor import STIXProcessor, STIXMapper
        from threat_forest.tree_enhancer import TreeEnhancer
        from threat_forest.summary_generator import SummaryGenerator
        from threat_forest.orchestrator import ThreatForestOrchestrator
        from threat_forest.cli import main
        
        print("✅ All imports successful!")
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_config():
    """Test configuration loading."""
    print("\nTesting configuration...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        print(f"Provider: {config.llm.provider}")
        print(f"Model: {config.llm.model}")
        print(f"Region: {config.llm.region}")
        
        print("✅ Configuration loading successful!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_file_scanner():
    """Test file scanner with current directory."""
    print("\nTesting file scanner...")
    
    try:
        scanner = FileScanner()
        scan_result = scanner.scan_directory(".")
        
        print(f"Files found: {len(scan_result.files_found)}")
        for file_info in scan_result.files_found:
            print(f"  - {file_info.file_type.value}: {file_info.path.name}")
        
        print("✅ File scanner test successful!")
        return True
        
    except Exception as e:
        print(f"❌ File scanner test failed: {e}")
        return False

def test_stix_loading():
    """Test STIX bundle loading if available."""
    print("\nTesting STIX processing...")
    
    stix_path = "aaf-bundle.json"
    if not Path(stix_path).exists():
        print(f"⚠️  STIX bundle not found at {stix_path}, skipping test")
        return True
    
    try:
        from threat_forest.stix_processor import STIXProcessor
        
        processor = STIXProcessor(stix_path)
        summary = processor.get_bundle_summary()
        
        print(f"Techniques loaded: {summary['total_techniques']}")
        print(f"Tactics loaded: {summary['total_tactics']}")
        
        print("✅ STIX processing test successful!")
        return True
        
    except Exception as e:
        print(f"❌ STIX processing test failed: {e}")
        return False

def check_aws_credentials():
    """Check AWS credentials availability."""
    print("\nChecking AWS credentials...")
    
    has_keys = bool(os.getenv("AWS_ACCESS_KEY_ID"))
    has_profile = bool(os.getenv("AWS_PROFILE"))
    
    if has_keys:
        print("✅ AWS access keys found in environment")
    elif has_profile:
        print("✅ AWS profile found in environment")
    else:
        print("⚠️  No AWS credentials found")
        print("   Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE")
        print("   Or run 'aws configure' to set up credentials")
    
    return has_keys or has_profile

def main():
    """Run all tests."""
    print("ThreatForest Complete Integration Test")
    print("=" * 40)
    
    success = True
    
    # Test imports
    if not test_imports():
        success = False
    
    # Test configuration
    if not test_config():
        success = False
    
    # Test file scanner
    if not test_file_scanner():
        success = False
    
    # Test STIX processing
    if not test_stix_loading():
        success = False
    
    # Check AWS credentials
    check_aws_credentials()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 All tests passed! ThreatForest is ready to use.")
        print("\nTo run ThreatForest:")
        print("  python -m threat_forest.cli")
        print("  # or")
        print("  python main.py")
    else:
        print("💥 Some tests failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()