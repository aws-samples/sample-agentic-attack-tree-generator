#!/usr/bin/env python3
"""Test script to verify Python bridge compatibility with Pydantic v2"""

import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_file_discovery():
    """Test FileDiscovery static method"""
    print("\n=== Testing FileDiscovery ===")
    try:
        from src.modules.core.file_discovery import FileDiscovery
        
        # Test with current directory
        result = FileDiscovery.discover(str(project_root))
        
        print(f"✓ FileDiscovery.discover() works")
        print(f"  Total files: {result.total_files}")
        print(f"  Threat models: {len(result.threat_models)}")
        print(f"  Source code: {len(result.source_code)}")
        print(f"  Discovery time: {result.discovery_time_ms:.2f}ms")
        
        # Test serialization
        data = {
            'threat_models': result.threat_models[:3],  # First 3 only
            'total_files': result.total_files,
            'discovery_time_ms': result.discovery_time_ms
        }
        json_str = json.dumps(data)
        print(f"✓ Serialization works")
        
        return True
    except Exception as e:
        print(f"✗ FileDiscovery failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cache():
    """Test BedrockResponseCache"""
    print("\n=== Testing BedrockResponseCache ===")
    try:
        from src.modules.core.cache import BedrockResponseCache
        
        cache = BedrockResponseCache()
        stats = cache.get_stats()
        
        print(f"✓ BedrockResponseCache instantiation works")
        print(f"  Enabled: {stats['enabled']}")
        print(f"  Entries: {stats['entry_count']}")
        print(f"  Cache size: {stats['cache_size_mb']} MB")
        
        # Test serialization
        json_str = json.dumps(stats)
        print(f"✓ Serialization works")
        
        return True
    except Exception as e:
        print(f"✗ Cache failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_state_manager():
    """Test StateManager with Pydantic v2"""
    print("\n=== Testing StateManager ===")
    try:
        from src.modules.core.state_manager import StateManager
        from src.modules.core.state import ThreatForestState, WorkflowStage
        
        manager = StateManager()
        
        # Try to load existing state
        state = manager.load_checkpoint('latest')
        
        if state is None:
            print("  No existing checkpoint found (expected)")
            
            # Create a test state
            test_state = ThreatForestState(
                project_path=str(project_root),
                bedrock_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
                current_stage=WorkflowStage.SETUP
            )
            
            # Test Pydantic v2 model_dump()
            data = test_state.model_dump()
            print(f"✓ Pydantic v2 model_dump() works")
            
            # Test serialization
            json_str = json.dumps(data, default=str)
            print(f"✓ Serialization works")
            
        else:
            print(f"✓ Loaded existing checkpoint")
            print(f"  Stage: {state.current_stage}")
            print(f"  Project: {state.project_path}")
            
            # Test Pydantic v2 model_dump()
            data = state.model_dump()
            print(f"✓ Pydantic v2 model_dump() works")
        
        return True
    except Exception as e:
        print(f"✗ StateManager failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_validation():
    """Test Pydantic v2 validation models"""
    print("\n=== Testing Validation Models ===")
    try:
        from src.modules.core.validation import SetupToolInput
        
        # Test valid input (Pydantic v2 validates during __init__)
        valid_input = SetupToolInput(
            project_path=str(project_root),
            bedrock_model="anthropic.claude-3-5-sonnet-20241022-v2:0"
        )
        
        print(f"✓ SetupToolInput validation works")
        
        # Test Pydantic v2 model_dump()
        data = valid_input.model_dump()
        print(f"✓ Pydantic v2 model_dump() works")
        
        # Test serialization
        json_str = json.dumps(data)
        print(f"✓ Serialization works")
        
        # Test invalid input
        try:
            invalid_input = SetupToolInput(
                project_path="/nonexistent/path",
                bedrock_model="test-model"
            )
            print(f"✗ Validation should have failed for invalid path")
            return False
        except Exception as e:
            print(f"✓ Validation correctly rejected invalid input")
        
        return True
    except Exception as e:
        print(f"✗ Validation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Testing Python Bridge Compatibility with Pydantic v2")
    print("=" * 60)
    
    results = {
        'FileDiscovery': test_file_discovery(),
        'Cache': test_cache(),
        'StateManager': test_state_manager(),
        'Validation': test_validation()
    }
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{test_name:20s} {status}")
    
    all_passed = all(results.values())
    print("\n" + ("=" * 60))
    if all_passed:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
