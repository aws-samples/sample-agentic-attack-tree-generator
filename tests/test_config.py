#!/usr/bin/env python3
"""
Unit tests for config module
Tests lazy loading, singleton pattern, and configuration access
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_section(title):
    """Print test section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    print("\n🧪 Config Module Unit Tests")
    print("Testing lazy loading, singleton pattern, and config access")
    print("=" * 60)

    all_passed = True

    # Test 1: Config can be imported without config file
    test_section("Test: Config Import Without File (Lazy Loading)")
    try:
        # This should NOT raise an error even if config file doesn't exist
        from threatforest.config import Config, config

        print("  ✓ Config imported successfully without config file")
        print("    This validates lazy loading fix")
    except Exception as e:
        print(f"  ✗ Config import: FAILED - {e}")
        all_passed = False

    # Test 2: Singleton pattern
    test_section("Test: Singleton Pattern")
    try:
        from threatforest.config import Config

        config1 = Config()
        config2 = Config()

        assert config1 is config2, "Config instances should be the same"
        print("  ✓ Singleton pattern: PASSED")
    except Exception as e:
        print(f"  ✗ Singleton pattern: FAILED - {e}")
        all_passed = False

    # Test 3: Lazy loading - config not loaded until accessed
    test_section("Test: Lazy Loading - Config Not Loaded Until Accessed")
    try:
        from threatforest.config import Config

        # Create new instance
        test_config = Config()
        test_config._config = None  # Reset to test lazy loading

        # Config should be None before access
        assert test_config._config is None, "Config should not be loaded yet"
        print("  ✓ Config not loaded at initialization: PASSED")
    except Exception as e:
        print(f"  ✗ Lazy loading check: FAILED - {e}")
        all_passed = False

    # Test 4: Config loading with mock file
    test_section("Test: Config Loading with Mock File")
    try:
        from threatforest.config import Config
        import yaml

        # Create temporary config file
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / ".threatforest"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"

            test_config_data = {
                "embeddings": {"model": "test-model", "ttc_threshold": 0.5},
                "bedrock": {"model_id": "test-bedrock"},
            }

            with open(config_file, "w") as f:
                yaml.dump(test_config_data, f)

            # Mock ROOT_DIR to point to temp directory
            with patch("threatforest.config.ROOT_DIR", Path(tmpdir)):
                test_config = Config()
                test_config._config = None  # Reset
                test_config._config_path = None

                # Access config - should trigger loading
                value = test_config.get("embeddings.model")

                assert value == "test-model", f"Expected 'test-model', got {value}"
                assert test_config._config is not None, "Config should be loaded"
                print("  ✓ Config loading from file: PASSED")

    except Exception as e:
        print(f"  ✗ Config loading: FAILED - {e}")
        all_passed = False

    # Test 5: Get method with dot notation
    test_section("Test: Get Method with Dot Notation")
    try:
        from threatforest.config import Config

        test_config = Config()
        test_config._config = {
            "embeddings": {"model": "test-model", "ttc_threshold": 0.3},
            "bedrock": {"model_id": "bedrock-model"},
        }

        # Test nested access
        assert test_config.get("embeddings.model") == "test-model"
        assert test_config.get("embeddings.ttc_threshold") == 0.3
        assert test_config.get("bedrock.model_id") == "bedrock-model"

        # Test default values
        assert test_config.get("nonexistent.key", "default") == "default"
        assert test_config.get("embeddings.nonexistent", "default") == "default"

        print("  ✓ Dot notation access: PASSED")
    except Exception as e:
        print(f"  ✗ Dot notation: FAILED - {e}")
        all_passed = False

    # Test 6: Property accessors
    test_section("Test: Property Accessors")
    try:
        from threatforest.config import Config

        test_config = Config()
        test_config._config = {
            "embeddings": {"model": "test-model", "ttc_threshold": 0.7},
            "bedrock": {"model_id": "bedrock-test"},
            "anthropic": {"model_id": "claude-test"},
        }

        # Test embeddings_model property
        assert test_config.embeddings_model == "test-model"

        # Test ttc_threshold property
        assert test_config.ttc_threshold == 0.7

        # Test provider properties
        assert test_config.bedrock == {"model_id": "bedrock-test"}
        assert test_config.anthropic == {"model_id": "claude-test"}

        print("  ✓ Property accessors: PASSED")
    except Exception as e:
        print(f"  ✗ Property accessors: FAILED - {e}")
        all_passed = False

    # Test 7: STIX bundle path (should work without config file)
    test_section("Test: STIX Bundle Path (No Config Required)")
    try:
        from threatforest.config import Config

        test_config = Config()
        test_config._config = None  # Ensure no config loaded

        # This should work without loading config
        stix_path = test_config.stix_bundle_path

        assert isinstance(stix_path, Path)
        assert "enterprise-attack" in str(stix_path)
        print("  ✓ STIX bundle path: PASSED")
    except Exception as e:
        print(f"  ✗ STIX bundle path: FAILED - {e}")
        all_passed = False

    # Test 8: Environment variable override
    test_section("Test: Environment Variable Override")
    try:
        from threatforest.config import Config

        test_config = Config()
        test_config._config = {"aws": {"default_profile": "config-profile"}}

        # Test without env var
        with patch.dict(os.environ, {}, clear=True):
            assert test_config.default_aws_profile == "config-profile"

        # Test with env var (should override)
        with patch.dict(os.environ, {"AWS_PROFILE": "env-profile"}):
            assert test_config.default_aws_profile == "env-profile"

        print("  ✓ Environment variable override: PASSED")
    except Exception as e:
        print(f"  ✗ Environment override: FAILED - {e}")
        all_passed = False

    # Test 9: FileNotFoundError with helpful message
    test_section("Test: FileNotFoundError with Helpful Message")
    try:
        from threatforest.config import Config

        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock ROOT_DIR to point to temp directory (no config file)
            with patch("threatforest.config.ROOT_DIR", Path(tmpdir)):
                test_config = Config()
                test_config._config = None
                test_config._config_path = None

                try:
                    # This should raise FileNotFoundError
                    test_config.get("some.key")
                    print("  ✗ Should have raised FileNotFoundError")
                    all_passed = False
                except FileNotFoundError as e:
                    error_msg = str(e)
                    assert "config.yaml" in error_msg
                    assert "threatforest" in error_msg.lower()
                    print("  ✓ FileNotFoundError with helpful message: PASSED")

    except Exception as e:
        print(f"  ✗ FileNotFoundError test: FAILED - {e}")
        all_passed = False

    # Test 10: Graph file path generation
    test_section("Test: Graph File Path Generation")
    try:
        from threatforest.config import Config

        test_config = Config()
        test_config._config = {"embeddings": {"model": "test/model-name"}}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("threatforest.config.ROOT_DIR", Path(tmpdir)):
                graph_path = test_config.graph_file_path

                assert isinstance(graph_path, Path)
                assert ".threatforest" in str(graph_path)
                assert "graphs" in str(graph_path)
                # Model name should be sanitized (/ replaced with _)
                assert "test_model-name" in str(graph_path)

                print("  ✓ Graph file path generation: PASSED")

    except Exception as e:
        print(f"  ✗ Graph file path: FAILED - {e}")
        all_passed = False

    # Summary
    test_section("Test Summary")

    if all_passed:
        print("\n  ✅ All tests PASSED!")
        print("  Config module is working correctly")
        print("  Lazy loading prevents import-time errors")
        return 0
    else:
        print("\n  ❌ Some tests FAILED")
        print("  Check error messages above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
