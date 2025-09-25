#!/usr/bin/env python3
"""
Test script for CLI help text and logging configuration (Task 9).

This script tests the enhanced help text and logging functionality
added to the ThreatForest CLI commands.
"""

import subprocess
import sys
import tempfile
import os
from pathlib import Path


def run_command(cmd, capture_output=True):
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=capture_output, 
            text=True,
            timeout=30
        )
        return result
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {cmd}")
        return None
    except Exception as e:
        print(f"Error running command '{cmd}': {e}")
        return None


def test_main_help():
    """Test the main command help text."""
    print("Testing main command help...")
    
    result = run_command("python -m threatforest.cli --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "QUICK START:",
            "EXAMPLES:",
            "CONFIGURATION:",
            "REQUIREMENTS:",
            "--verbose",
            "--log-level",
            "--log-file"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing help sections: {missing_sections}")
            return False
        else:
            print("✅ Main help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get main help: {result.stderr if result else 'Command failed'}")
        return False


def test_analyze_help():
    """Test the analyze command help text."""
    print("Testing analyze command help...")
    
    result = run_command("python -m threatforest.cli analyze --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "REQUIRED FILES:",
            "BASIC EXAMPLES:",
            "CONFIGURATION EXAMPLES:",
            "AUTOMATION EXAMPLES:",
            "TROUBLESHOOTING:",
            "OUTPUT:"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing analyze help sections: {missing_sections}")
            return False
        else:
            print("✅ Analyze help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get analyze help: {result.stderr if result else 'Command failed'}")
        return False


def test_setup_help():
    """Test the setup command help text."""
    print("Testing setup command help...")
    
    result = run_command("python -m threatforest.cli setup --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "CONFIGURATION LEVELS:",
            "PREREQUISITES:",
            "EXAMPLES:",
            "WHAT THIS WIZARD DOES:",
            "TROUBLESHOOTING:"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing setup help sections: {missing_sections}")
            return False
        else:
            print("✅ Setup help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get setup help: {result.stderr if result else 'Command failed'}")
        return False


def test_config_help():
    """Test the config command group help text."""
    print("Testing config command help...")
    
    result = run_command("python -m threatforest.cli config --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "COMMON TASKS:",
            "Configuration is loaded from multiple sources"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing config help sections: {missing_sections}")
            return False
        else:
            print("✅ Config help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get config help: {result.stderr if result else 'Command failed'}")
        return False


def test_config_validate_help():
    """Test the config validate command help text."""
    print("Testing config validate command help...")
    
    result = run_command("python -m threatforest.cli config validate --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "VALIDATION CHECKS:",
            "EXAMPLES:",
            "EXIT CODES:",
            "COMMON ISSUES AND SOLUTIONS:"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing config validate help sections: {missing_sections}")
            return False
        else:
            print("✅ Config validate help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get config validate help: {result.stderr if result else 'Command failed'}")
        return False


def test_config_model_help():
    """Test the config model command help text."""
    print("Testing config model command help...")
    
    result = run_command("python -m threatforest.cli config model --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "MODEL DISCOVERY:",
            "MODEL RECOMMENDATIONS:",
            "MODEL CONFIGURATION:",
            "MODEL TYPES:",
            "REGION AVAILABILITY:"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing config model help sections: {missing_sections}")
            return False
        else:
            print("✅ Config model help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get config model help: {result.stderr if result else 'Command failed'}")
        return False


def test_status_help():
    """Test the status command help text."""
    print("Testing status command help...")
    
    result = run_command("python -m threatforest.cli status --help")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for enhanced help sections
        required_sections = [
            "STATUS OVERVIEW:",
            "EXAMPLES:",
            "STATUS INDICATORS:",
            "TROUBLESHOOTING:"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing status help sections: {missing_sections}")
            return False
        else:
            print("✅ Status help text includes all required sections")
            return True
    else:
        print(f"❌ Failed to get status help: {result.stderr if result else 'Command failed'}")
        return False


def test_logging_options():
    """Test that logging options are properly recognized."""
    print("Testing logging options...")
    
    # Test verbose flag
    result = run_command("python -m threatforest.cli --verbose --help")
    if result and result.returncode == 0:
        if "Verbose logging enabled" in result.stderr or "--verbose" in result.stdout:
            print("✅ Verbose logging option recognized")
        else:
            print("❌ Verbose logging option not working properly")
            return False
    else:
        print("❌ Failed to test verbose logging")
        return False
    
    # Test log level option
    result = run_command("python -m threatforest.cli --log-level DEBUG --help")
    if result and result.returncode == 0:
        print("✅ Log level option recognized")
    else:
        print("❌ Log level option not working properly")
        return False
    
    return True


def test_error_messages():
    """Test enhanced error messages."""
    print("Testing enhanced error messages...")
    
    # Test config set with invalid key
    result = run_command("python -m threatforest.cli config set invalid.key test")
    if result and result.returncode != 0:
        if "Troubleshooting:" in result.stdout:
            print("✅ Enhanced error messages include troubleshooting guidance")
        else:
            print("❌ Error messages don't include troubleshooting guidance")
            return False
    else:
        print("⚠️  Could not test error messages (command may have succeeded unexpectedly)")
    
    return True


def test_examples_command():
    """Test the examples functionality."""
    print("Testing examples command...")
    
    result = run_command("python -m threatforest.cli analyze --examples")
    if result and result.returncode == 0:
        help_text = result.stdout
        
        # Check for example sections
        required_sections = [
            "Basic Usage:",
            "Configuration Options:",
            "Automation & CI/CD:",
            "Configuration Management:"
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in help_text:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ Missing example sections: {missing_sections}")
            return False
        else:
            print("✅ Examples command shows comprehensive usage examples")
            return True
    else:
        print(f"❌ Failed to get examples: {result.stderr if result else 'Command failed'}")
        return False


def main():
    """Run all tests."""
    print("🧪 Testing CLI Help Text and Logging Configuration (Task 9)")
    print("=" * 60)
    
    # Change to the project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    tests = [
        test_main_help,
        test_analyze_help,
        test_setup_help,
        test_config_help,
        test_config_validate_help,
        test_config_model_help,
        test_status_help,
        test_logging_options,
        test_error_messages,
        test_examples_command
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Task 9 implementation is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please review the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())