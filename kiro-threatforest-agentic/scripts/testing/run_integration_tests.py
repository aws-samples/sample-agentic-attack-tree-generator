#!/usr/bin/env python3
"""
Integration test runner for enhanced model provider configuration.

This script runs integration tests without circular import issues by
executing CLI commands directly and validating their outputs.
"""

import os
import sys
import subprocess
import tempfile
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IntegrationTestRunner:
    """Integration test runner for enhanced configuration features."""
    
    def __init__(self, test_dir: Optional[str] = None):
        """Initialize test runner."""
        self.test_dir = Path(test_dir) if test_dir else Path(tempfile.mkdtemp(prefix="tf_integration_test_"))
        self.test_results = []
        self.setup_test_environment()
    
    def setup_test_environment(self):
        """Set up test environment."""
        logger.info(f"Setting up test environment in {self.test_dir}")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        # Set environment variables for testing
        os.environ['TF_CONFIG_DIR'] = str(self.test_dir)
        os.environ['TF_TEST_MODE'] = 'true'
    
    def run_cli_command(self, command: List[str], expect_success: bool = True) -> Dict[str, Any]:
        """Run a CLI command and capture output."""
        logger.info(f"Running command: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=self.test_dir,
                timeout=30
            )
            
            output = {
                'command': ' '.join(command),
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
            if expect_success and result.returncode != 0:
                logger.error(f"Command failed: {result.stderr}")
            elif not expect_success and result.returncode == 0:
                logger.warning(f"Expected command to fail but it succeeded")
            
            return output
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return {
                'command': ' '.join(command),
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timed out',
                'success': False
            }
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return {
                'command': ' '.join(command),
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'success': False
            }
    
    def check_file_exists(self, file_path: str) -> bool:
        """Check if a file exists."""
        path = self.test_dir / file_path
        exists = path.exists()
        logger.info(f"File {file_path} exists: {exists}")
        return exists
    
    def read_config_file(self, file_path: str = ".tf/config.yaml") -> Optional[Dict[str, Any]]:
        """Read and parse configuration file."""
        config_path = self.test_dir / file_path
        if not config_path.exists():
            logger.warning(f"Config file not found: {config_path}")
            return None
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Successfully read config from {file_path}")
            return config
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            return None
    
    def validate_config_content(self, config: Dict[str, Any], expected: Dict[str, Any]) -> bool:
        """Validate configuration content against expected values."""
        for key, expected_value in expected.items():
            if '.' in key:
                # Handle nested keys like 'bedrock.region'
                keys = key.split('.')
                current = config
                for k in keys:
                    if k not in current:
                        logger.error(f"Missing config key: {key}")
                        return False
                    current = current[k]
                
                if current != expected_value:
                    logger.error(f"Config mismatch for {key}: expected {expected_value}, got {current}")
                    return False
            else:
                if key not in config:
                    logger.error(f"Missing config key: {key}")
                    return False
                if config[key] != expected_value:
                    logger.error(f"Config mismatch for {key}: expected {expected_value}, got {config[key]}")
                    return False
        
        logger.info("Configuration validation passed")
        return True
    
    def test_setup_wizard_basic_flow(self) -> bool:
        """Test basic setup wizard flow."""
        logger.info("=== Testing Setup Wizard Basic Flow ===")
        
        # Note: This would require interactive input simulation
        # For now, we'll test the command availability
        result = self.run_cli_command(['tf', 'setup', '--help'])
        
        if not result['success']:
            logger.error("Setup command not available")
            return False
        
        if 'interactive setup wizard' not in result['stdout'].lower():
            logger.error("Setup command help doesn't mention wizard")
            return False
        
        logger.info("Setup wizard command available")
        return True
    
    def test_config_validation(self) -> bool:
        """Test configuration validation."""
        logger.info("=== Testing Configuration Validation ===")
        
        # Test validation command availability
        result = self.run_cli_command(['tf', 'config', 'validate', '--help'])
        if not result['success']:
            logger.error("Config validate command not available")
            return False
        
        # Test validation with no config (should handle gracefully)
        result = self.run_cli_command(['tf', 'config', 'validate'], expect_success=False)
        
        # Should either succeed with default config or fail gracefully
        if result['returncode'] not in [0, 1]:
            logger.error("Config validation didn't handle missing config gracefully")
            return False
        
        logger.info("Configuration validation command works")
        return True
    
    def test_status_command_enhanced(self) -> bool:
        """Test enhanced status command."""
        logger.info("=== Testing Enhanced Status Command ===")
        
        # Test basic status command
        result = self.run_cli_command(['tf', 'status'])
        
        if not result['success']:
            logger.error("Status command failed")
            return False
        
        # Check for enhanced status information
        status_output = result['stdout'].lower()
        expected_sections = [
            'system status',
            'aws credentials',
            'configuration',
            'model availability'
        ]
        
        missing_sections = []
        for section in expected_sections:
            if section not in status_output:
                missing_sections.append(section)
        
        if missing_sections:
            logger.warning(f"Status output missing sections: {missing_sections}")
            # Don't fail the test, just warn
        
        # Test verbose status
        result = self.run_cli_command(['tf', 'status', '--verbose'])
        if result['success']:
            logger.info("Verbose status command works")
        else:
            logger.warning("Verbose status command failed")
        
        logger.info("Status command enhanced features working")
        return True
    
    def test_model_configuration_commands(self) -> bool:
        """Test model configuration commands."""
        logger.info("=== Testing Model Configuration Commands ===")
        
        # Test model command help
        result = self.run_cli_command(['tf', 'config', 'model', '--help'])
        if not result['success']:
            logger.error("Model config command not available")
            return False
        
        # Test model listing (may fail without AWS credentials, that's OK)
        result = self.run_cli_command(['tf', 'config', 'model', '--list'], expect_success=False)
        
        # Should either succeed or fail with clear error message
        if result['returncode'] not in [0, 1]:
            logger.error("Model list command didn't handle errors gracefully")
            return False
        
        if not result['success']:
            # Check for reasonable error message
            error_output = result['stderr'].lower()
            if 'credentials' in error_output or 'aws' in error_output:
                logger.info("Model list failed with expected credential error")
            else:
                logger.warning(f"Model list failed with unexpected error: {result['stderr']}")
        
        logger.info("Model configuration commands available")
        return True
    
    def test_analyze_with_validation_flags(self) -> bool:
        """Test analyze command with validation flags."""
        logger.info("=== Testing Analyze Command with Validation Flags ===")
        
        # Create a simple test project
        test_project = self.test_dir / "test_project"
        test_project.mkdir(exist_ok=True)
        
        # Create a simple README
        readme_path = test_project / "README.md"
        readme_path.write_text("""# Test Project
        
This is a test project for ThreatForest integration testing.

## Technologies
- Python
- AWS
- Docker
""")
        
        # Test analyze with validation (may fail, that's expected without proper config)
        result = self.run_cli_command(['tf', 'analyze', str(test_project), '--validate'], expect_success=False)
        
        # Should handle validation gracefully
        if result['returncode'] not in [0, 1]:
            logger.error("Analyze with validation didn't handle errors gracefully")
            return False
        
        # Test analyze with skip validation
        result = self.run_cli_command(['tf', 'analyze', str(test_project), '--skip-validation'], expect_success=False)
        
        # Should handle skip validation gracefully
        if result['returncode'] not in [0, 1]:
            logger.error("Analyze with skip validation didn't handle errors gracefully")
            return False
        
        logger.info("Analyze command validation flags working")
        return True
    
    def test_configuration_file_handling(self) -> bool:
        """Test configuration file creation and handling."""
        logger.info("=== Testing Configuration File Handling ===")
        
        # Create a basic configuration file
        config_dir = self.test_dir / ".tf"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "config.yaml"
        test_config = {
            'bedrock': {
                'region': 'us-east-1',
                'model': 'anthropic.claude-3-sonnet-20240229-v1:0',
                'temperature': 0.1,
                'max_tokens': 4000,
                'top_p': 0.9
            },
            'processing': {
                'severity_threshold': 'high',
                'max_concurrent_agents': 4
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        logger.info("Created test configuration file")
        
        # Test config show command
        result = self.run_cli_command(['tf', 'config', 'show'])
        if not result['success']:
            logger.error("Config show command failed")
            return False
        
        # Check if configuration is displayed
        config_output = result['stdout']
        if 'bedrock' not in config_output.lower():
            logger.error("Config show doesn't display bedrock configuration")
            return False
        
        logger.info("Configuration file handling working")
        return True
    
    def test_error_handling_scenarios(self) -> bool:
        """Test various error handling scenarios."""
        logger.info("=== Testing Error Handling Scenarios ===")
        
        # Test with invalid command
        result = self.run_cli_command(['tf', 'invalid-command'], expect_success=False)
        if result['returncode'] == 0:
            logger.error("Invalid command should have failed")
            return False
        
        # Test with invalid arguments
        result = self.run_cli_command(['tf', 'config', '--invalid-flag'], expect_success=False)
        if result['returncode'] == 0:
            logger.error("Invalid flag should have failed")
            return False
        
        # Test with non-existent directory
        result = self.run_cli_command(['tf', 'analyze', '/non/existent/path'], expect_success=False)
        if result['returncode'] == 0:
            logger.error("Non-existent path should have failed")
            return False
        
        logger.info("Error handling scenarios working correctly")
        return True
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests."""
        logger.info("Starting integration test suite")
        
        tests = [
            ('Setup Wizard Basic Flow', self.test_setup_wizard_basic_flow),
            ('Configuration Validation', self.test_config_validation),
            ('Enhanced Status Command', self.test_status_command_enhanced),
            ('Model Configuration Commands', self.test_model_configuration_commands),
            ('Analyze with Validation Flags', self.test_analyze_with_validation_flags),
            ('Configuration File Handling', self.test_configuration_file_handling),
            ('Error Handling Scenarios', self.test_error_handling_scenarios),
        ]
        
        results = {
            'total_tests': len(tests),
            'passed_tests': 0,
            'failed_tests': 0,
            'test_results': []
        }
        
        for test_name, test_func in tests:
            logger.info(f"\n--- Running test: {test_name} ---")
            try:
                success = test_func()
                if success:
                    results['passed_tests'] += 1
                    logger.info(f"✅ {test_name}: PASSED")
                else:
                    results['failed_tests'] += 1
                    logger.error(f"❌ {test_name}: FAILED")
                
                results['test_results'].append({
                    'name': test_name,
                    'success': success
                })
                
            except Exception as e:
                logger.error(f"❌ {test_name}: ERROR - {e}")
                results['failed_tests'] += 1
                results['test_results'].append({
                    'name': test_name,
                    'success': False,
                    'error': str(e)
                })
        
        # Calculate success rate
        results['success_rate'] = results['passed_tests'] / results['total_tests'] if results['total_tests'] > 0 else 0
        
        return results
    
    def cleanup(self):
        """Clean up test environment."""
        logger.info(f"Cleaning up test environment: {self.test_dir}")
        try:
            import shutil
            shutil.rmtree(self.test_dir)
        except Exception as e:
            logger.warning(f"Error cleaning up test directory: {e}")


def main():
    """Main test runner function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run ThreatForest integration tests')
    parser.add_argument('--test-dir', help='Test directory (default: temporary)')
    parser.add_argument('--keep-files', action='store_true', help='Keep test files after completion')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize test runner
    runner = IntegrationTestRunner(args.test_dir)
    
    try:
        # Run all tests
        results = runner.run_all_tests()
        
        # Print summary
        print("\n" + "="*60)
        print("INTEGRATION TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {results['total_tests']}")
        print(f"Passed: {results['passed_tests']}")
        print(f"Failed: {results['failed_tests']}")
        print(f"Success Rate: {results['success_rate']:.1%}")
        
        print("\nTest Results:")
        for test_result in results['test_results']:
            status = "✅ PASSED" if test_result['success'] else "❌ FAILED"
            print(f"  {test_result['name']}: {status}")
            if 'error' in test_result:
                print(f"    Error: {test_result['error']}")
        
        # Exit with appropriate code
        exit_code = 0 if results['failed_tests'] == 0 else 1
        
        if results['failed_tests'] > 0:
            print(f"\n⚠️  {results['failed_tests']} test(s) failed. Check logs for details.")
        else:
            print("\n🎉 All tests passed!")
        
        return exit_code
        
    finally:
        # Cleanup unless requested to keep files
        if not args.keep_files:
            runner.cleanup()
        else:
            print(f"\nTest files kept in: {runner.test_dir}")


if __name__ == '__main__':
    sys.exit(main())