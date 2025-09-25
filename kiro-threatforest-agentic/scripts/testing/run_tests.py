#!/usr/bin/env python3
"""
ThreatForest Test Runner

Comprehensive test runner for all ThreatForest test categories.
Supports different test modes and generates detailed reports.
"""

import sys
import argparse
import subprocess
from pathlib import Path
from typing import List, Optional


def run_pytest(
    test_paths: List[str],
    markers: Optional[str] = None,
    verbose: bool = True,
    coverage: bool = False,
    output_file: Optional[str] = None
) -> int:
    """
    Run pytest with specified parameters.
    
    Args:
        test_paths: List of test file/directory paths
        markers: Pytest marker expression (e.g., "not slow")
        verbose: Enable verbose output
        coverage: Enable coverage reporting
        output_file: Output file for results
        
    Returns:
        Exit code from pytest
    """
    cmd = ["python", "-m", "pytest"]
    
    # Add test paths
    cmd.extend(test_paths)
    
    # Add options
    if verbose:
        cmd.append("-v")
    
    if markers:
        cmd.extend(["-m", markers])
    
    if coverage:
        cmd.extend([
            "--cov=threatforest",
            "--cov-report=html:htmlcov",
            "--cov-report=term-missing"
        ])
    
    if output_file:
        cmd.extend([f"--junit-xml={output_file}"])
    
    # Add other useful options
    cmd.extend([
        "--tb=short",
        "--strict-markers",
        "--disable-warnings"
    ])
    
    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd).returncode


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(
        description="ThreatForest Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Test Categories:
  unit         - Unit tests for individual components
  integration  - Integration tests for component interaction
  performance  - Performance and scalability tests
  security     - Security and compliance tests
  all          - All test categories
  
Examples:
  python run_tests.py unit                    # Run unit tests only
  python run_tests.py integration --slow      # Run integration tests including slow ones
  python run_tests.py performance --coverage  # Run performance tests with coverage
  python run_tests.py all --output results.xml # Run all tests with JUnit output
        """
    )
    
    parser.add_argument(
        "category",
        choices=["unit", "integration", "performance", "security", "all", "comprehensive"],
        help="Test category to run"
    )
    
    parser.add_argument(
        "--slow",
        action="store_true",
        help="Include slow-running tests"
    )
    
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Generate coverage report"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for test results (JUnit XML format)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Enable verbose output (default: True)"
    )
    
    parser.add_argument(
        "--parallel",
        type=int,
        help="Number of parallel test processes"
    )
    
    args = parser.parse_args()
    
    # Determine test paths and markers based on category
    test_config = {
        "unit": {
            "paths": [
                "tests/test_models.py",
                "tests/test_config.py",
                "tests/test_bedrock_client.py",
                "tests/test_context_detection.py",
                "tests/test_information_extraction.py",
                "tests/test_attack_tree_generator.py",
                "tests/test_ttc_mapping.py",
                "tests/test_file_manager.py",
                "tests/test_error_handler.py",
                "tests/test_orchestrator.py",
                "tests/test_stix_processor.py",
                "tests/test_cli.py",
                "tests/test_cli_enhanced.py"
            ],
            "markers": "not integration and not performance and not security"
        },
        "integration": {
            "paths": ["tests/test_integration.py"],
            "markers": "integration"
        },
        "performance": {
            "paths": ["tests/test_performance.py"],
            "markers": "performance"
        },
        "security": {
            "paths": ["tests/test_security.py"],
            "markers": "security"
        },
        "all": {
            "paths": ["tests/"],
            "markers": None
        },
        "comprehensive": {
            "paths": ["tests/test_comprehensive.py"],
            "markers": None
        }
    }
    
    config = test_config[args.category]
    
    # Modify markers based on options
    markers = config["markers"]
    if not args.slow and markers:
        markers = f"({markers}) and not slow"
    elif not args.slow:
        markers = "not slow"
    
    print(f"🧪 Running ThreatForest {args.category.title()} Tests")
    print("=" * 60)
    
    # Run tests
    exit_code = run_pytest(
        test_paths=config["paths"],
        markers=markers,
        verbose=args.verbose,
        coverage=args.coverage,
        output_file=args.output
    )
    
    # Print summary
    print("\n" + "=" * 60)
    if exit_code == 0:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
    
    if args.coverage:
        print("📊 Coverage report generated in htmlcov/")
    
    if args.output:
        print(f"📄 Test results saved to {args.output}")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())