"""
Test utilities for ThreatForest comprehensive testing.

Provides utility functions for creating test environments,
validating outputs, measuring performance, and checking security compliance.
"""

import os
import time
import json
import tempfile
import shutil
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
from unittest.mock import patch

from .sample_data import SAMPLE_README_CONTENT, SAMPLE_THREATS_DATA, SAMPLE_ARCHITECTURE_CONTENT
from .mock_services import MockFileSystem, create_mock_environment


def create_test_project(
    project_type: str = "web_application",
    include_threats: bool = True,
    include_architecture: bool = True,
    custom_files: Optional[Dict[str, str]] = None
) -> Path:
    """
    Create a temporary test project directory with sample files.
    
    Args:
        project_type: Type of project (web_application, financial_services, healthcare)
        include_threats: Whether to include threat statements
        include_architecture: Whether to include architecture diagrams
        custom_files: Additional custom files to create
        
    Returns:
        Path to the created test project directory
    """
    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp(prefix="tf_test_"))
    
    # Create README.md
    readme_content = SAMPLE_README_CONTENT.get(project_type, SAMPLE_README_CONTENT['web_application'])
    (temp_dir / "README.md").write_text(readme_content)
    
    # Create threats.md if requested
    if include_threats:
        threats_key = f"{project_type}_threats"
        threats_data = SAMPLE_THREATS_DATA.get(threats_key, SAMPLE_THREATS_DATA['web_application_threats'])
        
        threats_content = "# Threat Statements\n\n"
        for threat in threats_data:
            threats_content += f"## {threat['id']}: Threat\n"
            threats_content += f"- **Severity**: {threat['severity']}\n"
            threats_content += f"- **Threat Source**: {threat['threat_source']}\n"
            threats_content += f"- **Prerequisites**: {threat['prerequisites']}\n"
            threats_content += f"- **Threat Action**: {threat['threat_action']}\n"
            threats_content += f"- **Threat Impact**: {threat['threat_impact']}\n"
            threats_content += f"- **Impacted Assets**: {', '.join(threat['impacted_assets'])}\n"
            threats_content += f"- **Impacted Goals**: {', '.join(threat['impacted_goals'])}\n\n"
        
        (temp_dir / "threats.md").write_text(threats_content)
    
    # Create architecture.md if requested
    if include_architecture:
        (temp_dir / "architecture.md").write_text(SAMPLE_ARCHITECTURE_CONTENT)
    
    # Create custom files if provided
    if custom_files:
        for filename, content in custom_files.items():
            file_path = temp_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
    
    return temp_dir


@contextmanager
def setup_mock_environment(
    simulate_errors: bool = False,
    response_delay: float = 0.0,
    custom_stix_data: Optional[Dict] = None
):
    """
    Context manager for setting up a complete mock environment.
    
    Args:
        simulate_errors: Whether to simulate API errors
        response_delay: Simulated response delay
        custom_stix_data: Custom STIX bundle data
        
    Yields:
        Dictionary containing mock environment components
    """
    # Create mock environment
    mock_env = create_mock_environment()
    
    # Configure mock services
    mock_env["bedrock_client"].simulate_errors = simulate_errors
    mock_env["bedrock_client"].response_delay = response_delay
    
    if custom_stix_data:
        mock_env["stix_processor"].bundle_data = custom_stix_data
        mock_env["stix_processor"].techniques = mock_env["stix_processor"]._extract_techniques()
    
    try:
        yield mock_env
    finally:
        # Cleanup if needed
        mock_env["file_system"].clear()


def validate_attack_tree_format(mermaid_content: str) -> Tuple[bool, List[str]]:
    """
    Validate that attack tree content follows proper Mermaid format.
    
    Args:
        mermaid_content: Mermaid diagram content to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check for basic Mermaid structure
    if not mermaid_content.strip().startswith(('graph', 'flowchart')):
        errors.append("Attack tree must start with 'graph' or 'flowchart' declaration")
    
    # Check for node definitions
    node_pattern = r'[A-Z]\[.*?\]'
    nodes = re.findall(node_pattern, mermaid_content)
    if len(nodes) < 3:
        errors.append("Attack tree must contain at least 3 nodes")
    
    # Check for connections
    connection_pattern = r'[A-Z]\s*-->\s*[A-Z]'
    connections = re.findall(connection_pattern, mermaid_content)
    if len(connections) < 2:
        errors.append("Attack tree must contain at least 2 connections")
    
    # Check for styling (optional but recommended)
    if 'classDef' not in mermaid_content:
        errors.append("Attack tree should include styling definitions (classDef)")
    
    # Check for required node types
    required_patterns = {
        'goal': r'class.*goal',
        'attack': r'class.*attack',
        'mitigation': r'class.*mitigation'
    }
    
    for node_type, pattern in required_patterns.items():
        if not re.search(pattern, mermaid_content):
            errors.append(f"Attack tree should include {node_type} nodes")
    
    return len(errors) == 0, errors


def measure_performance(func, *args, **kwargs) -> Dict[str, Any]:
    """
    Measure performance metrics for a function call.
    
    Args:
        func: Function to measure
        *args: Function arguments
        **kwargs: Function keyword arguments
        
    Returns:
        Dictionary containing performance metrics
    """
    import tracemalloc
    
    # Start memory tracing
    tracemalloc.start()
    
    # Get initial system metrics (optional psutil)
    initial_memory = 0
    final_memory = 0
    initial_cpu_percent = 0.0
    final_cpu_percent = 0.0
    
    try:
        import psutil
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        initial_cpu_percent = process.cpu_percent()
        psutil_available = True
    except ImportError:
        psutil_available = False
    
    # Measure execution time
    start_time = time.time()
    
    try:
        result = func(*args, **kwargs)
        success = True
        error = None
    except Exception as e:
        result = None
        success = False
        error = str(e)
    
    end_time = time.time()
    
    # Get final system metrics
    if psutil_available:
        try:
            import psutil
            process = psutil.Process()
            final_memory = process.memory_info().rss
            final_cpu_percent = process.cpu_percent()
        except ImportError:
            pass
    
    # Get memory trace
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return {
        "success": success,
        "error": error,
        "result": result,
        "execution_time": end_time - start_time,
        "memory_usage": {
            "initial_rss": initial_memory,
            "final_rss": final_memory,
            "peak_traced": peak,
            "current_traced": current
        },
        "cpu_usage": {
            "initial_percent": initial_cpu_percent,
            "final_percent": final_cpu_percent
        }
    }


def check_security_compliance(
    project_path: Path,
    output_files: List[Path],
    context_info: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Check security compliance of generated outputs.
    
    Args:
        project_path: Path to the analyzed project
        output_files: List of generated output files
        context_info: Context information from analysis
        
    Returns:
        Dictionary containing compliance check results
    """
    compliance_results = {
        "overall_score": 0.0,
        "checks": {},
        "violations": [],
        "recommendations": []
    }
    
    # Check 1: No sensitive data in outputs
    sensitive_patterns = [
        r'password\s*[:=]\s*\S+',
        r'api[_-]?key\s*[:=]\s*\S+',
        r'secret\s*[:=]\s*\S+',
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card pattern
        r'\b\d{3}-\d{2}-\d{4}\b'  # SSN pattern
    ]
    
    sensitive_data_found = False
    for file_path in output_files:
        if file_path.exists() and file_path.suffix in ['.md', '.txt', '.json']:
            content = file_path.read_text()
            for pattern in sensitive_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    sensitive_data_found = True
                    compliance_results["violations"].append(
                        f"Potential sensitive data found in {file_path.name}"
                    )
    
    compliance_results["checks"]["no_sensitive_data"] = not sensitive_data_found
    
    # Check 2: Proper file permissions (if on Unix-like system)
    if os.name != 'nt':  # Not Windows
        proper_permissions = True
        for file_path in output_files:
            if file_path.exists():
                stat_info = file_path.stat()
                # Check if file is world-readable (should not be for sensitive outputs)
                if stat_info.st_mode & 0o004:
                    proper_permissions = False
                    compliance_results["violations"].append(
                        f"File {file_path.name} is world-readable"
                    )
        
        compliance_results["checks"]["proper_permissions"] = proper_permissions
    
    # Check 3: Output file naming conventions
    proper_naming = True
    for file_path in output_files:
        filename = file_path.name
        # Check for proper naming (no spaces, special characters)
        if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
            proper_naming = False
            compliance_results["violations"].append(
                f"File {filename} uses improper naming convention"
            )
    
    compliance_results["checks"]["proper_naming"] = proper_naming
    
    # Check 4: Compliance framework alignment
    if context_info and context_info.get("compliance_frameworks"):
        frameworks = context_info["compliance_frameworks"]
        compliance_alignment = True
        
        # Check for framework-specific requirements
        if "PCI DSS" in frameworks:
            # Should have encryption and access control mentions
            has_encryption_controls = any(
                "encrypt" in file_path.read_text().lower()
                for file_path in output_files
                if file_path.exists() and file_path.suffix in ['.md', '.txt']
            )
            if not has_encryption_controls:
                compliance_alignment = False
                compliance_results["violations"].append(
                    "PCI DSS compliance requires encryption controls in threat model"
                )
        
        if "HIPAA" in frameworks:
            # Should have privacy and access control mentions
            has_privacy_controls = any(
                "privacy" in file_path.read_text().lower() or "access control" in file_path.read_text().lower()
                for file_path in output_files
                if file_path.exists() and file_path.suffix in ['.md', '.txt']
            )
            if not has_privacy_controls:
                compliance_alignment = False
                compliance_results["violations"].append(
                    "HIPAA compliance requires privacy controls in threat model"
                )
        
        compliance_results["checks"]["compliance_alignment"] = compliance_alignment
    
    # Calculate overall score
    total_checks = len(compliance_results["checks"])
    passed_checks = sum(1 for passed in compliance_results["checks"].values() if passed)
    compliance_results["overall_score"] = passed_checks / total_checks if total_checks > 0 else 0.0
    
    # Generate recommendations
    if compliance_results["overall_score"] < 1.0:
        compliance_results["recommendations"].extend([
            "Review and address all compliance violations",
            "Implement proper file permissions for sensitive outputs",
            "Ensure no sensitive data is included in generated files",
            "Follow proper naming conventions for output files"
        ])
    
    return compliance_results


def create_performance_test_data(size: str = "medium") -> Dict[str, Any]:
    """
    Create test data of various sizes for performance testing.
    
    Args:
        size: Size of test data (small, medium, large, xlarge)
        
    Returns:
        Dictionary containing test data
    """
    sizes = {
        "small": {"threats": 5, "readme_lines": 50, "files": 3},
        "medium": {"threats": 20, "readme_lines": 200, "files": 10},
        "large": {"threats": 100, "readme_lines": 1000, "files": 50},
        "xlarge": {"threats": 500, "readme_lines": 5000, "files": 200}
    }
    
    config = sizes.get(size, sizes["medium"])
    
    # Generate README content
    base_readme = SAMPLE_README_CONTENT["web_application"]
    readme_content = base_readme
    
    # Extend README to target line count
    current_lines = len(base_readme.split('\n'))
    if current_lines < config["readme_lines"]:
        additional_lines = config["readme_lines"] - current_lines
        readme_content += "\n\n" + "\n".join([
            f"## Additional Section {i}"
            f"\nThis is additional content for performance testing. "
            f"Line {i} of extended README content."
            for i in range(additional_lines // 3)
        ])
    
    # Generate threat statements
    threats = []
    base_threat = SAMPLE_THREATS_DATA["web_application_threats"][0]
    
    for i in range(config["threats"]):
        threat = base_threat.copy()
        threat["id"] = f"T{i+1:03d}"
        threat["threat_action"] = f"Threat action {i+1}: {threat['threat_action']}"
        threat["threat_impact"] = f"Impact {i+1}: {threat['threat_impact']}"
        threats.append(threat)
    
    # Generate additional files
    additional_files = {}
    for i in range(config["files"] - 3):  # Subtract README, threats, architecture
        additional_files[f"document_{i+1}.md"] = f"""# Document {i+1}

This is additional documentation file {i+1} for performance testing.

## Content
{'Content line ' * 20}

## More Content
{'Additional content line ' * 15}
"""
    
    return {
        "readme_content": readme_content,
        "threats_data": threats,
        "additional_files": additional_files,
        "expected_metrics": {
            "file_count": config["files"],
            "threat_count": config["threats"],
            "readme_size": len(readme_content)
        }
    }


def cleanup_test_files(*paths: Path):
    """
    Clean up test files and directories.
    
    Args:
        *paths: Paths to clean up
    """
    for path in paths:
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def assert_valid_mermaid(content: str, min_nodes: int = 3):
    """
    Assert that content is valid Mermaid format.
    
    Args:
        content: Mermaid content to validate
        min_nodes: Minimum number of nodes required
        
    Raises:
        AssertionError: If content is not valid Mermaid
    """
    is_valid, errors = validate_attack_tree_format(content)
    
    if not is_valid:
        raise AssertionError(f"Invalid Mermaid format: {'; '.join(errors)}")
    
    # Check minimum nodes
    node_pattern = r'[A-Z]\[.*?\]'
    nodes = re.findall(node_pattern, content)
    if len(nodes) < min_nodes:
        raise AssertionError(f"Expected at least {min_nodes} nodes, found {len(nodes)}")


def assert_performance_within_limits(
    metrics: Dict[str, Any],
    max_execution_time: float = 30.0,
    max_memory_mb: float = 500.0
):
    """
    Assert that performance metrics are within acceptable limits.
    
    Args:
        metrics: Performance metrics from measure_performance()
        max_execution_time: Maximum allowed execution time in seconds
        max_memory_mb: Maximum allowed memory usage in MB
        
    Raises:
        AssertionError: If performance is outside limits
    """
    execution_time = metrics.get("execution_time", 0)
    if execution_time > max_execution_time:
        raise AssertionError(
            f"Execution time {execution_time:.2f}s exceeds limit of {max_execution_time}s"
        )
    
    peak_memory = metrics.get("memory_usage", {}).get("peak_traced", 0)
    peak_memory_mb = peak_memory / (1024 * 1024)
    
    if peak_memory_mb > max_memory_mb:
        raise AssertionError(
            f"Memory usage {peak_memory_mb:.2f}MB exceeds limit of {max_memory_mb}MB"
        )


def generate_test_report(test_results: Dict[str, Any], output_path: Path):
    """
    Generate a comprehensive test report.
    
    Args:
        test_results: Dictionary containing test results
        output_path: Path to save the report
    """
    report_content = f"""# ThreatForest Test Report

Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Test Summary
- **Total Tests**: {test_results.get('total_tests', 0)}
- **Passed**: {test_results.get('passed_tests', 0)}
- **Failed**: {test_results.get('failed_tests', 0)}
- **Success Rate**: {test_results.get('success_rate', 0):.1%}

## Performance Metrics
- **Average Execution Time**: {test_results.get('avg_execution_time', 0):.2f}s
- **Peak Memory Usage**: {test_results.get('peak_memory_mb', 0):.2f}MB
- **Total Test Duration**: {test_results.get('total_duration', 0):.2f}s

## Security Compliance
- **Compliance Score**: {test_results.get('compliance_score', 0):.1%}
- **Violations Found**: {len(test_results.get('violations', []))}

## Test Categories
"""
    
    for category, results in test_results.get('categories', {}).items():
        report_content += f"\n### {category.title()}\n"
        report_content += f"- Tests: {results.get('count', 0)}\n"
        report_content += f"- Success Rate: {results.get('success_rate', 0):.1%}\n"
        
        if results.get('failures'):
            report_content += "- Failures:\n"
            for failure in results['failures']:
                report_content += f"  - {failure}\n"
    
    # Write report
    output_path.write_text(report_content)