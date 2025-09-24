"""
Pytest configuration and fixtures for ThreatForest comprehensive test suite.

Provides shared fixtures, test markers, and configuration for all test modules.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator

from tests.fixtures import create_test_project, setup_mock_environment, cleanup_test_files


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (may be slow)"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests (may be slow)"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow running"
    )


@pytest.fixture(scope="session")
def temp_workspace() -> Generator[Path, None, None]:
    """Create a temporary workspace for the test session."""
    temp_dir = Path(tempfile.mkdtemp(prefix="tf_test_workspace_"))
    try:
        yield temp_dir
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


@pytest.fixture
def test_project_web() -> Generator[Path, None, None]:
    """Create a temporary web application test project."""
    project_path = create_test_project("web_application")
    try:
        yield project_path
    finally:
        cleanup_test_files(project_path)


@pytest.fixture
def test_project_financial() -> Generator[Path, None, None]:
    """Create a temporary financial services test project."""
    project_path = create_test_project("financial_services")
    try:
        yield project_path
    finally:
        cleanup_test_files(project_path)


@pytest.fixture
def test_project_healthcare() -> Generator[Path, None, None]:
    """Create a temporary healthcare test project."""
    project_path = create_test_project("healthcare")
    try:
        yield project_path
    finally:
        cleanup_test_files(project_path)


@pytest.fixture
def mock_environment():
    """Create a mock environment for testing."""
    with setup_mock_environment() as mock_env:
        yield mock_env


@pytest.fixture
def mock_environment_with_errors():
    """Create a mock environment that simulates errors."""
    with setup_mock_environment(simulate_errors=True) as mock_env:
        yield mock_env


@pytest.fixture
def mock_environment_slow():
    """Create a mock environment with slow responses."""
    with setup_mock_environment(response_delay=0.5) as mock_env:
        yield mock_env


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup temporary files after each test."""
    # Setup
    temp_files = []
    temp_dirs = []
    
    yield
    
    # Cleanup
    for file_path in temp_files:
        if file_path.exists():
            file_path.unlink()
    
    for dir_path in temp_dirs:
        if dir_path.exists():
            shutil.rmtree(dir_path)


# Performance test configuration
@pytest.fixture
def performance_limits():
    """Default performance limits for tests."""
    return {
        "max_execution_time": 30.0,  # seconds
        "max_memory_mb": 500.0,      # MB
        "max_api_calls": 100,        # number of calls
        "max_file_size_mb": 10.0     # MB
    }


# Security test configuration
@pytest.fixture
def security_patterns():
    """Security patterns to check for in outputs."""
    return {
        "sensitive_data": [
            r'password\s*[:=]\s*\S+',
            r'api[_-]?key\s*[:=]\s*\S+',
            r'secret\s*[:=]\s*\S+',
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b\d{3}-\d{2}-\d{4}\b'  # SSN
        ],
        "dangerous_content": [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'eval\s*\(',
            r'document\.cookie',
            r'window\.location'
        ],
        "path_traversal": [
            r'\.\./\.\./\.\.',
            r'\.\.\\\.\.\\\.\.\\',
            r'/etc/passwd',
            r'C:\\Windows\\System32'
        ]
    }


# Test data fixtures
@pytest.fixture
def sample_threat_data():
    """Sample threat data for testing."""
    return {
        "high_severity": {
            "id": "T001",
            "severity": "High",
            "threat_source": "External attacker",
            "prerequisites": "Network access, vulnerability exists",
            "threat_action": "Exploit vulnerability to gain access",
            "threat_impact": "Data breach, system compromise",
            "impacted_assets": ["Database", "Web application"],
            "impacted_goals": ["Confidentiality", "Integrity"]
        },
        "medium_severity": {
            "id": "T002", 
            "severity": "Medium",
            "threat_source": "Malicious insider",
            "prerequisites": "Employee access, insufficient monitoring",
            "threat_action": "Abuse legitimate access to steal data",
            "threat_impact": "Data leak, privacy violation",
            "impacted_assets": ["Customer data", "Internal systems"],
            "impacted_goals": ["Confidentiality", "Privacy"]
        }
    }


@pytest.fixture
def sample_context_data():
    """Sample context data for testing."""
    return {
        "web_app": {
            "technologies": ["Python", "Django", "PostgreSQL", "Redis"],
            "programming_languages": ["Python", "JavaScript"],
            "sector": "E-commerce",
            "security_objectives": ["Confidentiality", "Integrity", "Availability"],
            "architecture_type": "Microservices",
            "compliance_frameworks": ["PCI DSS", "GDPR"]
        },
        "financial": {
            "technologies": ["Java", "Spring Boot", "Oracle", "Angular"],
            "programming_languages": ["Java", "TypeScript"],
            "sector": "Financial Services",
            "security_objectives": ["Confidentiality", "Integrity", "Availability", "Compliance"],
            "architecture_type": "Monolithic",
            "compliance_frameworks": ["SOX", "FFIEC", "PCI DSS"]
        }
    }


# Pytest hooks for test reporting
def pytest_runtest_makereport(item, call):
    """Generate custom test reports."""
    if "tmpdir" in item.fixturenames:
        # Clean up any temporary directories created during test
        pass


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Add markers based on test file names
        if "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        
        if "test_performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        
        if "test_security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        
        # Mark slow tests
        if any(keyword in item.name for keyword in ["large", "concurrent", "stress", "benchmark"]):
            item.add_marker(pytest.mark.slow)


# Custom assertions
def assert_no_sensitive_data(content: str, patterns: list):
    """Assert that content doesn't contain sensitive data patterns."""
    import re
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        assert not matches, f"Sensitive data pattern '{pattern}' found: {matches}"


def assert_valid_json(content: str):
    """Assert that content is valid JSON."""
    import json
    
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        pytest.fail(f"Invalid JSON content: {e}")


def assert_valid_yaml(content: str):
    """Assert that content is valid YAML."""
    import yaml
    
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        pytest.fail(f"Invalid YAML content: {e}")


# Register custom assertions
pytest.assert_no_sensitive_data = assert_no_sensitive_data
pytest.assert_valid_json = assert_valid_json
pytest.assert_valid_yaml = assert_valid_yaml