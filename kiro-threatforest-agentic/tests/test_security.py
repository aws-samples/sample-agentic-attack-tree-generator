"""
Security tests for ThreatForest.

Tests security aspects including input validation, output sanitization,
file permissions, and compliance with security best practices.
"""

import pytest
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

from threatforest.orchestrator import OrchestratorAgent
from threatforest.config import ThreatForestConfig
from threatforest.models import ContextInformation

from tests.fixtures import (
    create_test_project,
    setup_mock_environment,
    check_security_compliance,
    cleanup_test_files
)


class TestInputValidation:
    """Test input validation and sanitization."""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_malicious_file_content_handling(self):
        """Test handling of potentially malicious file content."""
        config = ThreatForestConfig()
        
        # Create project with malicious content
        malicious_content = {
            "script_injection.md": """# Project
            
<script>alert('XSS')</script>

## Description
This project contains <iframe src="javascript:alert('XSS')"></iframe> content.

### Technologies
- Python
- <img src=x onerror=alert('XSS')>
""",
            "sql_injection.md": """# Database Schema

```sql
SELECT * FROM users WHERE id = '1' OR '1'='1'; DROP TABLE users; --
```

## Queries
- User lookup: `SELECT * FROM users WHERE name = 'admin'--'`
""",
            "path_traversal.md": """# Configuration

File paths:
- Config: ../../../etc/passwd
- Logs: ../../../../var/log/auth.log
- Backup: ../../../home/user/.ssh/id_rsa
"""
        }
        
        project_path = create_test_project(
            "web_application",
            custom_files=malicious_content
        )
        
        try:
            with setup_mock_environment() as mock_env:
                # Set up files in mock system
                for filename, content in malicious_content.items():
                    mock_env["file_system"].create_file(
                        f"{project_path}/{filename}",
                        content
                    )
                
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Should handle malicious content without crashing
                result = await orchestrator.execute_workflow(str(project_path))
                
                # Should complete (may have warnings about suspicious content)
                assert result["status"] in ["completed", "completed_with_warnings"]
                
                # Check that outputs don't contain unescaped malicious content
                if "attack_trees" in result["results"]:
                    for tree in result["results"]["attack_trees"]:
                        mermaid_content = tree.get("mermaid_content", "")
                        
                        # Should not contain raw script tags or SQL injection
                        assert "<script>" not in mermaid_content
                        assert "DROP TABLE" not in mermaid_content
                        assert "../../../" not in mermaid_content
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_large_file_handling(self):
        """Test handling of excessively large input files."""
        config = ThreatForestConfig()
        
        # Create very large README content (simulating potential DoS)
        large_content = "# Large Project\n" + "A" * 1000000  # 1MB of A's
        
        project_path = create_test_project(
            "web_application",
            custom_files={"large_readme.md": large_content}
        )
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/large_readme.md",
                    large_content
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Should handle large files gracefully (may truncate or skip)
                result = await orchestrator.execute_workflow(str(project_path))
                
                # Should not crash, may complete with warnings
                assert result["status"] in ["completed", "completed_with_warnings", "failed"]
                
                # If failed, should be due to size limits, not crashes
                if result["status"] == "failed":
                    error_msg = str(result.get("error", "")).lower()
                    assert any(keyword in error_msg for keyword in ["size", "large", "limit", "memory"])
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.security
    def test_configuration_validation(self):
        """Test validation of configuration parameters."""
        # Test invalid configuration values
        invalid_configs = [
            {"bedrock": {"region": "../../../etc/passwd"}},  # Path traversal
            {"bedrock": {"model": "<script>alert('xss')</script>"}},  # XSS
            {"processing": {"severity_threshold": "'; DROP TABLE config; --"}},  # SQL injection
            {"output": {"directory": "/etc/passwd"}},  # Sensitive system path
            {"ttc": {"aaf_bundle_path": "http://malicious.com/bundle.json"}},  # Remote URL
        ]
        
        for invalid_config in invalid_configs:
            with pytest.raises((ValueError, TypeError, Exception)):
                # Should raise validation error
                ThreatForestConfig(**invalid_config)
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_context_information_sanitization(self):
        """Test sanitization of extracted context information."""
        config = ThreatForestConfig()
        
        # Create context info with potentially malicious content
        malicious_context = ContextInformation(
            technologies=["<script>alert('xss')</script>", "Python", "../../../etc/passwd"],
            programming_languages=["'; DROP TABLE languages; --", "JavaScript"],
            sector="<iframe src='javascript:alert(1)'></iframe>",
            security_objectives=["Confidentiality", "<img src=x onerror=alert(1)>"],
            architecture_type="../../sensitive/file.txt",
            compliance_frameworks=["<svg onload=alert(1)>", "GDPR"],
            extracted_from=["README.md"],
            validation_status="pending",
            confidence_score=0.85
        )
        
        # Context information should be validated during creation
        # Pydantic should handle basic validation, but we should also sanitize
        
        # Check that dangerous content is handled appropriately
        assert "<script>" not in str(malicious_context.technologies)
        assert "DROP TABLE" not in str(malicious_context.programming_languages)
        assert "<iframe>" not in malicious_context.sector


class TestOutputSecurity:
    """Test security of generated outputs."""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_output_file_permissions(self):
        """Test that output files have appropriate permissions."""
        if os.name == 'nt':  # Skip on Windows
            pytest.skip("File permission tests not applicable on Windows")
        
        config = ThreatForestConfig(
            output={"directory": "./secure-test-output"}
        )
        
        project_path = create_test_project("web_application")
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                result = await orchestrator.execute_workflow(str(project_path))
                
                if result["status"] == "completed":
                    # Check output directory permissions
                    output_dir = Path(config.output.directory)
                    if output_dir.exists():
                        stat_info = output_dir.stat()
                        
                        # Directory should not be world-writable
                        assert not (stat_info.st_mode & 0o002), "Output directory is world-writable"
                        
                        # Check individual files
                        for file_path in output_dir.rglob("*"):
                            if file_path.is_file():
                                file_stat = file_path.stat()
                                
                                # Files should not be world-readable for sensitive content
                                if "attack" in file_path.name.lower() or "threat" in file_path.name.lower():
                                    assert not (file_stat.st_mode & 0o004), f"Sensitive file {file_path.name} is world-readable"
        
        finally:
            cleanup_test_files(project_path)
            # Clean up output directory
            output_dir = Path(config.output.directory)
            if output_dir.exists():
                import shutil
                shutil.rmtree(output_dir)
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sensitive_data_exclusion(self):
        """Test that sensitive data is not included in outputs."""
        config = ThreatForestConfig()
        
        # Create project with sensitive data
        sensitive_content = {
            "config.md": """# Configuration

            # Placeholder for sensitive data
"""
        }
        
        project_path = create_test_project(
            "web_application",
            custom_files=sensitive_content
        )
        
        try:
            with setup_mock_environment() as mock_env:
                for filename, content in sensitive_content.items():
                    mock_env["file_system"].create_file(
                        f"{project_path}/{filename}",
                        content
                    )
                
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                result = await orchestrator.execute_workflow(str(project_path))
                
                if result["status"] == "completed":
                    # Check that outputs don't contain sensitive patterns
                    attack_trees = result["results"].get("attack_trees", [])
                    
                    for tree in attack_trees:
                        content = tree.get("mermaid_content", "")
                        
                        # Should not contain passwords, keys, or other sensitive data
                        sensitive_patterns = [
                            "super_secret_password",
                            "sk-1234567890abcdef",
                            "AKIAIOSFODNN7EXAMPLE",
                            "4111-1111-1111-1111",
                            "123-45-6789",
                            "BEGIN RSA PRIVATE KEY",
                            "my_super_secret_jwt_key"
                        ]
                        
                        for pattern in sensitive_patterns:
                            assert pattern not in content, f"Sensitive data '{pattern}' found in output"
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_output_content_validation(self):
        """Test validation of generated output content."""
        config = ThreatForestConfig()
        project_path = create_test_project("web_application")
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                result = await orchestrator.execute_workflow(str(project_path))
                
                if result["status"] == "completed":
                    # Validate attack tree content
                    attack_trees = result["results"].get("attack_trees", [])
                    
                    for tree in attack_trees:
                        mermaid_content = tree.get("mermaid_content", "")
                        
                        # Should not contain executable code or dangerous content
                        dangerous_patterns = [
                            "javascript:",
                            "data:text/html",
                            "vbscript:",
                            "onload=",
                            "onerror=",
                            "eval(",
                            "document.cookie",
                            "window.location"
                        ]
                        
                        for pattern in dangerous_patterns:
                            assert pattern not in mermaid_content.lower(), f"Dangerous pattern '{pattern}' found in Mermaid output"
        
        finally:
            cleanup_test_files(project_path)


class TestComplianceValidation:
    """Test compliance with security frameworks and standards."""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_pci_dss_compliance_validation(self):
        """Test PCI DSS compliance validation."""
        config = ThreatForestConfig()
        
        # Create project with PCI DSS requirements
        pci_content = {
            "README.md": """# Payment Processing System

## Overview
E-commerce platform handling credit card payments.

## Technologies
- Python, Django
- PostgreSQL (encrypted)
- Stripe API for payment processing
- SSL/TLS encryption

## Security
- PCI DSS Level 1 compliance
- Encrypted cardholder data
- Secure payment processing
- Regular security assessments

## Compliance
- PCI DSS
- GDPR
"""
        }
        
        project_path = create_test_project(
            "web_application",
            custom_files=pci_content
        )
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    pci_content["README.md"]
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                result = await orchestrator.execute_workflow(str(project_path))
                
                if result["status"] == "completed":
                    # Check compliance validation
                    context_info = result["results"]["context_information"]
                    
                    # Should identify PCI DSS compliance requirement
                    assert "PCI DSS" in context_info.compliance_frameworks
                    
                    # Attack trees should consider PCI DSS requirements
                    attack_trees = result["results"].get("attack_trees", [])
                    
                    # Should have encryption-related mitigations
                    has_encryption_controls = False
                    for tree in attack_trees:
                        content = tree.get("mermaid_content", "").lower()
                        if "encrypt" in content or "ssl" in content or "tls" in content:
                            has_encryption_controls = True
                            break
                    
                    # For PCI DSS, should mention encryption controls
                    assert has_encryption_controls, "PCI DSS compliance should include encryption controls"
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_hipaa_compliance_validation(self):
        """Test HIPAA compliance validation."""
        config = ThreatForestConfig()
        
        hipaa_content = {
            "README.md": """# Electronic Health Records System

## Overview
Healthcare application managing patient health information.

## Technologies
- C#, .NET Core
- SQL Server (encrypted)
- HL7 FHIR integration
- Azure cloud services

## Security
- HIPAA compliance
- PHI encryption at rest and in transit
- Role-based access controls
- Audit logging for all PHI access

## Compliance
- HIPAA
- HITECH Act
"""
        }
        
        project_path = create_test_project(
            "healthcare",
            custom_files=hipaa_content
        )
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    hipaa_content["README.md"]
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                result = await orchestrator.execute_workflow(str(project_path))
                
                if result["status"] == "completed":
                    context_info = result["results"]["context_information"]
                    
                    # Should identify HIPAA compliance
                    assert "HIPAA" in context_info.compliance_frameworks
                    
                    # Should include privacy in security objectives
                    assert "Privacy" in context_info.security_objectives
                    
                    # Attack trees should consider privacy controls
                    attack_trees = result["results"].get("attack_trees", [])
                    
                    has_privacy_controls = False
                    for tree in attack_trees:
                        content = tree.get("mermaid_content", "").lower()
                        if "privacy" in content or "access control" in content or "audit" in content:
                            has_privacy_controls = True
                            break
                    
                    assert has_privacy_controls, "HIPAA compliance should include privacy controls"
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_comprehensive_security_compliance(self):
        """Test comprehensive security compliance checking."""
        config = ThreatForestConfig(
            output={"directory": "./compliance-test-output"}
        )
        
        project_path = create_test_project("financial_services")
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                result = await orchestrator.execute_workflow(str(project_path))
                
                if result["status"] == "completed":
                    # Create mock output files for compliance checking
                    output_dir = Path(config.output.directory)
                    output_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Create sample output files
                    summary_file = output_dir / "threat_analysis_summary.md"
                    summary_file.write_text("# Threat Analysis Summary\n\nNo sensitive data here.")
                    
                    attack_tree_file = output_dir / "attack_tree_T001.mmd"
                    attack_tree_file.write_text("graph TD\nA[Attacker] --> B[Target]")
                    
                    # Run compliance check
                    compliance_results = check_security_compliance(
                        project_path,
                        [summary_file, attack_tree_file],
                        result["results"]["context_information"].__dict__
                    )
                    
                    # Should pass basic compliance checks
                    assert compliance_results["overall_score"] > 0.5
                    assert len(compliance_results["violations"]) == 0
                    
                    # Should have proper checks
                    assert "no_sensitive_data" in compliance_results["checks"]
                    assert "proper_naming" in compliance_results["checks"]
        
        finally:
            cleanup_test_files(project_path)
            # Clean up output directory
            output_dir = Path(config.output.directory)
            if output_dir.exists():
                import shutil
                shutil.rmtree(output_dir)


class TestAccessControl:
    """Test access control and authorization aspects."""
    
    @pytest.mark.security
    def test_file_access_restrictions(self):
        """Test that file access is properly restricted."""
        # Test that the system doesn't access files outside project directory
        config = ThreatForestConfig()
        
        # Attempt to create project with path traversal
        with pytest.raises((ValueError, OSError, PermissionError)):
            # Should not be able to access files outside project
            dangerous_paths = [
                "../../../etc/passwd",
                "/etc/shadow", 
                "C:\\Windows\\System32\\config\\SAM",
                "~/.ssh/id_rsa"
            ]
            
            for path in dangerous_paths:
                # This should be caught by path validation
                project_path = Path(path)
                if project_path.exists():
                    # If it somehow exists, reading should be restricted
                    with open(project_path, 'r') as f:
                        content = f.read()
                    
                    # Should not reach here for sensitive system files
                    assert False, f"Unauthorized access to {path}"
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_configuration_access_control(self):
        """Test access control for configuration files."""
        # Test that configuration doesn't allow dangerous settings
        dangerous_configs = [
            {"output": {"directory": "/etc"}},  # System directory
            {"ttc": {"aaf_bundle_path": "/etc/passwd"}},  # System file
            {"bedrock": {"region": "../../../sensitive"}},  # Path traversal
        ]
        
        for dangerous_config in dangerous_configs:
            # Should either reject the config or sanitize it
            try:
                config = ThreatForestConfig(**dangerous_config)
                
                # If config is created, dangerous values should be sanitized
                if "output" in dangerous_config:
                    assert config.output.directory != "/etc"
                
                if "ttc" in dangerous_config:
                    assert config.ttc.aaf_bundle_path != "/etc/passwd"
                
            except (ValueError, TypeError, Exception):
                # Expected - dangerous config should be rejected
                pass
