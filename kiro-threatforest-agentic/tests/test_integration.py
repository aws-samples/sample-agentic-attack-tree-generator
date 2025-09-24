"""
Integration tests for ThreatForest complete pipeline.

Tests the end-to-end workflow from context detection through
attack tree generation and TTC enhancement.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

from threatforest.models import ContextInformation, ThreatStatement
from threatforest.orchestrator import OrchestratorAgent
from threatforest.config import ThreatForestConfig

from tests.fixtures import (
    create_test_project,
    setup_mock_environment,
    validate_attack_tree_format,
    measure_performance,
    check_security_compliance,
    cleanup_test_files,
    assert_valid_mermaid,
    assert_performance_within_limits
)


class TestEndToEndWorkflow:
    """Test complete end-to-end workflow scenarios."""
    
    @pytest.fixture
    def test_config(self):
        """Create test configuration."""
        return ThreatForestConfig(
            bedrock={
                "region": "us-east-1",
                "model": "anthropic.claude-3-sonnet-20240229-v1:0",
                "timeout_seconds": 300
            },
            processing={
                "severity_threshold": "high",
                "max_concurrent_agents": 2,
                "timeout_seconds": 600
            },
            output={
                "directory": "./test-output",
                "format": "mermaid",
                "include_summary": True
            },
            ttc={
                "aaf_bundle_path": "./test-aaf-bundle.json",
                "alignment_threshold": 0.8,
                "enable_enhancement": True
            }
        )
    
    @pytest.mark.asyncio
    async def test_complete_web_application_analysis(self, test_config):
        """Test complete analysis of web application project."""
        # Create test project
        project_path = create_test_project("web_application")
        
        try:
            with setup_mock_environment() as mock_env:
                # Set up project files in mock file system
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                # Create orchestrator with mock environment
                orchestrator = OrchestratorAgent(
                    config=test_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Run complete workflow
                results = await orchestrator.execute_workflow(str(project_path))
                
                # Validate results
                assert results["status"] == "completed"
                assert "context_files" in results["results"]
                assert "context_information" in results["results"]
                assert "attack_trees" in results["results"]
                
                # Validate context files were detected
                context_files = results["results"]["context_files"]
                assert len(context_files) >= 2  # README and threats
                
                file_types = [f["type"] for f in context_files]
                assert "readme" in file_types
                assert "threats" in file_types
                
                # Validate context information extraction
                context_info = results["results"]["context_information"]
                assert isinstance(context_info, ContextInformation)
                assert len(context_info.technologies) > 0
                assert len(context_info.programming_languages) > 0
                assert context_info.sector is not None
                
                # Validate attack trees generation
                attack_trees = results["results"]["attack_trees"]
                assert len(attack_trees) > 0
                
                for tree in attack_trees:
                    assert "threat_id" in tree
                    assert "mermaid_content" in tree
                    assert "severity" in tree
                    
                    # Validate Mermaid format
                    is_valid, errors = validate_attack_tree_format(tree["mermaid_content"])
                    assert is_valid, f"Invalid Mermaid format: {errors}"
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.asyncio
    async def test_financial_services_analysis(self, test_config):
        """Test analysis of financial services project."""
        project_path = create_test_project("financial_services")
        
        try:
            with setup_mock_environment() as mock_env:
                # Set up project files
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=test_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                results = await orchestrator.execute_workflow(str(project_path))
                
                # Validate financial services specific aspects
                assert results["status"] == "completed"
                
                context_info = results["results"]["context_information"]
                assert "Financial Services" in context_info.sector or "Banking" in context_info.sector
                
                # Should have compliance frameworks
                assert len(context_info.compliance_frameworks) > 0
                expected_frameworks = ["SOX", "FFIEC", "PCI DSS"]
                assert any(fw in context_info.compliance_frameworks for fw in expected_frameworks)
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.asyncio
    async def test_healthcare_analysis(self, test_config):
        """Test analysis of healthcare project."""
        project_path = create_test_project("healthcare")
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=test_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                results = await orchestrator.execute_workflow(str(project_path))
                
                # Validate healthcare specific aspects
                assert results["status"] == "completed"
                
                context_info = results["results"]["context_information"]
                assert "Healthcare" in context_info.sector
                
                # Should include privacy in security objectives
                assert "Privacy" in context_info.security_objectives
                
                # Should have HIPAA compliance
                assert "HIPAA" in context_info.compliance_frameworks
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.asyncio
    async def test_workflow_with_missing_files(self, test_config):
        """Test workflow behavior with missing context files."""
        # Create project with only README
        project_path = create_test_project("web_application", include_threats=False, include_architecture=False)
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=test_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                results = await orchestrator.execute_workflow(str(project_path))
                
                # Should still complete but with warnings
                assert results["status"] in ["completed", "completed_with_warnings"]
                
                # Should have extracted some information from README
                context_info = results["results"]["context_information"]
                assert len(context_info.technologies) > 0
                
                # May have no attack trees if no threats file
                attack_trees = results["results"]["attack_trees"]
                # This is acceptable - no threats means no attack trees
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.asyncio
    async def test_workflow_error_handling(self, test_config):
        """Test workflow error handling and recovery."""
        project_path = create_test_project("web_application")
        
        try:
            # Configure mock to simulate errors
            with setup_mock_environment(simulate_errors=True) as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=test_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Should handle errors gracefully
                results = await orchestrator.execute_workflow(str(project_path))
                
                # May complete with errors or fail gracefully
                assert results["status"] in ["completed", "completed_with_errors", "failed"]
                
                # Should have error information
                if results["status"] != "completed":
                    assert "errors" in results
                    assert len(results["errors"]) > 0
        
        finally:
            cleanup_test_files(project_path)


class TestAgentIntegration:
    """Test integration between different agents."""
    
    @pytest.mark.asyncio
    async def test_context_to_extraction_flow(self):
        """Test data flow from context detection to information extraction."""
        with setup_mock_environment() as mock_env:
            # Create test files
            mock_env["file_system"].create_file(
                "test_project/README.md",
                "# Test Project\nPython web application using Django and PostgreSQL."
            )
            
            # Test context detection
            context_agent = mock_env["agents"]["context_detection"]
            context_files = await context_agent.process("test_project")
            
            assert len(context_files) == 1
            assert context_files[0]["type"] == "readme"
            
            # Test information extraction with context files
            extraction_agent = mock_env["agents"]["information_extraction"]
            context_info = await extraction_agent.process(context_files)
            
            assert isinstance(context_info, ContextInformation)
            assert "Python" in context_info.programming_languages
    
    @pytest.mark.asyncio
    async def test_extraction_to_generation_flow(self):
        """Test data flow from information extraction to attack tree generation."""
        with setup_mock_environment() as mock_env:
            # Create mock context information
            context_info = ContextInformation(
                technologies=["Python", "Django", "PostgreSQL"],
                programming_languages=["Python"],
                sector="E-commerce",
                security_objectives=["Confidentiality", "Integrity"],
                architecture_type="Microservices",
                compliance_frameworks=["PCI DSS"],
                extracted_from=["README.md"],
                validation_status="approved",
                confidence_score=0.85
            )
            
            # Create mock threat statements
            threat_statements = [
                ThreatStatement(
                    id="T001",
                    severity="High",
                    threat_source="External attacker",
                    prerequisites="SQL injection vulnerability",
                    threat_action="Exploit SQL injection to extract data",
                    threat_impact="Data breach and compliance violation",
                    impacted_assets=["Database", "Customer data"],
                    impacted_goals=["Confidentiality", "Compliance"],
                    raw_statement="SQL injection attack"
                )
            ]
            
            # Test attack tree generation
            generator_agent = mock_env["agents"]["attack_tree_generator"]
            attack_trees = generator_agent._generate_mock_output(threat_statements)
            
            assert len(attack_trees) == 1
            assert attack_trees[0]["threat_id"] == "T001"
            assert "mermaid_content" in attack_trees[0]
            
            # Validate Mermaid format
            assert_valid_mermaid(attack_trees[0]["mermaid_content"])
    
    @pytest.mark.asyncio
    async def test_generation_to_ttc_flow(self):
        """Test data flow from attack tree generation to TTC mapping."""
        with setup_mock_environment() as mock_env:
            # Create mock attack trees
            attack_trees = [
                {
                    "threat_id": "T001",
                    "title": "SQL Injection Attack",
                    "severity": "High",
                    "mermaid_content": "graph TD\nA[Attacker] --> B[SQL Injection]",
                    "generated_timestamp": 1234567890
                }
            ]
            
            # Test TTC mapping
            mapping_agent = mock_env["agents"]["ttc_mapping"]
            enhanced_trees = mapping_agent._generate_mock_output(attack_trees)
            
            assert len(enhanced_trees) == 1
            assert enhanced_trees[0]["enhanced"] is True
            assert "ttc_mappings" in enhanced_trees[0]
            
            # Validate TTC mappings
            ttc_mappings = enhanced_trees[0]["ttc_mappings"]
            assert len(ttc_mappings) > 0
            
            for technique_id, mapping in ttc_mappings.items():
                assert "technique" in mapping
                assert "alignment_score" in mapping
                assert 0.0 <= mapping["alignment_score"] <= 1.0


class TestConfigurationVariations:
    """Test different configuration scenarios."""
    
    @pytest.mark.asyncio
    async def test_different_severity_thresholds(self):
        """Test analysis with different severity thresholds."""
        project_path = create_test_project("web_application")
        
        try:
            # Test with high severity threshold
            high_config = ThreatForestConfig(
                processing={"severity_threshold": "high"}
            )
            
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=high_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                results_high = await orchestrator.execute_workflow(str(project_path))
                
            # Test with medium severity threshold
            medium_config = ThreatForestConfig(
                processing={"severity_threshold": "medium"}
            )
            
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=medium_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                results_medium = await orchestrator.execute_workflow(str(project_path))
            
            # Medium threshold should potentially generate more attack trees
            high_trees = len(results_high["results"]["attack_trees"])
            medium_trees = len(results_medium["results"]["attack_trees"])
            
            # Both should complete successfully
            assert results_high["status"] == "completed"
            assert results_medium["status"] == "completed"
            
            # Medium threshold should include medium severity threats too
            assert medium_trees >= high_trees
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.asyncio
    async def test_ttc_enhancement_disabled(self):
        """Test analysis with TTC enhancement disabled."""
        project_path = create_test_project("web_application")
        
        try:
            config = ThreatForestConfig(
                ttc={"enable_enhancement": False}
            )
            
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                results = await orchestrator.execute_workflow(str(project_path))
                
                assert results["status"] == "completed"
                
                # Attack trees should not have TTC mappings when disabled
                attack_trees = results["results"]["attack_trees"]
                for tree in attack_trees:
                    # Should not have enhanced flag or should be False
                    assert tree.get("enhanced", False) is False
        
        finally:
            cleanup_test_files(project_path)


class TestConcurrencyAndPerformance:
    """Test concurrent execution and performance characteristics."""
    
    @pytest.mark.asyncio
    async def test_concurrent_agent_execution(self):
        """Test that agents can execute concurrently without conflicts."""
        project_path = create_test_project("web_application")
        
        try:
            config = ThreatForestConfig(
                processing={"max_concurrent_agents": 4}
            )
            
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                mock_env["file_system"].create_file(
                    f"{project_path}/threats.md",
                    (project_path / "threats.md").read_text()
                )
                
                # Run multiple concurrent workflows
                orchestrators = [
                    OrchestratorAgent(
                        config=config,
                        bedrock_client=mock_env["bedrock_client"],
                        agents=mock_env["agents"]
                    )
                    for _ in range(3)
                ]
                
                # Execute concurrently
                tasks = [
                    orchestrator.execute_workflow(str(project_path))
                    for orchestrator in orchestrators
                ]
                
                results_list = await asyncio.gather(*tasks, return_exceptions=True)
                
                # All should complete successfully
                for results in results_list:
                    assert not isinstance(results, Exception)
                    assert results["status"] == "completed"
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.asyncio
    async def test_performance_benchmarks(self):
        """Test performance benchmarks for different project sizes."""
        # Test small project
        small_project = create_test_project("web_application")
        
        try:
            config = ThreatForestConfig()
            
            with setup_mock_environment(response_delay=0.01) as mock_env:
                mock_env["file_system"].create_file(
                    f"{small_project}/README.md",
                    (small_project / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Measure performance
                metrics = measure_performance(
                    orchestrator.execute_workflow,
                    str(small_project)
                )
                
                # Validate performance is within reasonable limits
                assert_performance_within_limits(
                    metrics,
                    max_execution_time=10.0,  # 10 seconds for small project
                    max_memory_mb=100.0       # 100MB memory limit
                )
                
                assert metrics["success"] is True
        
        finally:
            cleanup_test_files(small_project)