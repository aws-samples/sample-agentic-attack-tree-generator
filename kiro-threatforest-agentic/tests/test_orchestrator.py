"""
Tests for the Orchestrator Agent.

This module contains unit and integration tests for the orchestrator
that coordinates the ThreatForest workflow.
"""

import pytest
import pytest_asyncio
import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from threatforest.agents.orchestrator import OrchestratorAgent
from threatforest.models import ContextInformation, ThreatStatement, AttackTree, AttackStep, TTCMapping
from threatforest.utils.bedrock_client import BedrockClient
from threatforest.utils.file_manager import FileManager


@pytest.fixture
def mock_bedrock_client():
    """Create a mock Bedrock client."""
    client = Mock(spec=BedrockClient)
    client.invoke_model = AsyncMock()
    return client


@pytest.fixture
def mock_file_manager():
    """Create a mock file manager."""
    manager = Mock(spec=FileManager)
    manager.read_file = AsyncMock()
    manager.save_attack_tree = AsyncMock()
    manager.save_extracted_information = AsyncMock()
    manager.save_summary_report = AsyncMock()
    return manager


@pytest.fixture
def sample_config():
    """Create sample configuration."""
    return {
        'ttc': {
            'aaf_bundle_path': './test-aaf-bundle.json',
            'alignment_threshold': 0.8
        },
        'processing': {
            'severity_threshold': 'high',
            'max_concurrent_agents': 4
        }
    }


@pytest.fixture
def orchestrator(mock_bedrock_client, mock_file_manager, sample_config):
    """Create orchestrator instance with mocked dependencies."""
    return OrchestratorAgent(
        bedrock_client=mock_bedrock_client,
        file_manager=mock_file_manager,
        config=sample_config
    )


@pytest.fixture
def sample_context_files():
    """Create sample context files."""
    return [
        Path("README.md"),
        Path("architecture.png"),
        Path("threats.json")
    ]


@pytest.fixture
def sample_context_info():
    """Create sample context information."""
    return ContextInformation(
        technologies=["Python", "AWS", "Docker"],
        programming_languages=["Python", "JavaScript"],
        sector="Technology",
        security_objectives=["Confidentiality", "Integrity", "Availability"],
        architecture_type="Microservices",
        compliance_frameworks=["SOC2"],
        extracted_from=["README.md"],
        validation_status="approved",
        timestamp=datetime.now()
    )


@pytest.fixture
def sample_threat_statements():
    """Create sample threat statements."""
    return [
        ThreatStatement(
            id="T001",
            severity="high",
            threat_source="External Attacker",
            prerequisites="Network access",
            threat_action="SQL injection attack",
            threat_impact="Data breach",
            impacted_assets=["Database"],
            impacted_goals=["Confidentiality"],
            raw_statement="High severity SQL injection threat"
        ),
        ThreatStatement(
            id="T002",
            severity="medium",
            threat_source="Insider",
            prerequisites="System access",
            threat_action="Data exfiltration",
            threat_impact="Information disclosure",
            impacted_assets=["Files"],
            impacted_goals=["Confidentiality"],
            raw_statement="Medium severity insider threat"
        )
    ]


@pytest.fixture
def sample_attack_tree():
    """Create sample attack tree."""
    return AttackTree(
        threat_id="T001",
        title="SQL Injection Attack Tree",
        mermaid_content="graph TD\n  A[Start] --> B[SQL Injection]",
        attack_steps=[
            AttackStep(
                id="step1",
                description="Identify injection point",
                step_type="attack",
                dependencies=[],
                ttc_reference=None
            )
        ],
        ttc_mappings={},
        generated_timestamp=datetime.now()
    )


class TestOrchestratorAgent:
    """Test cases for OrchestratorAgent."""
    
    def test_initialization(self, orchestrator):
        """Test orchestrator initialization."""
        assert orchestrator.bedrock_client is not None
        assert orchestrator.file_manager is not None
        assert orchestrator.config is not None
        assert orchestrator.context_agent is not None
        assert orchestrator.extraction_agent is not None
        assert orchestrator.generator_agent is not None
        assert orchestrator.mapping_agent is not None
        assert orchestrator.workflow_state['started_at'] is None
    
    @pytest.mark.asyncio
    async def test_successful_workflow_execution(
        self, 
        orchestrator, 
        sample_context_files,
        sample_context_info,
        sample_threat_statements,
        sample_attack_tree
    ):
        """Test successful complete workflow execution."""
        # Mock all agent methods
        with patch.object(orchestrator.context_agent, 'scan_directory', 
                         return_value=sample_context_files) as mock_scan, \
             patch.object(orchestrator.extraction_agent, 'extract_information',
                         return_value=sample_context_info) as mock_extract, \
             patch.object(orchestrator.generator_agent, 'generate_attack_tree',
                         return_value=sample_attack_tree) as mock_generate, \
             patch.object(orchestrator.mapping_agent, 'enhance_attack_tree',
                         return_value=sample_attack_tree) as mock_enhance, \
             patch.object(orchestrator, '_parse_threat_statements',
                         return_value=sample_threat_statements) as mock_parse:
            
            # Configure file manager mocks
            orchestrator.file_manager.save_extracted_information.return_value = "info.md"
            orchestrator.file_manager.save_attack_tree.return_value = "attack_tree.mmd"
            orchestrator.file_manager.save_summary_report.return_value = "summary.md"
            
            # Execute workflow
            result = await orchestrator.execute_workflow("/test/directory")
            
            # Verify workflow completion
            assert result['status'] == 'completed'
            assert result['started_at'] is not None
            assert result['completed_at'] is not None
            assert result['duration_seconds'] is not None
            assert len(result['errors']) == 0
            
            # Verify all phases were executed
            expected_phases = [
                'context_files', 'context_information', 'attack_trees', 
                'info_file', 'summary_file'
            ]
            for phase in expected_phases:
                assert phase in result['results']
            
            # Verify agent method calls
            mock_scan.assert_called_once_with("/test/directory")
            mock_extract.assert_called_once_with(sample_context_files)
            mock_generate.assert_called_once()
            mock_enhance.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_context_detection_failure(self, orchestrator):
        """Test workflow handling when context detection fails."""
        with patch.object(orchestrator.context_agent, 'scan_directory',
                         return_value=[]) as mock_scan:
            
            with pytest.raises(ValueError, match="No context files found"):
                await orchestrator.execute_workflow("/empty/directory")
            
            mock_scan.assert_called_once_with("/empty/directory")
    
    @pytest.mark.asyncio
    async def test_non_critical_phase_failure_continues_workflow(
        self, 
        orchestrator,
        sample_context_files,
        sample_context_info
    ):
        """Test that non-critical phase failures don't stop the workflow."""
        with patch.object(orchestrator.context_agent, 'scan_directory',
                         return_value=sample_context_files), \
             patch.object(orchestrator.extraction_agent, 'extract_information',
                         return_value=sample_context_info), \
             patch.object(orchestrator, '_parse_threat_statements',
                         return_value=[]), \
             patch.object(orchestrator.mapping_agent, 'enhance_attack_tree',
                         side_effect=Exception("TTC mapping failed")):
            
            orchestrator.file_manager.save_extracted_information.return_value = "info.md"
            orchestrator.file_manager.save_summary_report.return_value = "summary.md"
            
            result = await orchestrator.execute_workflow("/test/directory")
            
            # Workflow should complete despite TTC mapping failure
            assert result['status'] == 'completed'
            assert len(result['errors']) == 0  # TTC mapping failure is handled gracefully
    
    @pytest.mark.asyncio
    async def test_critical_phase_failure_stops_workflow(self, orchestrator):
        """Test that critical phase failures stop the workflow."""
        with patch.object(orchestrator.context_agent, 'scan_directory',
                         side_effect=Exception("Critical failure")), \
             patch.object(orchestrator, '_save_partial_results') as mock_save:
            
            with pytest.raises(Exception, match="Critical failure"):
                await orchestrator.execute_workflow("/test/directory")
            
            mock_save.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_high_severity_threat_filtering(
        self, 
        orchestrator,
        sample_context_files,
        sample_context_info,
        sample_threat_statements
    ):
        """Test that only high-severity threats generate attack trees."""
        with patch.object(orchestrator.context_agent, 'scan_directory',
                         return_value=sample_context_files), \
             patch.object(orchestrator.extraction_agent, 'extract_information',
                         return_value=sample_context_info), \
             patch.object(orchestrator, '_parse_threat_statements',
                         return_value=sample_threat_statements), \
             patch.object(orchestrator.generator_agent, 'generate_attack_tree') as mock_generate, \
             patch.object(orchestrator.mapping_agent, 'enhance_attack_tree') as mock_enhance:
            
            orchestrator.file_manager.save_extracted_information.return_value = "info.md"
            orchestrator.file_manager.save_attack_tree.return_value = "tree.mmd"
            orchestrator.file_manager.save_summary_report.return_value = "summary.md"
            
            await orchestrator.execute_workflow("/test/directory")
            
            # Should only generate attack tree for high-severity threat (T001)
            assert mock_generate.call_count == 1
            call_args = mock_generate.call_args[0]
            assert call_args[0].id == "T001"  # High severity threat
            assert call_args[0].severity == "high"
    
    @pytest.mark.asyncio
    async def test_parse_threat_statements_json(self, orchestrator, mock_file_manager):
        """Test parsing threat statements from JSON file."""
        json_content = '''
        {
            "threats": [
                {
                    "id": "T001",
                    "severity": "high",
                    "threat_source": "External",
                    "prerequisites": "Network access",
                    "threat_action": "Attack",
                    "threat_impact": "Data loss",
                    "impacted_assets": ["Database"],
                    "impacted_goals": ["Confidentiality"],
                    "raw_statement": "Test threat"
                }
            ]
        }
        '''
        
        mock_file_manager.read_context_file.return_value = json_content
        
        threats = await orchestrator._parse_threat_statements(Path("threats.json"))
        
        assert len(threats) == 1
        assert threats[0].id == "T001"
        assert threats[0].severity == "high"
        assert threats[0].threat_source == "External"
    
    @pytest.mark.asyncio
    async def test_generate_analysis_summary(self, orchestrator, sample_attack_tree, sample_context_info):
        """Test analysis summary generation."""
        orchestrator.workflow_state['started_at'] = datetime.now()
        orchestrator.workflow_state['completed_at'] = datetime.now()
        
        summary = await orchestrator._generate_analysis_summary(
            [sample_attack_tree], 
            sample_context_info
        )
        
        assert 'analysis_metadata' in summary
        assert 'context_summary' in summary
        assert 'threat_analysis' in summary
        assert 'files_generated' in summary
        
        assert summary['analysis_metadata']['total_attack_trees'] == 1
        assert summary['context_summary']['technologies'] == ["Python", "AWS", "Docker"]
        assert len(summary['threat_analysis']) == 1
        assert summary['threat_analysis'][0]['threat_id'] == "T001"
    
    def test_is_critical_phase(self, orchestrator):
        """Test critical phase identification."""
        assert orchestrator._is_critical_phase('context_detection') is True
        assert orchestrator._is_critical_phase('information_extraction') is True
        assert orchestrator._is_critical_phase('attack_tree_generation') is False
        assert orchestrator._is_critical_phase('ttc_mapping') is False
        assert orchestrator._is_critical_phase('summary_generation') is False
    
    @pytest.mark.asyncio
    async def test_save_partial_results(self, orchestrator, sample_attack_tree, sample_context_info):
        """Test saving partial results on failure."""
        orchestrator.workflow_state['results'] = {
            'attack_trees': [sample_attack_tree],
            'context_information': sample_context_info
        }
        
        await orchestrator._save_partial_results()
        
        orchestrator.file_manager.write_attack_tree.assert_called_once_with(sample_attack_tree)
        orchestrator.file_manager.write_context_information.assert_called_once_with(sample_context_info)
    
    def test_calculate_workflow_duration(self, orchestrator):
        """Test workflow duration calculation."""
        start_time = datetime.now()
        end_time = datetime.now()
        
        orchestrator.workflow_state['started_at'] = start_time
        orchestrator.workflow_state['completed_at'] = end_time
        
        duration = orchestrator._calculate_workflow_duration()
        assert duration is not None
        assert duration >= 0
    
    def test_generate_workflow_summary(self, orchestrator):
        """Test workflow summary generation."""
        orchestrator.workflow_state.update({
            'started_at': datetime.now(),
            'completed_at': datetime.now(),
            'errors': [],
            'results': {'context_files': [], 'attack_trees': []}
        })
        
        summary = orchestrator._generate_workflow_summary()
        
        assert summary['status'] == 'completed'
        assert 'started_at' in summary
        assert 'completed_at' in summary
        assert 'duration_seconds' in summary
        assert 'phases_completed' in summary
        assert 'errors' in summary
        assert 'results' in summary


class TestOrchestratorIntegration:
    """Integration tests for orchestrator workflow."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_workflow_simulation(self, mock_bedrock_client, mock_file_manager, sample_config):
        """Test end-to-end workflow with realistic data flow."""
        orchestrator = OrchestratorAgent(
            bedrock_client=mock_bedrock_client,
            file_manager=mock_file_manager,
            config=sample_config
        )
        
        # Setup realistic mock responses
        context_files = [Path("README.md"), Path("threats.json")]
        context_info = ContextInformation(
            technologies=["Python", "FastAPI"],
            programming_languages=["Python"],
            sector="FinTech",
            security_objectives=["Confidentiality", "Integrity"],
            architecture_type="API",
            compliance_frameworks=["PCI-DSS"],
            extracted_from=["README.md"],
            validation_status="approved",
            timestamp=datetime.now()
        )
        
        threat_statement = ThreatStatement(
            id="T001",
            severity="high",
            threat_source="External Attacker",
            prerequisites="API access",
            threat_action="Authentication bypass",
            threat_impact="Unauthorized access",
            impacted_assets=["User accounts"],
            impacted_goals=["Confidentiality", "Integrity"],
            raw_statement="High severity authentication bypass"
        )
        
        attack_tree = AttackTree(
            threat_id="T001",
            title="Authentication Bypass Attack Tree",
            mermaid_content="graph TD\n  A[Start] --> B[Bypass Auth]",
            attack_steps=[
                AttackStep(
                    id="step1",
                    description="Identify auth endpoint",
                    step_type="attack",
                    dependencies=[],
                    ttc_reference="T1078"
                )
            ],
            ttc_mappings={
                "step1": TTCMapping(
                    attack_step_id="step1",
                    ttc_technique_id="T1078",
                    ttc_technique_name="Valid Accounts",
                    alignment_score=0.9,
                    stix_data={},
                    applied=True
                )
            },
            generated_timestamp=datetime.now()
        )
        
        # Mock all agent interactions
        with patch.object(orchestrator.context_agent, 'scan_directory',
                         return_value=context_files), \
             patch.object(orchestrator.extraction_agent, 'extract_information',
                         return_value=context_info), \
             patch.object(orchestrator, '_parse_threat_statements',
                         return_value=[threat_statement]), \
             patch.object(orchestrator.generator_agent, 'generate_attack_tree',
                         return_value=attack_tree), \
             patch.object(orchestrator.mapping_agent, 'enhance_attack_tree',
                         return_value=attack_tree):
            
            # Configure file manager returns
            mock_file_manager.save_extracted_information.return_value = "extracted_info.md"
            mock_file_manager.save_attack_tree.return_value = "T001_attack_tree.mmd"
            mock_file_manager.save_summary_report.return_value = "analysis_summary.md"
            
            # Execute workflow
            result = await orchestrator.execute_workflow("/test/fintech/app")
            
            # Verify complete workflow execution
            assert result['status'] == 'completed'
            assert len(result['errors']) == 0
            
            # Verify all file operations were called
            mock_file_manager.write_context_information.assert_called_once()
            mock_file_manager.write_attack_tree.assert_called()
            mock_file_manager.generate_summary_report.assert_called_once()
            
            # Verify results structure
            assert 'context_files' in result['results']
            assert 'context_information' in result['results']
            assert 'attack_trees' in result['results']
            assert 'summary_file' in result['results']
            
            # Verify attack tree was processed
            assert len(result['results']['attack_trees']) == 1
            assert result['results']['attack_trees'][0].threat_id == "T001"