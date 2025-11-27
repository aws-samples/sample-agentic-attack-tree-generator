"""
Integration tests for Strands Agent-based architecture
"""
import pytest
from pathlib import Path
import tempfile
import json


class TestAgentIntegration:
    """Test the new agent-based architecture"""
    
    def test_repository_analysis_agent_init(self):
        """Test RepositoryAnalysisAgent initialization"""
        from threatforest.modules.agents import RepositoryAnalysisAgent
        
        agent = RepositoryAnalysisAgent()
        assert agent.name == "repository_analysis"
        assert agent.logger is not None
    
    def test_parser_agent_init(self):
        """Test ParserAgent initialization"""
        from threatforest.modules.agents import ParserAgent
        
        agent = ParserAgent()
        assert agent.name == "parser"
        assert agent.logger is not None
        # Parser chain removed - now fully Strands-only
    
    def test_threat_generation_agent_init(self):
        """Test ThreatGenerationAgent initialization"""
        from threatforest.modules.agents import ThreatGenerationAgent
        
        agent = ThreatGenerationAgent()
        assert agent.name == "threat_generation"
        assert agent.logger is not None
        assert agent.formatter is not None
    
    def test_parser_agent_strands_only(self):
        """Test ParserAgent uses Strands tools only (no parser chain)"""
        from threatforest.modules.agents import ParserAgent
        
        agent = ParserAgent()
        
        # Verify parser chain is not present
        assert not hasattr(agent, 'parser_chain') or agent.parser_chain is None
        
        # Verify it's Strands-only
        assert agent.description == "Parse existing threat statement files"
        
        # Note: Actual parsing requires LLM, so we just test initialization
        print("  ✓ ParserAgent is now Strands-only (no parser chain)")
    
    def test_threat_generation_fallback(self):
        """Test ThreatGenerationAgent fallback threats"""
        from threatforest.modules.agents import ThreatGenerationAgent
        
        agent = ThreatGenerationAgent()
        
        context = {
            "application_name": "Test App",
            "technologies": ["Python", "FastAPI"],
            "sector": "Healthcare"
        }
        
        fallback_threats = agent._get_fallback_threats(context)
        
        assert len(fallback_threats) == 4
        assert all(t['source'] == 'Fallback' for t in fallback_threats)
        assert "Test App" in fallback_threats[0]['statement']
    
    def test_information_extraction_tool_with_agents(self):
        """Test InformationExtractionTool uses new agents"""
        from threatforest.modules.tools.information_extraction_tool import InformationExtractionTool
        
        tool = InformationExtractionTool()
        
        # Verify agents are initialized
        assert hasattr(tool, 'repository_agent')
        assert hasattr(tool, 'parser_agent')
        assert hasattr(tool, 'threat_generator')
        
        assert tool.repository_agent.name == "repository_analysis"
        assert tool.parser_agent.name == "parser"
        assert tool.threat_generator.name == "threat_generation"
    
    def test_cli_wizard_threat_preference(self):
        """Test CLI wizard has new threat preference method"""
        from threatforest.modules.cli import CLIWizard
        
        wizard = CLIWizard()
        
        # Verify new method exists
        assert hasattr(wizard, 'ask_threat_statement_preference')
        
        # Verify old method still exists (deprecated but available)
        assert hasattr(wizard, 'get_threat_model_path')


class TestPromptFiles:
    """Test that new prompt files exist and are properly formatted"""
    
    def test_repository_analysis_prompt_exists(self):
        """Test repository-analysis.md prompt exists"""
        from threatforest.config import ROOT_DIR
        
        prompt_path = ROOT_DIR / "src" / "threatforest" / "prompts" / "repository-analysis.md"
        assert prompt_path.exists(), "repository-analysis.md prompt not found"
        
        content = prompt_path.read_text()
        assert "Repository Analysis System Prompt" in content
        assert "file_read" in content
        assert "editor" in content
        assert "image_reader" in content
    
    def test_threat_parsing_prompt_exists(self):
        """Test threat-parsing.md prompt exists"""
        from threatforest.config import ROOT_DIR
        
        prompt_path = ROOT_DIR / "src" / "threatforest" / "prompts" / "threat-parsing.md"
        assert prompt_path.exists(), "threat-parsing.md prompt not found"
        
        content = prompt_path.read_text()
        assert "Threat Statement Parsing System Prompt" in content
        assert "file_read" in content


class TestStrandsToolsIntegration:
    """Test Strands community tools integration"""
    
    def test_strands_tools_importable(self):
        """Test that strands_tools can be imported"""
        try:
            import strands_tools
            assert True
        except ImportError:
            pytest.fail("strands_tools not importable - check dependencies")
    
    def test_file_read_tool_importable(self):
        """Test that file_read tool can be imported"""
        try:
            from strands_tools import file_read
            assert file_read is not None
        except ImportError:
            pytest.fail("file_read tool not importable")
    
    def test_editor_tool_importable(self):
        """Test that editor tool can be imported"""
        try:
            from strands_tools import editor
            assert editor is not None
        except ImportError:
            pytest.fail("editor tool not importable")
    
    def test_image_reader_tool_importable(self):
        """Test that image_reader tool can be imported"""
        try:
            from strands_tools import image_reader
            assert image_reader is not None
        except ImportError:
            pytest.fail("image_reader tool not importable")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
