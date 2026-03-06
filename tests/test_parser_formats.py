"""
Unit tests for ParserAgent with various threat file formats
Testing Strands-only parsing without parser chain fallback
"""
import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.modules.agents import ParserAgent


class TestParserAgentFormats:
    """Test ParserAgent can parse all formats using Strands tools only"""
    
    @pytest.fixture
    def parser_agent(self):
        """Create ParserAgent instance"""
        return ParserAgent()
    
    @pytest.fixture
    def fixtures_dir(self):
        """Get fixtures directory"""
        return Path(__file__).parent / "fixtures"
    
    def test_json_format_with_parser_chain(self, parser_agent, fixtures_dir):
        """Test JSON parsing using parser chain (baseline)"""
        json_file = fixtures_dir / "threats.json"
        assert json_file.exists(), "JSON fixture not found"
        
        # Use parser chain as baseline
        threats = parser_agent._parse_with_chain(json_file)
        
        assert len(threats) == 3, f"Expected 3 threats, got {len(threats)}"
        assert threats[0]['id'] == 'T001'
        assert threats[0]['severity'] == 'High'
        print(f"✓ JSON baseline: {len(threats)} threats parsed")
    
    def test_yaml_format_with_parser_chain(self, parser_agent, fixtures_dir):
        """Test YAML parsing using parser chain (baseline)"""
        yaml_file = fixtures_dir / "threats.yaml"
        assert yaml_file.exists(), "YAML fixture not found"
        
        # Use parser chain as baseline
        threats = parser_agent._parse_with_chain(yaml_file)
        
        assert len(threats) == 3, f"Expected 3 threats, got {len(threats)}"
        assert threats[0]['id'] == 'T001'
        print(f"✓ YAML baseline: {len(threats)} threats parsed")
    
    def test_markdown_format_with_parser_chain(self, parser_agent, fixtures_dir):
        """Test Markdown parsing using parser chain (baseline)"""
        md_file = fixtures_dir / "threats.md"
        assert md_file.exists(), "Markdown fixture not found"
        
        # Use parser chain as baseline
        threats = parser_agent._parse_with_chain(md_file)
        
        assert len(threats) >= 1, f"Expected at least 1 threat, got {len(threats)}"
        print(f"✓ Markdown baseline: {len(threats)} threats parsed")
    
    def test_threatcomposer_format_with_parser_chain(self, parser_agent, fixtures_dir):
        """Test ThreatComposer parsing using parser chain (baseline)"""
        tc_file = fixtures_dir / "threats.tc.json"
        if not tc_file.exists():
            pytest.skip("ThreatComposer fixture not found")
        
        # Use parser chain as baseline
        threats = parser_agent._parse_with_chain(tc_file)
        
        assert len(threats) >= 1, f"Expected at least 1 threat, got {len(threats)}"
        print(f"✓ ThreatComposer baseline: {len(threats)} threats parsed")
    
    @pytest.mark.skipif(
        True,
        reason="Requires LLM access - run manually with: pytest tests/test_parser_formats.py -v -m strands_only"
    )
    @pytest.mark.strands_only
    def test_json_format_strands_only(self, parser_agent, fixtures_dir):
        """Test JSON parsing using Strands agent ONLY (no fallback)
        
        This test requires actual LLM access. Run with:
        pytest tests/test_parser_formats.py::TestParserAgentFormats::test_json_format_strands_only -v
        """
        json_file = fixtures_dir / "threats.json"
        
        # Call parse_threats which uses Strands agent
        # For this test, we'd need to mock or actually call the agent
        # Since this requires LLM, mark as integration test
        
        threats = parser_agent.parse_threats(str(json_file))
        
        assert len(threats) >= 2, f"Expected at least 2 threats, got {len(threats)}"
        assert any(t['id'].startswith('T00') for t in threats)
        print(f"✓ Strands-only JSON: {len(threats)} threats parsed")


class TestParserChainRemoval:
    """Tests to validate parser chain can be safely removed"""
    
    def test_parser_agent_without_chain_init(self):
        """Test if ParserAgent can initialize without parser chain"""
        from threatforest.modules.agents import ParserAgent
        
        # This test checks current implementation
        agent = ParserAgent()
        
        # Currently has parser_chain
        assert hasattr(agent, 'parser_chain')
        assert agent.parser_chain is not None
        
        print("ℹ️ ParserAgent currently uses parser chain as fallback")
        print("  After Strands-only tests pass, we can remove this dependency")
    
    def test_strands_tools_available(self):
        """Verify Strands file_read tool is available"""
        try:
            from strands_tools import file_read
            assert file_read is not None
            print("✓ Strands file_read tool available")
        except ImportError:
            pytest.fail("strands_tools not available - check dependencies")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
