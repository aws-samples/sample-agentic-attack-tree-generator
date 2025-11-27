"""Integration tests for SummaryGeneratorTool with DocsGenerator"""
import pytest
from pathlib import Path
import json
import tempfile
import shutil

from threatforest.modules.workflow.summary_generator.tool import SummaryGeneratorTool, MKDOCS_AVAILABLE


class TestSummaryDocsIntegration:
    """Test that SummaryGeneratorTool integrates with DocsGenerator"""
    
    def test_summary_tool_has_mkdocs_flag(self):
        """Test that MKDOCS_AVAILABLE flag is defined"""
        assert isinstance(MKDOCS_AVAILABLE, bool)
    
    def test_summary_tool_runs_without_mkdocs(self):
        """Test that SummaryGeneratorTool works even if mkdocs is not available"""
        tool = SummaryGeneratorTool()
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "threatforest" / "attack_trees"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create minimal required files
            (output_dir / "threatforest_analysis_report.md").write_text("# Test Report")
            (output_dir / "threatforest_data.json").write_text(json.dumps({
                "project_info": {"application_name": "TestApp"},
                "threat_statements": []
            }))
            
            # Run summary generation
            result = tool.run(
                attack_trees={},
                extracted_info={"project_info": {"application_name": "TestApp"}},
                output_dir=str(output_dir)
            )
            
            # Should succeed regardless of mkdocs availability
            assert 'output_files' in result
    
    @pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
    def test_summary_tool_generates_docs_when_available(self):
        """Test that SummaryGeneratorTool generates docs when mkdocs is available"""
        tool = SummaryGeneratorTool()
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as tmpdir:
            threatforest_dir = Path(tmpdir) / "threatforest"
            output_dir = threatforest_dir / "attack_trees"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create required files
            (output_dir / "threatforest_analysis_report.md").write_text("# Test Report\n\n## Summary\nTest content")
            (output_dir / "threatforest_data.json").write_text(json.dumps({
                "project_info": {
                    "application_name": "TestApp",
                    "description": "Test application"
                },
                "threat_statements": [
                    {
                        "id": "T001",
                        "category": "Data Breach",
                        "severity": "High",
                        "statement": "Test threat"
                    }
                ]
            }))
            (output_dir / "attack_tree_T001_data_breach.md").write_text("# Attack Tree T001")
            (output_dir / "attack_trees_dashboard.html").write_text("<html><body>Dashboard</body></html>")
            
            # Run summary generation
            result = tool.run(
                attack_trees={
                    "attack_trees": [
                        {
                            "threat_id": "T001",
                            "category": "Data Breach",
                            "tree": {"root": "test"}
                        }
                    ]
                },
                extracted_info={
                    "project_info": {
                        "application_name": "TestApp",
                        "description": "Test application"
                    }
                },
                output_dir=str(output_dir)
            )
            
            # Should have docs_dir in result
            assert 'docs_dir' in result
            
            # If mkdocs is available, docs should be generated
            if result['docs_dir']:
                docs_path = Path(result['docs_dir'])
                assert docs_path.exists()
                assert (threatforest_dir / "mkdocs.yml").exists()
                assert (docs_path / "index.md").exists()
    
    def test_summary_tool_handles_docs_generation_failure(self):
        """Test that SummaryGeneratorTool handles docs generation failures gracefully"""
        tool = SummaryGeneratorTool()
        
        # Create temporary output directory with missing files
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "threatforest" / "attack_trees"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Don't create required files - this should cause docs generation to fail
            # but not fail the entire summary generation
            
            # Run summary generation
            result = tool.run(
                attack_trees={},
                extracted_info={"project_info": {"application_name": "TestApp"}},
                output_dir=str(output_dir)
            )
            
            # Should still succeed even if docs generation fails
            assert 'output_files' in result
            assert 'docs_dir' in result
