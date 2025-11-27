"""Test that DocsGenerator moves files instead of copying them

**Validates: Requirements 6.2 - No duplication of attack tree files**
"""
import pytest
from pathlib import Path
import json
import tempfile

from threatforest.modules.visualization import DocsGenerator
from threatforest.modules.workflow.summary_generator.tool import MKDOCS_AVAILABLE


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_files_are_moved_not_copied():
    """Test that attack tree files are moved into docs structure, not copied
    
    **Validates: Requirements 6.2**
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directory structure
        output_dir = Path(tmpdir) / "attack_trees"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test files
        project_info = {
            "application_name": "Move Test",
            "description": "Testing file moving"
        }
        
        threat_statements = [
            {
                "id": "T001",
                "category": "Test Category",
                "severity": "High",
                "statement": "Test threat"
            }
        ]
        
        (output_dir / "threatforest_data.json").write_text(json.dumps({
            "project_info": project_info,
            "threat_statements": threat_statements
        }))
        
        (output_dir / "threatforest_analysis_report.md").write_text("# Test Report")
        (output_dir / "attack_tree_T001_test.md").write_text("# Attack Tree T001")
        (output_dir / ".threatforest_state.json").write_text(json.dumps({"state": "test"}))
        
        # Verify files exist in original location
        assert (output_dir / "attack_tree_T001_test.md").exists()
        assert (output_dir / "threatforest_data.json").exists()
        assert (output_dir / "threatforest_analysis_report.md").exists()
        
        # Generate docs
        generator = DocsGenerator(output_dir)
        docs_dir = generator.generate()
        
        # Verify files were MOVED (not in original location anymore)
        assert not (output_dir / "attack_tree_T001_test.md").exists(), "Attack tree should be moved, not copied"
        assert not (output_dir / "threatforest_data.json").exists(), "Data file should be moved"
        assert not (output_dir / "threatforest_analysis_report.md").exists(), "Report should be moved"
        
        # Verify files exist in new location
        assert (docs_dir / "attack_trees" / "attack_tree_T001_test.md").exists(), "Attack tree should be in docs/attack_trees/"
        assert (docs_dir / "data" / "threatforest_data.json").exists(), "Data should be in docs/data/"
        assert (docs_dir / "threatforest_analysis_report.md").exists(), "Report should be in docs/"
        
        # Verify no duplication - count total attack tree files
        all_attack_trees = list(output_dir.rglob("attack_tree_*.md"))
        assert len(all_attack_trees) == 1, f"Should have exactly 1 attack tree file (no duplication), found {len(all_attack_trees)}"
        
        print("✓ Files are moved, not copied - no duplication")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_original_directory_structure_after_generation():
    """Test that original directory only contains mkdocs.yml and docs/ after generation
    
    **Validates: Requirements 6.2**
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directory structure
        output_dir = Path(tmpdir) / "attack_trees"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test files
        (output_dir / "threatforest_data.json").write_text(json.dumps({
            "project_info": {"application_name": "Test"},
            "threat_statements": []
        }))
        (output_dir / "threatforest_analysis_report.md").write_text("# Test")
        (output_dir / "attack_tree_T001.md").write_text("# Tree")
        
        # Generate docs
        generator = DocsGenerator(output_dir)
        generator.generate()
        
        # Check what remains in original directory
        remaining_files = [f.name for f in output_dir.iterdir() if f.is_file()]
        remaining_dirs = [d.name for d in output_dir.iterdir() if d.is_dir()]
        
        # Should only have mkdocs.yml file
        assert "mkdocs.yml" in remaining_files, "mkdocs.yml should exist"
        
        # Should only have docs directory
        assert "docs" in remaining_dirs, "docs directory should exist"
        assert len(remaining_dirs) == 1, f"Should only have docs directory, found: {remaining_dirs}"
        
        # Original files should not be in root anymore
        assert "attack_tree_T001.md" not in remaining_files
        assert "threatforest_data.json" not in remaining_files
        assert "threatforest_analysis_report.md" not in remaining_files
        
        print("✓ Original directory cleaned up correctly")
