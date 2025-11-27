"""End-to-end test for docs generation integration"""
import pytest
from pathlib import Path
import json
import tempfile
import shutil
import yaml

from threatforest.modules.workflow.summary_generator.tool import SummaryGeneratorTool, MKDOCS_AVAILABLE
from threatforest.modules.visualization import DocsGenerator


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_end_to_end_docs_generation():
    """Test complete workflow from summary generation to docs generation"""
    tool = SummaryGeneratorTool()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directory structure
        threatforest_dir = Path(tmpdir) / "threatforest"
        output_dir = threatforest_dir / "attack_trees"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sample data
        project_info = {
            "application_name": "E-Commerce Platform",
            "description": "Online shopping platform",
            "components": ["Web Frontend", "API Gateway", "Database"]
        }
        
        threat_statements = [
            {
                "id": "T001",
                "category": "Data Breach",
                "severity": "High",
                "statement": "Attacker gains unauthorized access to customer data"
            },
            {
                "id": "T002",
                "category": "Denial of Service",
                "severity": "High",
                "statement": "Attacker overwhelms system with requests"
            }
        ]
        
        attack_trees_data = {
            "attack_trees": [
                {
                    "threat_id": "T001",
                    "category": "Data Breach",
                    "tree": {
                        "root": "Gain unauthorized access",
                        "children": [
                            {"node": "SQL Injection"},
                            {"node": "Credential Theft"}
                        ]
                    }
                },
                {
                    "threat_id": "T002",
                    "category": "Denial of Service",
                    "tree": {
                        "root": "Overwhelm system",
                        "children": [
                            {"node": "DDoS Attack"},
                            {"node": "Resource Exhaustion"}
                        ]
                    }
                }
            ]
        }
        
        extracted_info = {
            "project_info": project_info,
            "threat_statements": threat_statements
        }
        
        # Create required files
        (output_dir / "threatforest_analysis_report.md").write_text(
            "# Threat Analysis Report\n\n## Executive Summary\n\nTest report content"
        )
        
        (output_dir / "threatforest_data.json").write_text(
            json.dumps({
                "project_info": project_info,
                "threat_statements": threat_statements
            }, indent=2)
        )
        
        (output_dir / "attack_tree_T001_data_breach.md").write_text(
            "# Attack Tree: T001 - Data Breach\n\n## Attack Path\n\nTest content"
        )
        
        (output_dir / "attack_tree_T002_denial_of_service.md").write_text(
            "# Attack Tree: T002 - Denial of Service\n\n## Attack Path\n\nTest content"
        )
        
        (output_dir / "attack_trees_dashboard.html").write_text(
            "<html><body><h1>Attack Trees Dashboard</h1></body></html>"
        )
        
        # Run summary generation (which should trigger docs generation)
        result = tool.run(
            attack_trees=attack_trees_data,
            extracted_info=extracted_info,
            output_dir=str(output_dir)
        )
        
        # Verify summary generation succeeded
        assert 'output_files' in result
        assert len(result['output_files']) > 0
        
        # Verify docs generation was triggered
        assert 'docs_dir' in result
        
        if result['docs_dir']:
            docs_path = Path(result['docs_dir'])
            
            # Verify MkDocs structure was created
            assert (threatforest_dir / "mkdocs.yml").exists()
            assert docs_path.exists()
            assert (docs_path / "index.md").exists()
            
            # Verify attack trees were copied
            assert (docs_path / "attack_trees").exists()
            assert (docs_path / "attack_trees" / "attack_tree_T001_data_breach.md").exists()
            assert (docs_path / "attack_trees" / "attack_tree_T002_denial_of_service.md").exists()
            
            # Verify data files were copied
            assert (docs_path / "data").exists()
            assert (docs_path / "data" / "threatforest_data.json").exists()
            
            # Verify assets were copied
            assert (docs_path / "assets").exists()
            assert (docs_path / "assets" / "attack_trees_dashboard.html").exists()
            
            # Verify threat statements page was generated
            threat_files = list(docs_path.glob("*_generated_threat_statements.md"))
            assert len(threat_files) == 1
            
            # Verify mkdocs.yml contains correct project name
            mkdocs_content = (threatforest_dir / "mkdocs.yml").read_text()
            assert "E-Commerce Platform" in mkdocs_content or "E_Commerce_Platform" in mkdocs_content
            
            print(f"✓ End-to-end test passed - docs generated at {docs_path}")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_end_to_end_with_vehicle_platform_sample():
    """Test documentation generation with real vehicle-platform sample data
    
    **Validates: Requirements 1.1, 1.4**
    """
    # Path to vehicle-platform sample docs (source files are in docs directory)
    sample_docs_dir = Path(__file__).parent.parent / "sample-applications" / "vehicle-platform" / "threatforest" / "attack_trees" / "docs"
    
    # Skip if sample doesn't exist
    if not sample_docs_dir.exists():
        pytest.skip("Vehicle platform sample not available")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy sample source files to temp directory
        temp_output = Path(tmpdir) / "threatforest" / "attack_trees"
        temp_output.mkdir(parents=True, exist_ok=True)
        
        # Copy the required source files from docs directory
        shutil.copy2(sample_docs_dir / "threatforest_analysis_report.md", temp_output)
        shutil.copy2(sample_docs_dir / "data" / "threatforest_data.json", temp_output)
        
        # Copy attack tree markdown files
        attack_trees_dir = sample_docs_dir / "attack_trees"
        if attack_trees_dir.exists():
            for file in attack_trees_dir.glob("*.md"):
                shutil.copy2(file, temp_output)
        
        # Initialize DocsGenerator
        generator = DocsGenerator(temp_output)
        
        # Validate required files exist
        missing_files = generator.validate_output_dir()
        assert len(missing_files) == 0, f"Missing required files: {missing_files}"
        
        # Generate documentation
        docs_dir = generator.generate()
        
        # Verify docs directory was created
        assert docs_dir.exists(), "Docs directory should be created"
        
        # Verify all expected files are in correct locations
        # mkdocs.yml is created at the output_dir level (attack_trees)
        mkdocs_yml = temp_output / "mkdocs.yml"
        assert mkdocs_yml.exists(), "mkdocs.yml should exist at output_dir level"
        
        # Verify mkdocs.yml is valid YAML
        with open(mkdocs_yml, 'r') as f:
            config = yaml.safe_load(f)
            assert 'site_name' in config, "mkdocs.yml should have site_name"
            assert 'theme' in config, "mkdocs.yml should have theme"
            assert 'nav' in config, "mkdocs.yml should have navigation"
            assert 'markdown_extensions' in config, "mkdocs.yml should have markdown_extensions"
        
        # Check docs/ structure
        assert (docs_dir / "index.md").exists(), "index.md should exist"
        assert (docs_dir / "attack_trees").exists(), "attack_trees directory should exist"
        assert (docs_dir / "data").exists(), "data directory should exist"
        assert (docs_dir / "assets").exists(), "assets directory should exist"
        
        # Verify attack tree files were copied
        attack_tree_files = list((docs_dir / "attack_trees").glob("attack_tree_*.md"))
        assert len(attack_tree_files) > 0, "Attack tree files should be copied"
        
        # Verify data files were copied
        assert (docs_dir / "data" / "threatforest_data.json").exists(), "threatforest_data.json should be copied"
        
        # Verify threat statements page was generated (named threats.md)
        threats_file = docs_dir / "threats.md"
        assert threats_file.exists(), "Threat statements page (threats.md) should be generated"
        
        # Verify attack trees index was generated
        assert (docs_dir / "attack_trees" / "index.md").exists(), "Attack trees index should be generated"
        
        print(f"✓ Vehicle platform sample test passed - docs at {docs_dir}")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_mkdocs_yml_structure():
    """Test that generated mkdocs.yml has correct structure
    
    **Validates: Requirements 1.1, 4.1, 4.3**
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directory structure
        threatforest_dir = Path(tmpdir) / "threatforest"
        output_dir = threatforest_dir / "attack_trees"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create minimal required files
        project_info = {
            "application_name": "Test Application",
            "description": "Test description"
        }
        
        (output_dir / "threatforest_data.json").write_text(json.dumps({
            "project_info": project_info,
            "threat_statements": []
        }))
        
        (output_dir / "threatforest_analysis_report.md").write_text("# Test Report")
        (output_dir / "attack_trees_dashboard.html").write_text("<html><body>Test</body></html>")
        
        # Generate docs
        generator = DocsGenerator(output_dir)
        generator.generate()
        
        # Load and verify mkdocs.yml (created at output_dir level)
        mkdocs_yml = output_dir / "mkdocs.yml"
        with open(mkdocs_yml, 'r') as f:
            config = yaml.safe_load(f)
        
        # Verify required fields
        assert config['site_name'] == "Test Application", "Site name should be the project name"
        
        # Verify theme configuration
        assert config['theme']['name'] == 'material', "Should use Material theme"
        assert 'palette' in config['theme'], "Should have color palette"
        
        # Verify Mermaid support
        assert 'pymdownx.superfences' in config['markdown_extensions'], "Should support superfences for Mermaid"
        
        # Find superfences config
        superfences_config = None
        for ext in config['markdown_extensions']:
            if isinstance(ext, dict) and 'pymdownx.superfences' in ext:
                superfences_config = ext['pymdownx.superfences']
                break
        
        assert superfences_config is not None, "Should have superfences configuration"
        assert 'custom_fences' in superfences_config, "Should have custom_fences for Mermaid"
        
        # Verify navigation structure
        assert len(config['nav']) > 0, "Should have navigation items"
        nav_items = config['nav']
        
        # Check for expected sections
        nav_labels = []
        for item in nav_items:
            if isinstance(item, dict):
                nav_labels.extend(item.keys())
        
        assert 'Home' in nav_labels or any('index.md' in str(item) for item in nav_items), "Should have Home/index"
        
        print("✓ mkdocs.yml structure test passed")


@pytest.mark.skipif(not MKDOCS_AVAILABLE, reason="MkDocs not installed")
def test_file_organization():
    """Test that files are organized in correct directory structure
    
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directory structure
        threatforest_dir = Path(tmpdir) / "threatforest"
        output_dir = threatforest_dir / "attack_trees"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test files
        project_info = {
            "application_name": "File Organization Test",
            "description": "Testing file organization"
        }
        
        threat_statements = [
            {
                "id": "T001",
                "category": "Test Category",
                "severity": "High",
                "statement": "Test threat statement"
            }
        ]
        
        (output_dir / "threatforest_data.json").write_text(json.dumps({
            "project_info": project_info,
            "threat_statements": threat_statements
        }))
        
        (output_dir / "threatforest_analysis_report.md").write_text("# Analysis Report\n\nTest content")
        (output_dir / "attack_tree_T001_test_category.md").write_text("# Attack Tree T001")
        (output_dir / ".threatforest_state.json").write_text(json.dumps({"state": "test"}))
        
        # Generate docs
        generator = DocsGenerator(output_dir)
        docs_dir = generator.generate()
        
        # Verify directory structure
        assert docs_dir.name == "docs", "Docs directory should be named 'docs'"
        assert docs_dir.parent == output_dir, "Docs should be under output_dir (attack_trees)"
        
        # Verify subdirectories
        assert (docs_dir / "attack_trees").is_dir(), "attack_trees should be a directory"
        assert (docs_dir / "data").is_dir(), "data should be a directory"
        assert (docs_dir / "assets").is_dir(), "assets should be a directory"
        
        # Verify files in correct locations
        assert (docs_dir / "index.md").is_file(), "index.md should be in docs/"
        assert (docs_dir / "attack_trees" / "attack_tree_T001_test_category.md").is_file(), "Attack trees should be in attack_trees/"
        assert (docs_dir / "data" / "threatforest_data.json").is_file(), "JSON should be in data/"
        assert (docs_dir / "data" / ".threatforest_state.json").is_file(), "State file should be in data/"
        
        # Verify mkdocs.yml is at output_dir level
        assert (output_dir / "mkdocs.yml").is_file(), "mkdocs.yml should be at output_dir level"
        
        print("✓ File organization test passed")
