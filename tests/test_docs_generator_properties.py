"""
Property-based tests for DocsGenerator module.

Uses Hypothesis for property-based testing to verify correctness properties
defined in the mkdocs-integration design document.
"""
import json
import tempfile
from pathlib import Path
import sys

import pytest
import yaml
from hypothesis import given, strategies as st, settings, assume

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.modules.visualization.docs_generator import (
    DocsGenerator,
    MkDocsConfig,
    ThreatStatement,
)


# Strategies for generating test data
project_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=100,
).filter(lambda x: x.strip())  # Non-empty after stripping

attack_tree_filename_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=5,
    max_size=50,
).map(lambda x: f"attack_tree_{x}.md")


class TestProperty4MissingFileErrorReporting:
    """
    **Feature: mkdocs-integration, Property 4: Missing File Error Reporting**
    
    *For any* required file that is missing from the output directory, 
    the validation function SHALL return an error message that includes 
    the name of the missing file.
    
    **Validates: Requirements 5.3**
    """

    @given(
        missing_files=st.lists(
            st.sampled_from(DocsGenerator.REQUIRED_FILES),
            min_size=1,
            max_size=len(DocsGenerator.REQUIRED_FILES),
            unique=True,
        )
    )
    @settings(max_examples=100)
    def test_missing_files_are_reported(self, missing_files):
        """
        **Feature: mkdocs-integration, Property 4: Missing File Error Reporting**
        **Validates: Requirements 5.3**
        
        For any subset of required files that are missing, validate_output_dir()
        should return a list containing exactly those missing file names.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Create only the files that are NOT in missing_files
            present_files = set(DocsGenerator.REQUIRED_FILES) - set(missing_files)
            
            for filename in present_files:
                file_path = output_dir / filename
                if filename.endswith(".json"):
                    file_path.write_text("{}")
                elif filename.endswith(".html"):
                    file_path.write_text("<html></html>")
                else:
                    file_path.write_text("# Test content")
            
            # Create generator and validate
            generator = DocsGenerator(output_dir)
            result = generator.validate_output_dir()
            
            # Property: All missing files should be reported
            assert set(result) == set(missing_files), (
                f"Expected missing files {missing_files}, but got {result}"
            )
            
            # Property: Each missing file name should appear in the result
            for missing_file in missing_files:
                assert missing_file in result, (
                    f"Missing file '{missing_file}' not reported in validation result"
                )

    def test_all_files_present_returns_empty(self):
        """
        When all required files are present, validate_output_dir() should 
        return an empty list.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Create all required files
            for filename in DocsGenerator.REQUIRED_FILES:
                file_path = output_dir / filename
                if filename.endswith(".json"):
                    file_path.write_text("{}")
                elif filename.endswith(".html"):
                    file_path.write_text("<html></html>")
                else:
                    file_path.write_text("# Test content")
            
            generator = DocsGenerator(output_dir)
            result = generator.validate_output_dir()
            
            assert result == [], f"Expected empty list, got {result}"

    def test_empty_directory_reports_all_required_files(self):
        """
        When the output directory is empty, all required files should be reported.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            generator = DocsGenerator(output_dir)
            result = generator.validate_output_dir()
            
            assert set(result) == set(DocsGenerator.REQUIRED_FILES), (
                f"Expected all required files to be missing, got {result}"
            )


class TestProperty6AttackTreeLinkGeneration:
    """
    **Feature: mkdocs-integration, Property 6: Attack Tree Link Generation**
    
    *For any* threat that has an associated attack tree file, the generated 
    threats.md page SHALL contain a valid relative link to that attack tree page.
    
    **Validates: Requirements 8.3**
    """

    @given(
        threat_count=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=100)
    def test_threats_with_trees_have_links(self, threat_count):
        """
        **Feature: mkdocs-integration, Property 6: Attack Tree Link Generation**
        **Validates: Requirements 8.3**
        
        For any threat with an associated attack tree file, the generated page
        should contain a link to that attack tree.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Create threats and corresponding attack tree files
            threats = []
            for i in range(threat_count):
                threat_id = f"T{i:03d}"
                category = ["authentication", "injection", "dos", "breach"][i % 4]
                threats.append({
                    "id": threat_id,
                    "category": category.title(),
                    "severity": ["High", "Medium", "Low"][i % 3],
                    "statement": f"Threat statement for {threat_id}"
                })
                
                # Create attack tree file
                tree_file = output_dir / f"attack_tree_{threat_id}_{category}.md"
                tree_file.write_text(f"# Attack Tree for {threat_id}")
            
            threats_data = {
                "threats": {
                    "all_threats": threats
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: Each threat should have a link to its attack tree
            for threat in threats:
                threat_id = threat["id"]
                # Check for link pattern: [View Attack Tree](attack_trees/attack_tree_TXXX_
                link_pattern = f"attack_trees/attack_tree_{threat_id}_"
                assert link_pattern in content, (
                    f"Link to attack tree for '{threat_id}' not found in generated page"
                )

    @given(
        threats_with_trees=st.integers(min_value=1, max_value=5),
        threats_without_trees=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=100)
    def test_only_threats_with_trees_have_links(self, threats_with_trees, threats_without_trees):
        """
        **Feature: mkdocs-integration, Property 6: Attack Tree Link Generation**
        **Validates: Requirements 8.3**
        
        Threats without attack tree files should not have attack tree links.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            threats = []
            
            # Create threats WITH attack trees
            for i in range(threats_with_trees):
                threat_id = f"T{i:03d}"
                category = "authentication"
                threats.append({
                    "id": threat_id,
                    "category": category.title(),
                    "severity": "High",
                    "statement": f"Threat with tree {threat_id}"
                })
                tree_file = output_dir / f"attack_tree_{threat_id}_{category}.md"
                tree_file.write_text(f"# Attack Tree for {threat_id}")
            
            # Create threats WITHOUT attack trees
            for i in range(threats_without_trees):
                threat_id = f"T{100 + i:03d}"  # Different ID range
                threats.append({
                    "id": threat_id,
                    "category": "Injection",
                    "severity": "Medium",
                    "statement": f"Threat without tree {threat_id}"
                })
                # No attack tree file created
            
            threats_data = {
                "threats": {
                    "all_threats": threats
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: Threats without trees should NOT have attack tree links
            for i in range(threats_without_trees):
                threat_id = f"T{100 + i:03d}"
                link_pattern = f"attack_trees/attack_tree_{threat_id}_"
                assert link_pattern not in content, (
                    f"Unexpected link to attack tree for '{threat_id}' found "
                    f"(this threat has no attack tree file)"
                )

    def test_link_format_is_valid_relative_path(self):
        """
        **Feature: mkdocs-integration, Property 6: Attack Tree Link Generation**
        **Validates: Requirements 8.3**
        
        Attack tree links should be valid relative paths.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Create a threat with attack tree
            threat_id = "T001"
            category = "authentication"
            tree_file = output_dir / f"attack_tree_{threat_id}_{category}.md"
            tree_file.write_text(f"# Attack Tree for {threat_id}")
            
            threats_data = {
                "threats": {
                    "all_threats": [{
                        "id": threat_id,
                        "category": category.title(),
                        "severity": "High",
                        "statement": "Test threat"
                    }]
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: Link should be a valid relative path format
            assert "attack_trees/" in content
            assert "[View Attack Tree]" in content
            # Should not have absolute paths
            assert "file://" not in content
            assert "/Users/" not in content


class TestProperty5ThreatStatementsPageCompleteness:
    """
    **Feature: mkdocs-integration, Property 5: Threat Statements Page Completeness**
    
    *For any* threatforest_data.json containing threat statements, the generated 
    threats.md page SHALL contain all threat IDs, categories, and statements 
    from the source data.
    
    **Validates: Requirements 8.1, 8.2**
    """

    @given(
        threat_count=st.integers(min_value=1, max_value=20),
    )
    @settings(max_examples=100)
    def test_all_threat_ids_in_page(self, threat_count):
        """
        **Feature: mkdocs-integration, Property 5: Threat Statements Page Completeness**
        **Validates: Requirements 8.1, 8.2**
        
        For any set of threats, all threat IDs should appear in the generated page.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Generate test threats data
            threats = [
                {
                    "id": f"T{i:03d}",
                    "category": f"Category{i}",
                    "severity": ["High", "Medium", "Low"][i % 3],
                    "statement": f"Threat statement for T{i:03d}"
                }
                for i in range(threat_count)
            ]
            
            threats_data = {
                "threats": {
                    "all_threats": threats
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: All threat IDs should appear in the content
            for threat in threats:
                assert threat["id"] in content, (
                    f"Threat ID '{threat['id']}' not found in generated page"
                )

    @given(
        threat_count=st.integers(min_value=1, max_value=20),
    )
    @settings(max_examples=100)
    def test_all_categories_in_page(self, threat_count):
        """
        **Feature: mkdocs-integration, Property 5: Threat Statements Page Completeness**
        **Validates: Requirements 8.1, 8.2**
        
        For any set of threats, all categories should appear in the generated page.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            categories = ["Authentication", "Injection", "DoS", "DataBreach", 
                         "Tampering", "Escalation", "Disclosure", "Spoofing"]
            
            threats = [
                {
                    "id": f"T{i:03d}",
                    "category": categories[i % len(categories)],
                    "severity": ["High", "Medium", "Low"][i % 3],
                    "statement": f"Threat statement for T{i:03d}"
                }
                for i in range(threat_count)
            ]
            
            threats_data = {
                "threats": {
                    "all_threats": threats
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: All categories should appear in the content
            for threat in threats:
                assert threat["category"] in content, (
                    f"Category '{threat['category']}' not found in generated page"
                )

    @given(
        threat_count=st.integers(min_value=1, max_value=15),
        statement_words=st.lists(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10),
            min_size=5,
            max_size=20,
        ),
    )
    @settings(max_examples=100)
    def test_all_statements_in_page(self, threat_count, statement_words):
        """
        **Feature: mkdocs-integration, Property 5: Threat Statements Page Completeness**
        **Validates: Requirements 8.1, 8.2**
        
        For any set of threats, all statements should appear in the generated page.
        """
        assume(len(statement_words) >= 5)  # Ensure we have enough words
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            threats = [
                {
                    "id": f"T{i:03d}",
                    "category": f"Category{i}",
                    "severity": ["High", "Medium", "Low"][i % 3],
                    "statement": " ".join(statement_words) + f" unique{i}"
                }
                for i in range(threat_count)
            ]
            
            threats_data = {
                "threats": {
                    "all_threats": threats
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: All statements should appear in the content
            for threat in threats:
                assert threat["statement"] in content, (
                    f"Statement for '{threat['id']}' not found in generated page"
                )

    def test_empty_threats_handled_gracefully(self):
        """
        **Feature: mkdocs-integration, Property 5: Threat Statements Page Completeness**
        **Validates: Requirements 8.1, 8.2**
        
        When there are no threats, the page should be generated without errors.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            threats_data = {
                "threats": {
                    "all_threats": []
                }
            }
            
            generator = DocsGenerator(output_dir)
            content = generator.generate_threats_page(threats_data)
            
            # Property: Should generate valid content even with no threats
            assert "Threat Statements" in content
            assert "No threats identified" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


class TestProperty1ValidMkDocsConfiguration:
    """
    **Feature: mkdocs-integration, Property 1: Valid MkDocs Configuration Generation**
    
    *For any* valid ThreatForest output directory containing threatforest_data.json, 
    the generated mkdocs.yml SHALL be valid YAML that can be parsed and contains 
    required fields (site_name, theme, nav).
    
    **Validates: Requirements 1.1**
    """

    @given(
        project_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
            min_size=1,
            max_size=100,
        ).filter(lambda x: x.strip()),
        attack_tree_count=st.integers(min_value=0, max_value=20),
    )
    @settings(max_examples=100)
    def test_generated_config_is_valid_yaml(self, project_name, attack_tree_count):
        """
        **Feature: mkdocs-integration, Property 1: Valid MkDocs Configuration Generation**
        **Validates: Requirements 1.1**
        
        For any project name and set of attack trees, the generated configuration
        should be valid YAML that can be parsed.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Generate attack tree filenames
            attack_trees = [
                f"attack_tree_{i:08d}_category{i}.md" 
                for i in range(attack_tree_count)
            ]
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config(project_name, attack_trees)
            
            # Property: Config should be serializable to valid YAML
            yaml_str = yaml.dump(config, default_flow_style=False)
            parsed = yaml.safe_load(yaml_str)
            
            assert parsed is not None, "YAML parsing returned None"
            assert isinstance(parsed, dict), "Parsed YAML is not a dictionary"

    @given(
        project_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
            min_size=1,
            max_size=100,
        ).filter(lambda x: x.strip()),
        attack_tree_count=st.integers(min_value=0, max_value=20),
    )
    @settings(max_examples=100)
    def test_generated_config_has_required_fields(self, project_name, attack_tree_count):
        """
        **Feature: mkdocs-integration, Property 1: Valid MkDocs Configuration Generation**
        **Validates: Requirements 1.1**
        
        For any project name and set of attack trees, the generated configuration
        should contain all required MkDocs fields.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            attack_trees = [
                f"attack_tree_{i:08d}_category{i}.md" 
                for i in range(attack_tree_count)
            ]
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config(project_name, attack_trees)
            
            # Property: Config must have required fields
            assert "site_name" in config, "Missing site_name field"
            assert "theme" in config, "Missing theme field"
            assert "nav" in config, "Missing nav field"
            
            # Property: Theme must specify Material
            assert config["theme"].get("name") == "material", (
                f"Theme should be 'material', got {config['theme'].get('name')}"
            )
            
            # Property: Nav must be a list
            assert isinstance(config["nav"], list), "nav should be a list"

    @given(
        project_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
            min_size=1,
            max_size=100,
        ).filter(lambda x: x.strip()),
    )
    @settings(max_examples=100)
    def test_config_has_mermaid_support(self, project_name):
        """
        **Feature: mkdocs-integration, Property 1: Valid MkDocs Configuration Generation**
        **Validates: Requirements 1.1, 4.3**
        
        For any configuration, Mermaid diagram support should be configured
        via pymdown-extensions.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config(project_name, [])
            
            # Property: markdown_extensions should include pymdownx.superfences
            extensions = config.get("markdown_extensions", [])
            extension_names = []
            for ext in extensions:
                if isinstance(ext, str):
                    extension_names.append(ext)
                elif isinstance(ext, dict):
                    extension_names.extend(ext.keys())
            
            assert "pymdownx.superfences" in extension_names, (
                "pymdownx.superfences should be in markdown_extensions for Mermaid support"
            )


class TestProperty3AttackTreeNavigationCompleteness:
    """
    **Feature: mkdocs-integration, Property 3: Attack Tree Navigation Completeness**
    
    *For any* set of attack tree Markdown files in the output directory, 
    all files SHALL appear in the generated MkDocs navigation structure 
    under the "Attack Trees" section.
    
    **Validates: Requirements 1.3, 6.2**
    """

    @given(
        attack_tree_count=st.integers(min_value=0, max_value=20),
    )
    @settings(max_examples=100)
    def test_all_attack_trees_in_navigation(self, attack_tree_count):
        """
        **Feature: mkdocs-integration, Property 3: Attack Tree Navigation Completeness**
        **Validates: Requirements 1.3, 6.2**
        
        For any set of attack tree files, all files should appear in the 
        generated MkDocs navigation under the "Attack Trees" section.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Generate attack tree filenames with realistic format
            categories = ["authentication", "lateral_movement", "privilege_escalation", 
                         "denial_of_service", "data_breach", "injection", "tampering",
                         "credential_compromise", "supply_chain", "mitm"] * 2
            attack_trees = [
                f"attack_tree_T{i:03d}_{categories[i]}.md" 
                for i in range(attack_tree_count)
            ]
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config("Test Project", attack_trees)
            
            # Find the Attack Trees section in nav
            attack_trees_nav = None
            for nav_item in config.get("nav", []):
                if isinstance(nav_item, dict) and "Attack Trees" in nav_item:
                    attack_trees_nav = nav_item["Attack Trees"]
                    break
            
            assert attack_trees_nav is not None, "Attack Trees section not found in navigation"
            
            # Extract all file paths from the Attack Trees navigation
            nav_files = set()
            for item in attack_trees_nav:
                if isinstance(item, dict):
                    for key, value in item.items():
                        if isinstance(value, str) and value.endswith(".md"):
                            # Extract just the filename from the path
                            nav_files.add(Path(value).name)
            
            # Property: All attack tree files should be in navigation
            for tree_file in attack_trees:
                assert tree_file in nav_files, (
                    f"Attack tree '{tree_file}' not found in navigation. "
                    f"Navigation contains: {nav_files}"
                )

    @given(
        attack_tree_names=st.lists(
            st.text(
                alphabet="abcdefghijklmnopqrstuvwxyz0123456789_",
                min_size=3,
                max_size=30,
            ).filter(lambda x: x.strip()),
            min_size=1,
            max_size=15,
            unique=True,
        ),
    )
    @settings(max_examples=100)
    def test_attack_tree_paths_are_correct(self, attack_tree_names):
        """
        **Feature: mkdocs-integration, Property 3: Attack Tree Navigation Completeness**
        **Validates: Requirements 1.3, 6.2**
        
        For any attack tree files, the navigation paths should point to 
        the correct location in the attack_trees subdirectory.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            attack_trees = [f"attack_tree_{name}.md" for name in attack_tree_names]
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config("Test Project", attack_trees)
            
            # Find the Attack Trees section in nav
            attack_trees_nav = None
            for nav_item in config.get("nav", []):
                if isinstance(nav_item, dict) and "Attack Trees" in nav_item:
                    attack_trees_nav = nav_item["Attack Trees"]
                    break
            
            assert attack_trees_nav is not None, "Attack Trees section not found in navigation"
            
            # Property: All paths should be in attack_trees/ subdirectory
            for item in attack_trees_nav:
                if isinstance(item, dict):
                    for key, value in item.items():
                        if isinstance(value, str) and "attack_tree_" in value:
                            assert value.startswith("attack_trees/"), (
                                f"Attack tree path '{value}' should start with 'attack_trees/'"
                            )

    def test_empty_attack_trees_still_has_overview(self):
        """
        **Feature: mkdocs-integration, Property 3: Attack Tree Navigation Completeness**
        **Validates: Requirements 1.3, 6.2**
        
        When there are no attack trees, the Attack Trees section should 
        still contain an Overview page.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config("Test Project", [])
            
            # Find the Attack Trees section in nav
            attack_trees_nav = None
            for nav_item in config.get("nav", []):
                if isinstance(nav_item, dict) and "Attack Trees" in nav_item:
                    attack_trees_nav = nav_item["Attack Trees"]
                    break
            
            assert attack_trees_nav is not None, "Attack Trees section not found in navigation"
            
            # Property: Should have at least the Overview page
            has_overview = False
            for item in attack_trees_nav:
                if isinstance(item, dict) and "Overview" in item:
                    has_overview = True
                    break
            
            assert has_overview, "Attack Trees section should have Overview page even with no attack trees"


class TestProperty2ProjectNamePropagation:
    """
    **Feature: mkdocs-integration, Property 2: Project Name Propagation**
    
    *For any* project name extracted from threatforest_data.json, the generated 
    mkdocs.yml SHALL contain that exact project name in the site_name field.
    
    **Validates: Requirements 4.2**
    """

    @given(
        project_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
            min_size=1,
            max_size=100,
        ).filter(lambda x: x.strip()),
    )
    @settings(max_examples=100)
    def test_project_name_in_site_name(self, project_name):
        """
        **Feature: mkdocs-integration, Property 2: Project Name Propagation**
        **Validates: Requirements 4.2**
        
        For any project name, the generated mkdocs.yml configuration should
        contain that exact project name in the site_name field.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config(project_name, [])
            
            # Property: site_name must exactly match the provided project name
            assert config["site_name"] == project_name, (
                f"site_name should be '{project_name}', got '{config['site_name']}'"
            )

    @given(
        project_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
            min_size=1,
            max_size=100,
        ).filter(lambda x: x.strip()),
        attack_tree_count=st.integers(min_value=0, max_value=10),
    )
    @settings(max_examples=100)
    def test_project_name_preserved_with_attack_trees(self, project_name, attack_tree_count):
        """
        **Feature: mkdocs-integration, Property 2: Project Name Propagation**
        **Validates: Requirements 4.2**
        
        For any project name and any number of attack trees, the project name
        should be preserved exactly in the site_name field.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            attack_trees = [
                f"attack_tree_{i:08d}_category{i}.md" 
                for i in range(attack_tree_count)
            ]
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config(project_name, attack_trees)
            
            # Property: site_name must exactly match regardless of attack trees
            assert config["site_name"] == project_name, (
                f"site_name should be '{project_name}' with {attack_tree_count} attack trees, "
                f"got '{config['site_name']}'"
            )

    @given(
        project_name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
            min_size=1,
            max_size=100,
        ).filter(lambda x: x.strip()),
    )
    @settings(max_examples=100)
    def test_project_name_in_yaml_output(self, project_name):
        """
        **Feature: mkdocs-integration, Property 2: Project Name Propagation**
        **Validates: Requirements 4.2**
        
        For any project name, when the configuration is serialized to YAML
        and parsed back, the site_name should still match exactly.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            generator = DocsGenerator(output_dir)
            config = generator.generate_mkdocs_config(project_name, [])
            
            # Serialize to YAML and parse back
            yaml_str = yaml.dump(config, default_flow_style=False)
            parsed_config = yaml.safe_load(yaml_str)
            
            # Property: site_name must survive YAML round-trip
            assert parsed_config["site_name"] == project_name, (
                f"site_name should be '{project_name}' after YAML round-trip, "
                f"got '{parsed_config['site_name']}'"
            )
