"""DocsGenerator - Generates MkDocs documentation from ThreatForest output.

This module provides the DocsGenerator class which transforms ThreatForest
analysis output into a navigable MkDocs documentation site.
"""

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from ..utils.logger import ThreatForestLogger


@dataclass
class MkDocsConfig:
    """MkDocs configuration model."""

    site_name: str
    site_description: str = ""
    theme: dict = field(default_factory=dict)
    nav: List[dict] = field(default_factory=list)
    markdown_extensions: List = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_yaml(self) -> str:
        """Serialize to YAML string."""
        config_dict = {
            "site_name": self.site_name,
            "site_description": self.site_description,
            "theme": self.theme,
            "nav": self.nav,
            "markdown_extensions": self.markdown_extensions,
            "plugins": self.plugins,
        }
        if self.extra:
            config_dict["extra"] = self.extra
        return yaml.dump(config_dict, default_flow_style=False, sort_keys=False)


@dataclass
class ThreatStatement:
    """Threat statement for display."""

    id: str
    category: str
    severity: str
    statement: str
    has_attack_tree: bool = False
    attack_tree_file: Optional[str] = None


class DocsGenerator:
    """Generates MkDocs documentation from ThreatForest output."""

    # Required files that must exist in the output directory
    REQUIRED_FILES = [
        "threatforest_data.json",
        "threatforest_analysis_report.md",
    ]

    def __init__(self, output_dir: Path):
        """Initialize with ThreatForest output directory.

        Args:
            output_dir: Path to the ThreatForest output directory containing
                       attack trees and analysis files.
        """
        self.output_dir = Path(output_dir)
        self._data: Optional[dict] = None
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)

    @staticmethod
    def is_mkdocs_available() -> bool:
        """Check if mkdocs command is available in the system.

        Returns:
            True if mkdocs is available, False otherwise.
        """
        try:
            result = subprocess.run(
                ["mkdocs", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def get_mkdocs_install_instructions() -> str:
        """Get installation instructions for mkdocs.

        Returns:
            String with installation instructions.
        """
        return (
            "MkDocs is not installed. To install it, run:\n\n"
            "  pip install mkdocs mkdocs-material pymdown-extensions\n\n"
            "Or if using pipx:\n\n"
            "  pipx reinstall threatforest --force\n"
        )

    def validate_output_dir(self) -> List[str]:
        """Validate required files exist in output directory.

        Returns:
            List of missing required files (empty if valid).
        """
        missing_files = []
        for required_file in self.REQUIRED_FILES:
            file_path = self.output_dir / required_file
            if not file_path.exists():
                missing_files.append(required_file)
        return missing_files

    def _load_data(self) -> dict:
        """Load threatforest_data.json."""
        if self._data is None:
            data_file = self.output_dir / "threatforest_data.json"
            with open(data_file, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        return self._data

    def _get_project_name(self) -> str:
        """Extract project name from data."""
        data = self._load_data()
        return data.get("project_info", {}).get(
            "application_name", "ThreatForest Analysis"
        )

    def _get_attack_tree_files(self) -> List[str]:
        """Get list of attack tree markdown files."""
        attack_tree_files = []
        for file_path in self.output_dir.glob("attack_tree_*.md"):
            attack_tree_files.append(file_path.name)
        return sorted(attack_tree_files)

    def generate_mkdocs_config(
        self, project_name: str, attack_trees: List[str]
    ) -> dict:
        """Generate mkdocs.yml configuration.

        Args:
            project_name: Name from project_info
            attack_trees: List of attack tree filenames

        Returns:
            Dictionary representing mkdocs.yml content
        """
        # Build navigation structure for attack trees
        attack_tree_nav = []
        for tree_file in attack_trees:
            # Extract a readable name from the filename
            # Format: attack_tree_{uuid}_{category}.md
            parts = tree_file.replace("attack_tree_", "").replace(".md", "").split("_")
            if len(parts) >= 2:
                category = parts[-1].replace("_", " ").title()
                tree_id = parts[0][:8]  # First 8 chars of UUID
                display_name = f"{category} ({tree_id})"
            else:
                display_name = tree_file.replace(".md", "")
            attack_tree_nav.append({display_name: f"attack_trees/{tree_file}"})

        # Add index page for attack trees section
        attack_trees_section = [{"Overview": "attack_trees/index.md"}] + attack_tree_nav

        config = MkDocsConfig(
            site_name=project_name,
            site_description=f"Threat Analysis Report for {project_name}",
            theme={
                "name": "material",
                "palette": [
                    {
                        "scheme": "slate",
                        "primary": "deep orange",
                        "accent": "teal",
                    }
                ],
                "features": [
                    "navigation.tabs",
                    "navigation.sections",
                    "navigation.expand",
                    "content.code.copy",
                ],
            },
            nav=[
                {"Home": "index.md"},
                {"Threat Statements": "threats.md"},
                {"Attack Trees": attack_trees_section},
            ],
            markdown_extensions=[
                "pymdownx.superfences",
                {
                    "pymdownx.superfences": {
                        "custom_fences": [
                            {
                                "name": "mermaid",
                                "class": "mermaid",
                                "format": "!!python/name:pymdownx.superfences.fence_code_format",
                            }
                        ]
                    }
                },
                "pymdownx.tabbed",
                "pymdownx.details",
                "admonition",
                "tables",
                "toc",
            ],
            plugins=["search"],
            extra={
                "generator": "ThreatForest MkDocs Integration",
            },
        )

        return {
            "site_name": config.site_name,
            "site_description": config.site_description,
            "theme": config.theme,
            "nav": config.nav,
            "markdown_extensions": config.markdown_extensions,
            "plugins": config.plugins,
            "extra": config.extra,
        }

    def generate(self) -> Path:
        """Generate complete MkDocs documentation structure.

        Returns:
            Path to the generated docs directory.

        Raises:
            FileNotFoundError: If required files are missing.
            ValueError: If data files contain invalid content.
        """
        # Validate required files exist
        missing = self.validate_output_dir()
        if missing:
            raise FileNotFoundError(
                f"Missing required files: {', '.join(missing)}"
            )

        self.logger.info(f"Generating MkDocs documentation from {self.output_dir}")

        # Create output structure
        docs_dir = self.output_dir / "docs"
        docs_dir.mkdir(exist_ok=True)
        (docs_dir / "attack_trees").mkdir(exist_ok=True)
        (docs_dir / "data").mkdir(exist_ok=True)
        (docs_dir / "assets").mkdir(exist_ok=True)

        # Load data and get project info
        project_name = self._get_project_name()
        attack_trees = self._get_attack_tree_files()

        # Generate mkdocs.yml
        config = self.generate_mkdocs_config(project_name, attack_trees)
        mkdocs_yml_path = self.output_dir / "mkdocs.yml"
        with open(mkdocs_yml_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        self.logger.info(f"Generated mkdocs.yml with {len(attack_trees)} attack trees")

        # Move attack tree files into docs structure (no duplication)
        for tree_file in attack_trees:
            src = self.output_dir / tree_file
            dst = docs_dir / "attack_trees" / tree_file
            
            # Remove destination if it exists
            if dst.exists():
                dst.unlink()
            
            # Move the file
            shutil.move(str(src), str(dst))
        
        self.logger.info(f"Moved {len(attack_trees)} attack tree files into docs structure")

        # Move data files
        data_src = self.output_dir / "threatforest_data.json"
        data_dst = docs_dir / "data" / "threatforest_data.json"
        if data_dst.exists():
            data_dst.unlink()
        shutil.move(str(data_src), str(data_dst))
        
        state_file = self.output_dir / ".threatforest_state.json"
        if state_file.exists():
            state_dst = docs_dir / "data" / ".threatforest_state.json"
            if state_dst.exists():
                state_dst.unlink()
            shutil.move(str(state_file), str(state_dst))

        # Move analysis report (will be used to generate index.md)
        report_src = self.output_dir / "threatforest_analysis_report.md"
        report_dst = docs_dir / "threatforest_analysis_report.md"
        if report_src.exists():
            if report_dst.exists():
                report_dst.unlink()
            shutil.move(str(report_src), str(report_dst))

        # Generate index.md from analysis report
        self._generate_index_page(docs_dir)

        # Generate threats page
        self._generate_threats_page_file(docs_dir)

        # Generate attack trees index
        self._generate_attack_trees_index(docs_dir, attack_trees)

        self.logger.info(f"✓ MkDocs documentation generated at {docs_dir}")

        return docs_dir

    def _generate_index_page(self, docs_dir: Path) -> None:
        """Generate index.md from threatforest_analysis_report.md."""
        # Report has been moved to docs_dir
        report_path = docs_dir / "threatforest_analysis_report.md"
        index_path = docs_dir / "index.md"

        # Read the analysis report
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Add link to interactive dashboard
        dashboard_link = "\n\n[View Interactive Dashboard](assets/attack_trees_dashboard.html)\n"

        with open(index_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.write(dashboard_link)

    def generate_threats_page(self, threats_data: dict) -> str:
        """Generate Markdown page listing all threat statements.

        Args:
            threats_data: Data from threatforest_data.json

        Returns:
            Markdown content for threats page
        """
        content = ["# Threat Statements\n\n"]
        content.append(
            "This page lists all identified threats from the threat modeling analysis.\n\n"
        )

        all_threats = threats_data.get("threats", {}).get("all_threats", [])
        
        if not all_threats:
            content.append("*No threats identified.*\n")
            return "".join(content)

        # Build a set of threat IDs that have attack trees
        attack_tree_files = self._get_attack_tree_files()
        threat_ids_with_trees = set()
        for tree_file in attack_tree_files:
            # Extract threat ID from filename: attack_tree_T001_category.md
            parts = tree_file.replace("attack_tree_", "").replace(".md", "").split("_")
            if parts:
                threat_ids_with_trees.add(parts[0])

        # Group threats by severity
        high_threats = [t for t in all_threats if t.get("severity") == "High"]
        medium_threats = [t for t in all_threats if t.get("severity") == "Medium"]
        low_threats = [t for t in all_threats if t.get("severity") == "Low"]

        def format_threat(threat: dict) -> str:
            """Format a single threat as markdown."""
            threat_id = threat.get("id", "Unknown")
            category = threat.get("category", "Unknown")
            severity = threat.get("severity", "Unknown")
            statement = threat.get("statement", "No statement provided")
            
            lines = []
            lines.append(f"### {threat_id}: {category}\n\n")
            lines.append(f"**Severity:** {severity}\n\n")
            lines.append(f"{statement}\n\n")
            
            # Add link to attack tree if available
            if threat_id in threat_ids_with_trees:
                # Find the matching attack tree file
                for tree_file in attack_tree_files:
                    if tree_file.startswith(f"attack_tree_{threat_id}_"):
                        lines.append(
                            f"[View Attack Tree](attack_trees/{tree_file})\n\n"
                        )
                        break
            
            lines.append("---\n\n")
            return "".join(lines)

        if high_threats:
            content.append("## High Severity Threats\n\n")
            for threat in high_threats:
                content.append(format_threat(threat))

        if medium_threats:
            content.append("## Medium Severity Threats\n\n")
            for threat in medium_threats:
                content.append(format_threat(threat))

        if low_threats:
            content.append("## Low Severity Threats\n\n")
            for threat in low_threats:
                content.append(format_threat(threat))

        return "".join(content)

    def _generate_threats_page_file(self, docs_dir: Path) -> None:
        """Generate threats.md file in docs directory.
        
        First checks for existing generated threats file following the naming
        convention {AppName}_generated_threat_statements.md. If found, copies it.
        Otherwise generates from threatforest_data.json.
        """
        data = self._load_data()
        project_name = self._get_project_name()
        
        # Check for existing generated threats file
        # Format: {ApplicationName}_generated_threat_statements.md
        safe_name = project_name.replace(" ", "_")
        existing_threats_file = self.output_dir.parent / f"{safe_name}_generated_threat_statements.md"
        
        threats_page_path = docs_dir / "threats.md"
        
        if existing_threats_file.exists():
            # Copy existing file
            shutil.copy2(existing_threats_file, threats_page_path)
            self.logger.info(f"Copied existing threats file: {existing_threats_file.name}")
        else:
            # Generate from JSON data
            content = self.generate_threats_page(data)
            with open(threats_page_path, "w", encoding="utf-8") as f:
                f.write(content)
            self.logger.info("Generated threats page from threatforest_data.json")

    def _generate_attack_trees_index(
        self, docs_dir: Path, attack_trees: List[str]
    ) -> None:
        """Generate attack_trees/index.md with overview."""
        index_path = docs_dir / "attack_trees" / "index.md"
        data = self._load_data()

        content = ["# Attack Trees Overview\n"]
        content.append(
            "This section contains detailed attack trees for each identified threat.\n\n"
        )

        # Build a mapping of threat IDs to their info
        threat_info = {}
        for threat in data.get("threats", {}).get("all_threats", []):
            threat_info[threat["id"]] = threat

        content.append("| Threat ID | Category | Severity | Description |\n")
        content.append("|-----------|----------|----------|-------------|\n")

        for tree_file in attack_trees:
            # Extract threat ID from filename
            # Format: attack_tree_{uuid}_{category}.md
            parts = tree_file.replace("attack_tree_", "").replace(".md", "")
            uuid_part = "_".join(parts.split("_")[:-1])

            info = threat_info.get(uuid_part, {})
            threat_id = uuid_part[:8] if uuid_part else "Unknown"
            category = info.get("category", "Unknown")
            severity = info.get("severity", "Unknown")
            description = info.get("description", "")[:80] + "..."

            content.append(
                f"| [{threat_id}]({tree_file}) | {category} | {severity} | {description} |\n"
            )

        with open(index_path, "w", encoding="utf-8") as f:
            f.writelines(content)
