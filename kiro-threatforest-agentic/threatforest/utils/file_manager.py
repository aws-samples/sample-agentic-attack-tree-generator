"""
File Manager for ThreatForest.

This module provides comprehensive file I/O operations including reading context files,
writing attack trees, generating summary reports, and managing output directories.
"""

import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime

from ..models import (
    AttackTree, 
    ThreatStatement, 
    ContextInformation, 
    AnalysisResult,
    SeverityLevel
)

# Import types for type hints only
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..agents.context_detection import DetectedFile, FileType


logger = logging.getLogger(__name__)


@dataclass
class OutputSummary:
    """Summary of generated output files."""
    
    output_directory: Path
    attack_tree_files: List[Path]
    summary_report_file: Optional[Path]
    context_info_file: Optional[Path]
    threat_statements_file: Optional[Path]
    total_files_created: int
    generation_timestamp: datetime
    
    def get_file_count_by_type(self) -> Dict[str, int]:
        """Get count of files by type."""
        return {
            "attack_trees": len(self.attack_tree_files),
            "summary_report": 1 if self.summary_report_file else 0,
            "context_info": 1 if self.context_info_file else 0,
            "threat_statements": 1 if self.threat_statements_file else 0
        }


class FileManagerError(Exception):
    """Custom exception for file manager errors."""
    pass


class FileManager:
    """
    Comprehensive file manager for ThreatForest operations.
    
    Handles reading context files, writing attack trees, generating reports,
    and managing output directory structures.
    """
    
    def __init__(self, base_output_dir: str = "./tf-output"):
        """
        Initialize FileManager.
        
        Args:
            base_output_dir: Base directory for all outputs
        """
        self.base_output_dir = Path(base_output_dir)
        self.current_session_dir: Optional[Path] = None
        
        # File extensions and formats
        self.supported_formats = {
            '.md': 'markdown',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.txt': 'text',
            '.mmd': 'mermaid'
        }
        
        logger.info(f"FileManager initialized with base directory: {self.base_output_dir}")
    
    def create_session_directory(self, session_name: Optional[str] = None) -> Path:
        """
        Create a new session directory for outputs.
        
        Args:
            session_name: Optional custom session name
            
        Returns:
            Path to created session directory
        """
        if session_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_name = f"session_{timestamp}"
        
        session_dir = self.base_output_dir / session_name
        session_dir.mkdir(parents=True, exist_ok=True)
        
        self.current_session_dir = session_dir
        logger.info(f"Created session directory: {session_dir}")
        
        return session_dir
    
    def get_session_directory(self) -> Path:
        """Get current session directory, creating one if needed."""
        if self.current_session_dir is None:
            return self.create_session_directory()
        return self.current_session_dir
    
    def read_context_file(self, file_path: Union[str, Path]) -> Tuple[str, Dict[str, Any]]:
        """
        Read and parse a context file.
        
        Args:
            file_path: Path to the context file
            
        Returns:
            Tuple of (content_string, metadata_dict)
            
        Raises:
            FileManagerError: If file cannot be read or parsed
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileManagerError(f"Context file not found: {file_path}")
        
        if not file_path.is_file():
            raise FileManagerError(f"Path is not a file: {file_path}")
        
        try:
            # Determine file format
            file_format = self.supported_formats.get(file_path.suffix.lower(), 'text')
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse structured formats
            parsed_data = None
            if file_format == 'json':
                try:
                    parsed_data = json.loads(content)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON in {file_path}: {e}")
            elif file_format == 'yaml':
                try:
                    parsed_data = yaml.safe_load(content)
                except yaml.YAMLError as e:
                    logger.warning(f"Invalid YAML in {file_path}: {e}")
            
            # Create metadata
            metadata = {
                'file_path': str(file_path),
                'file_size': file_path.stat().st_size,
                'file_format': file_format,
                'parsed_data': parsed_data,
                'read_timestamp': datetime.now().isoformat()
            }
            
            logger.debug(f"Successfully read context file: {file_path}")
            return content, metadata
            
        except Exception as e:
            raise FileManagerError(f"Error reading context file {file_path}: {e}")
    
    def read_multiple_context_files(
        self, 
        detected_files: List["DetectedFile"]
    ) -> Dict[str, Tuple[str, Dict[str, Any]]]:
        """
        Read multiple context files.
        
        Args:
            detected_files: List of detected context files
            
        Returns:
            Dictionary mapping file paths to (content, metadata) tuples
        """
        results = {}
        errors = []
        
        for detected_file in detected_files:
            try:
                # Check if the detected_file has the expected methods
                if hasattr(detected_file, 'is_valid') and hasattr(detected_file, 'is_readable'):
                    if detected_file.is_valid() and detected_file.is_readable():
                        content, metadata = self.read_context_file(detected_file.path)
                        results[str(detected_file.path)] = (content, metadata)
                    else:
                        logger.warning(f"Skipping invalid/unreadable file: {detected_file.path}")
                else:
                    # Fallback for simple path objects
                    content, metadata = self.read_context_file(detected_file.path)
                    results[str(detected_file.path)] = (content, metadata)
            except FileManagerError as e:
                error_msg = f"Error reading {detected_file.path}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        if errors:
            logger.warning(f"Encountered {len(errors)} errors while reading context files")
        
        logger.info(f"Successfully read {len(results)} context files")
        return results
    
    def write_attack_tree(
        self, 
        attack_tree: AttackTree, 
        output_dir: Optional[Path] = None,
        filename_prefix: str = "attack_tree"
    ) -> Path:
        """
        Write an attack tree to a Mermaid file.
        
        Args:
            attack_tree: Attack tree to write
            output_dir: Output directory (uses session dir if None)
            filename_prefix: Prefix for the filename
            
        Returns:
            Path to written file
        """
        if output_dir is None:
            output_dir = self.get_session_directory()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create safe filename
        safe_threat_id = self._sanitize_filename(attack_tree.threat_id)
        filename = f"{filename_prefix}_{safe_threat_id}.mmd"
        output_file = output_dir / filename
        
        try:
            # Generate file content
            content_lines = [
                f"# Attack Tree: {attack_tree.title}",
                "",
                f"**Threat ID:** {attack_tree.threat_id}",
                f"**Generated:** {attack_tree.generated_timestamp.isoformat()}",
                f"**Attack Steps:** {len(attack_tree.attack_steps)}",
                f"**TTC Mappings:** {len(attack_tree.ttc_mappings)}",
                "",
                "## Mermaid Diagram",
                "",
                "```mermaid",
                attack_tree.mermaid_content,
                "```",
                "",
                "## Attack Steps Details",
                ""
            ]
            
            # Add step details
            for step in attack_tree.attack_steps:
                content_lines.extend([
                    f"### {step.id} ({step.step_type.value.title()})",
                    "",
                    f"**Description:** {step.description}",
                    ""
                ])
                
                if step.dependencies:
                    content_lines.extend([
                        f"**Dependencies:** {', '.join(step.dependencies)}",
                        ""
                    ])
                
                if step.ttc_reference:
                    content_lines.extend([
                        f"**TTC Reference:** {step.ttc_reference}",
                        ""
                    ])
            
            # Add TTC mappings section
            if attack_tree.ttc_mappings:
                content_lines.extend([
                    "## TTC Mappings",
                    ""
                ])
                
                for step_id, mapping in attack_tree.ttc_mappings.items():
                    content_lines.extend([
                        f"### {step_id} → {mapping.ttc_technique_name}",
                        "",
                        f"- **TTC ID:** {mapping.ttc_technique_id}",
                        f"- **Alignment Score:** {mapping.alignment_score:.3f}",
                        f"- **Applied:** {'Yes' if mapping.applied else 'No'}",
                        ""
                    ])
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content_lines))
            
            logger.info(f"Attack tree written to: {output_file}")
            return output_file
            
        except Exception as e:
            raise FileManagerError(f"Error writing attack tree to {output_file}: {e}")
    
    def write_multiple_attack_trees(
        self, 
        attack_trees: List[AttackTree],
        output_dir: Optional[Path] = None
    ) -> List[Path]:
        """
        Write multiple attack trees to files.
        
        Args:
            attack_trees: List of attack trees to write
            output_dir: Output directory (uses session dir if None)
            
        Returns:
            List of paths to written files
        """
        if output_dir is None:
            output_dir = self.get_session_directory()
        
        written_files = []
        
        for attack_tree in attack_trees:
            try:
                output_file = self.write_attack_tree(attack_tree, output_dir)
                written_files.append(output_file)
            except FileManagerError as e:
                logger.error(f"Failed to write attack tree {attack_tree.threat_id}: {e}")
        
        logger.info(f"Successfully wrote {len(written_files)} attack tree files")
        return written_files
    
    def write_context_information(
        self, 
        context_info: ContextInformation,
        output_dir: Optional[Path] = None,
        filename: str = "context_information.md"
    ) -> Path:
        """
        Write context information to a markdown file.
        
        Args:
            context_info: Context information to write
            output_dir: Output directory (uses session dir if None)
            filename: Output filename
            
        Returns:
            Path to written file
        """
        if output_dir is None:
            output_dir = self.get_session_directory()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / filename
        
        try:
            content_lines = [
                "# Context Information",
                "",
                f"**Extraction Date:** {context_info.timestamp.isoformat()}",
                f"**Validation Status:** {context_info.validation_status.value.title()}",
                f"**Confidence Score:** {context_info.confidence_score:.2f}",
                ""
            ]
            
            # Technologies
            if context_info.technologies:
                content_lines.extend([
                    "## Technologies and Frameworks",
                    "",
                    *[f"- {tech}" for tech in context_info.technologies],
                    ""
                ])
            
            # Programming Languages
            if context_info.programming_languages:
                content_lines.extend([
                    "## Programming Languages",
                    "",
                    *[f"- {lang}" for lang in context_info.programming_languages],
                    ""
                ])
            
            # Business Sector
            if context_info.sector:
                content_lines.extend([
                    "## Business Sector",
                    "",
                    context_info.sector,
                    ""
                ])
            
            # Security Objectives
            if context_info.security_objectives:
                content_lines.extend([
                    "## Security Objectives",
                    "",
                    *[f"- {obj.title()}" for obj in context_info.security_objectives],
                    ""
                ])
            
            # Architecture Type
            if context_info.architecture_type:
                content_lines.extend([
                    "## Architecture Type",
                    "",
                    context_info.architecture_type,
                    ""
                ])
            
            # Compliance Frameworks
            if context_info.compliance_frameworks:
                content_lines.extend([
                    "## Compliance Frameworks",
                    "",
                    *[f"- {framework.upper()}" for framework in context_info.compliance_frameworks],
                    ""
                ])
            
            # Source Files
            if context_info.extracted_from:
                content_lines.extend([
                    "## Source Files",
                    "",
                    *[f"- {file}" for file in context_info.extracted_from],
                    ""
                ])
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content_lines))
            
            logger.info(f"Context information written to: {output_file}")
            return output_file
            
        except Exception as e:
            raise FileManagerError(f"Error writing context information to {output_file}: {e}")
    
    def write_threat_statements(
        self,
        threat_statements: List[ThreatStatement],
        output_dir: Optional[Path] = None,
        filename: str = "threat_statements.json"
    ) -> Path:
        """
        Write threat statements to a JSON file.
        
        Args:
            threat_statements: List of threat statements to write
            output_dir: Output directory (uses session dir if None)
            filename: Output filename
            
        Returns:
            Path to written file
        """
        if output_dir is None:
            output_dir = self.get_session_directory()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / filename
        
        try:
            # Convert to serializable format
            statements_data = []
            for statement in threat_statements:
                statement_dict = statement.model_dump()
                # Convert enum to string
                statement_dict['severity'] = statement.severity.value
                statements_data.append(statement_dict)
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(statements_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Threat statements written to: {output_file}")
            return output_file
            
        except Exception as e:
            raise FileManagerError(f"Error writing threat statements to {output_file}: {e}")
    
    def generate_summary_report(
        self,
        analysis_result: AnalysisResult,
        output_dir: Optional[Path] = None,
        filename: str = "analysis_summary.md"
    ) -> Path:
        """
        Generate a comprehensive summary report.
        
        Args:
            analysis_result: Complete analysis results
            output_dir: Output directory (uses session dir if None)
            filename: Output filename
            
        Returns:
            Path to written summary report
        """
        if output_dir is None:
            output_dir = self.get_session_directory()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / filename
        
        try:
            # Calculate statistics
            high_severity_threats = analysis_result.get_high_severity_threats()
            total_threats = len(analysis_result.threat_statements)
            total_trees = len(analysis_result.attack_trees)
            
            # Count TTC mappings
            total_mappings = sum(len(tree.ttc_mappings) for tree in analysis_result.attack_trees)
            
            content_lines = [
                "# ThreatForest Analysis Summary",
                "",
                f"**Analysis Date:** {analysis_result.analysis_timestamp.isoformat()}",
                f"**Source Directory:** {analysis_result.source_directory}",
                f"**Output Directory:** {analysis_result.output_directory}",
                "",
                "## Overview",
                "",
                f"- **Total Threat Statements:** {total_threats}",
                f"- **High-Severity Threats:** {len(high_severity_threats)}",
                f"- **Attack Trees Generated:** {total_trees}",
                f"- **TTC Mappings Applied:** {total_mappings}",
                "",
                "## Context Information",
                ""
            ]
            
            # Add context information summary
            context = analysis_result.context_info
            if context.technologies:
                content_lines.extend([
                    f"**Technologies:** {', '.join(context.technologies)}",
                    ""
                ])
            
            if context.programming_languages:
                content_lines.extend([
                    f"**Programming Languages:** {', '.join(context.programming_languages)}",
                    ""
                ])
            
            if context.sector:
                content_lines.extend([
                    f"**Business Sector:** {context.sector}",
                    ""
                ])
            
            # Threat statements by severity
            content_lines.extend([
                "## Threat Statements by Severity",
                ""
            ])
            
            severity_counts = {}
            for statement in analysis_result.threat_statements:
                severity = statement.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity in ['high', 'medium', 'low']:
                count = severity_counts.get(severity, 0)
                content_lines.append(f"- **{severity.title()}:** {count}")
            
            content_lines.append("")
            
            # High-severity threats (only these get attack trees)
            if high_severity_threats:
                content_lines.extend([
                    "## High-Severity Threats (Attack Trees Generated)",
                    ""
                ])
                
                for i, threat in enumerate(high_severity_threats, 1):
                    # Find corresponding attack tree
                    attack_tree = None
                    for tree in analysis_result.attack_trees:
                        if tree.threat_id == threat.id:
                            attack_tree = tree
                            break
                    
                    content_lines.extend([
                        f"### {i}. {threat.threat_action}",
                        "",
                        f"**Threat ID:** {threat.id}",
                        f"**Source:** {threat.threat_source}",
                        f"**Impact:** {threat.threat_impact}",
                        f"**Impacted Assets:** {', '.join(threat.impacted_assets)}",
                        ""
                    ])
                    
                    if attack_tree:
                        tree_filename = f"attack_tree_{self._sanitize_filename(threat.id)}.mmd"
                        content_lines.extend([
                            f"**Attack Tree:** [{tree_filename}](./{tree_filename})",
                            f"**Attack Steps:** {len(attack_tree.attack_steps)}",
                            f"**TTC Mappings:** {len(attack_tree.ttc_mappings)}",
                            ""
                        ])
            
            # Other severity threats (informational)
            other_threats = [t for t in analysis_result.threat_statements if not t.is_high_severity()]
            if other_threats:
                content_lines.extend([
                    "## Other Threats (No Attack Trees Generated)",
                    "",
                    "The following threats were identified but did not meet the high-severity threshold for attack tree generation:",
                    ""
                ])
                
                for threat in other_threats:
                    content_lines.extend([
                        f"- **{threat.threat_action}** ({threat.severity.value})",
                        f"  - Source: {threat.threat_source}",
                        f"  - Impact: {threat.threat_impact}",
                        ""
                    ])
            
            # Files generated
            content_lines.extend([
                "## Generated Files",
                "",
                "This analysis generated the following files:",
                "",
                "- `analysis_summary.md` - This summary report",
                "- `context_information.md` - Extracted context information",
                "- `threat_statements.json` - All identified threat statements"
            ])
            
            if analysis_result.attack_trees:
                content_lines.append("- Attack tree files (`.mmd` format):")
                for tree in analysis_result.attack_trees:
                    tree_filename = f"attack_tree_{self._sanitize_filename(tree.threat_id)}.mmd"
                    content_lines.append(f"  - `{tree_filename}`")
            
            content_lines.extend([
                "",
                "## Next Steps",
                "",
                "1. Review the generated attack trees in a Mermaid-compatible viewer",
                "2. Validate the TTC mappings against your threat model",
                "3. Consider implementing mitigations for high-severity attack paths",
                "4. Update your threat statements based on the analysis results",
                "",
                f"*Report generated by ThreatForest on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}*"
            ])
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content_lines))
            
            logger.info(f"Summary report written to: {output_file}")
            return output_file
            
        except Exception as e:
            raise FileManagerError(f"Error writing summary report to {output_file}: {e}")
    
    def generate_complete_output(
        self,
        analysis_result: AnalysisResult,
        output_dir: Optional[Path] = None
    ) -> OutputSummary:
        """
        Generate complete output for an analysis result.
        
        Args:
            analysis_result: Complete analysis results
            output_dir: Output directory (uses session dir if None)
            
        Returns:
            OutputSummary with information about generated files
        """
        if output_dir is None:
            output_dir = self.get_session_directory()
        
        output_dir = Path(output_dir)
        logger.info(f"Generating complete output to: {output_dir}")
        
        generated_files = []
        
        try:
            # Write attack trees
            attack_tree_files = self.write_multiple_attack_trees(
                analysis_result.attack_trees, output_dir
            )
            generated_files.extend(attack_tree_files)
            
            # Write context information
            context_info_file = self.write_context_information(
                analysis_result.context_info, output_dir
            )
            generated_files.append(context_info_file)
            
            # Write threat statements
            threat_statements_file = self.write_threat_statements(
                analysis_result.threat_statements, output_dir
            )
            generated_files.append(threat_statements_file)
            
            # Generate summary report
            summary_report_file = self.generate_summary_report(
                analysis_result, output_dir
            )
            generated_files.append(summary_report_file)
            
            # Create output summary
            output_summary = OutputSummary(
                output_directory=output_dir,
                attack_tree_files=attack_tree_files,
                summary_report_file=summary_report_file,
                context_info_file=context_info_file,
                threat_statements_file=threat_statements_file,
                total_files_created=len(generated_files),
                generation_timestamp=datetime.now()
            )
            
            logger.info(f"Complete output generation finished: {len(generated_files)} files created")
            return output_summary
            
        except Exception as e:
            raise FileManagerError(f"Error generating complete output: {e}")
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a string for use as a filename.
        
        Args:
            filename: Original filename string
            
        Returns:
            Sanitized filename string
        """
        import re
        
        # Replace invalid characters with underscores
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Replace spaces with underscores
        sanitized = sanitized.replace(' ', '_')
        
        # Remove multiple consecutive underscores
        sanitized = re.sub(r'_+', '_', sanitized)
        
        # Remove leading/trailing underscores
        sanitized = sanitized.strip('_')
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = "unnamed"
        
        # Limit length
        if len(sanitized) > 100:
            sanitized = sanitized[:100]
        
        return sanitized
    
    def cleanup_old_sessions(self, keep_recent: int = 10) -> int:
        """
        Clean up old session directories.
        
        Args:
            keep_recent: Number of recent sessions to keep
            
        Returns:
            Number of directories removed
        """
        if not self.base_output_dir.exists():
            return 0
        
        try:
            # Find all session directories
            session_dirs = []
            for item in self.base_output_dir.iterdir():
                if item.is_dir() and item.name.startswith('session_'):
                    session_dirs.append(item)
            
            # Sort by modification time (newest first)
            session_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            
            # Remove old sessions
            removed_count = 0
            for old_dir in session_dirs[keep_recent:]:
                try:
                    import shutil
                    shutil.rmtree(old_dir)
                    removed_count += 1
                    logger.info(f"Removed old session directory: {old_dir}")
                except Exception as e:
                    logger.warning(f"Failed to remove old session directory {old_dir}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} old session directories")
            
            return removed_count
            
        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")
            return 0