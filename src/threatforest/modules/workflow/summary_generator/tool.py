"""Main Summary Generator Tool - Orchestrates report generation"""
from typing import Dict, Any, List
from pathlib import Path
from ...utils.logger import ThreatForestLogger
from .report_formatters import ReportFormatters
from .file_generators import FileGenerators

# Import progress types if available
try:
    from ...core import ProgressEmitter, ProgressEvent, ProgressEventType
    PROGRESS_AVAILABLE = True
except ImportError:
    PROGRESS_AVAILABLE = False

# Import DocsGenerator if mkdocs is available
try:
    from ...visualization.docs_generator import DocsGenerator
    MKDOCS_AVAILABLE = True
except ImportError:
    MKDOCS_AVAILABLE = False


class SummaryGeneratorTool:
    """Tool for generating comprehensive summary reports
    
    Fully synchronous implementation - no async needed for report generation.
    """
    
    def __init__(self):
        self.name = "summary_generator"
        self.description = "Generate comprehensive threat analysis reports"
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Initialize modules
        self.formatters = ReportFormatters()
        self.file_gen = FileGenerators(self.logger, self.formatters)
    
    def run(self, attack_trees: Dict[str, Any],
               extracted_info: Dict[str, Any],
               output_dir: str,
               progress_emitter: 'ProgressEmitter' = None) -> Dict[str, Any]:
        """Execute summary generation (fully synchronous)
        
        Args:
            attack_trees: Dict with attack tree data
            extracted_info: Dict with extracted project info
            output_dir: Output directory path
            progress_emitter: Optional progress emitter
            
        Returns:
            Dict with output_files list
        """
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Handle None inputs
            attack_trees = attack_trees or {}
            extracted_info = extracted_info or {}
            
            # Emit progress
            if PROGRESS_AVAILABLE and progress_emitter:
                progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.STAGE_UPDATE,
                    stage="summary",
                    percentage=82.0,
                    message="Generating analysis report"
                ))
            
            # Generate main summary
            try:
                summary_file = self.file_gen.generate_main_summary(
                    output_path, attack_trees, extracted_info
                )
            except Exception as e:
                self.logger.warning(f"Main summary generation failed: {e}")
                summary_file = None
            
            # Emit progress
            if PROGRESS_AVAILABLE and progress_emitter:
                progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.STAGE_UPDATE,
                    stage="summary",
                    percentage=88.0,
                    message="Generating attack tree files"
                ))
            
            # Generate attack tree files
            try:
                trees = attack_trees.get('ttc_mapped_trees', []) or attack_trees.get('attack_trees', [])
                tree_files = self.file_gen.generate_attack_tree_files(output_path, trees)
            except Exception as e:
                self.logger.warning(f"Attack tree file generation failed: {e}")
                tree_files = []
            
            # Emit progress
            if PROGRESS_AVAILABLE and progress_emitter:
                progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.STAGE_UPDATE,
                    stage="summary",
                    percentage=95.0,
                    message="Exporting JSON data"
                ))
            
            # Generate JSON export
            try:
                json_file = self.file_gen.generate_json_export(
                    output_path, attack_trees, extracted_info
                )
            except Exception as e:
                self.logger.warning(f"JSON export generation failed: {e}")
                json_file = None
            
            # Collect output files (HTML generation removed - using MkDocs instead)
            output_files = []
            if summary_file:
                output_files.append(summary_file)
            if json_file:
                output_files.append(json_file)
            output_files.extend(tree_files)
            
            # Generate MkDocs documentation if available
            docs_dir = None
            if MKDOCS_AVAILABLE:
                try:
                    if PROGRESS_AVAILABLE and progress_emitter:
                        progress_emitter.emit(ProgressEvent(
                            type=ProgressEventType.STAGE_UPDATE,
                            stage="summary",
                            percentage=99.0,
                            message="Generating MkDocs documentation"
                        ))
                    
                    # Get parent directory (threatforest/) for docs generation
                    threatforest_dir = output_path.parent
                    docs_generator = DocsGenerator(threatforest_dir)
                    docs_dir = docs_generator.generate()
                    self.logger.info(f"Generated MkDocs documentation at {docs_dir}")
                except Exception as e:
                    self.logger.warning(f"MkDocs documentation generation failed: {e}")
                    # Don't fail the entire workflow if docs generation fails
            else:
                self.logger.debug("MkDocs not available - skipping documentation generation")
            
            return {
                'output_files': output_files,
                'summary_file': summary_file,
                'json_file': json_file,
                'tree_files': tree_files,
                'docs_dir': str(docs_dir) if docs_dir else None
            }
            
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return {'output_files': []}
