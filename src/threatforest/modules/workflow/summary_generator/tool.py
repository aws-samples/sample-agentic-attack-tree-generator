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
            
            # Generate HTML visualizations (interactive dashboard)
            html_files = []
            try:
                if PROGRESS_AVAILABLE and progress_emitter:
                    progress_emitter.emit(ProgressEvent(
                        type=ProgressEventType.STAGE_UPDATE,
                        stage="summary",
                        percentage=98.0,
                        message="Generating interactive HTML dashboard"
                    ))
                
                trees = attack_trees.get('ttc_mapped_trees', []) or attack_trees.get('attack_trees', [])
                html_files = self.file_gen.generate_html_visualizations(
                    output_path, trees, extracted_info
                )
                self.logger.info(f"Generated {len(html_files)} HTML visualization files")
            except Exception as e:
                self.logger.warning(f"HTML visualization generation failed: {e}")
            
            # Collect output files
            output_files = []
            if summary_file:
                output_files.append(summary_file)
            if json_file:
                output_files.append(json_file)
            output_files.extend(tree_files)
            output_files.extend(html_files)
            
            return {
                'output_files': output_files,
                'summary_file': summary_file,
                'json_file': json_file,
                'tree_files': tree_files,
                'html_files': html_files
            }
            
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return {'output_files': []}
