"""
ThreatForest Strands-based Orchestrator Agent
"""
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import traceback

from .modules.core import Context, ThreatForestState, WorkflowStage, StateManager
from .modules.core import ProgressEmitter, ProgressEvent, ProgressEventType
from .modules.workflow.context_analysis import ContextAnalysisTool
from .modules.workflow.information_extraction import InformationExtractionTool
from .modules.workflow.attack_tree_generator import AttackTreeGeneratorTool
from .modules.workflow.ttc_mappings import TTCMappingTool
from .modules.workflow.summary_generator import SummaryGeneratorTool


@dataclass
class ThreatForestConfig:
    """Configuration for ThreatForest execution"""
    project_path: Path
    bedrock_model: str  # Required - must be provided by caller
    threat_model_path: Optional[str] = None
    aws_profile: Optional[str] = None
    output_dir: Optional[Path] = None
    resume: bool = False  # Enable resume from checkpoint


class ThreatForestOrchestrator:
    """Main orchestrating workflow for ThreatForest attack tree generation"""
    
    def __init__(self, config: ThreatForestConfig, console=None):
        self.config = config
        self.state_manager = StateManager()
        self.state: Optional[ThreatForestState] = None
        self.progress_emitter = ProgressEmitter(enabled=False)
        self.console = console
        
        # Initialize logger
        from .modules.utils.logger import ThreatForestLogger
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Get threshold from config.yaml
        from .config import config as app_config
        
        # Initialize tools as instance attributes for direct access
        self.context_tool = ContextAnalysisTool()
        self.extraction_tool = InformationExtractionTool(console=console)
        self.tree_generator_tool = AttackTreeGeneratorTool(console=console)
        self.ttc_tool = TTCMappingTool(threshold=app_config.ttc_threshold, console=console)
        self.summary_tool = SummaryGeneratorTool()
    
    def _initialize_state(self) -> ThreatForestState:
        """Initialize or resume workflow state"""
        # Check for existing state
        existing_state = self.state_manager.load_checkpoint()
        
        if existing_state:
            # Validate state
            is_valid, message = existing_state.is_valid_for_resume()
            
            if not is_valid:
                self.logger.warning(f"Found existing state but it's invalid: {message}")
                self.logger.info("Starting fresh workflow...")
                print(f"⚠️  Found existing state but it's invalid: {message}")
                print("Starting fresh workflow...")
                return ThreatForestState(
                    project_path=str(self.config.project_path),
                    threat_model_path=self.config.threat_model_path,
                    aws_profile=self.config.aws_profile,
                    bedrock_model=self.config.bedrock_model
                )
            
            # If resume flag is explicitly set, use it
            if self.config.resume:
                self.logger.info(f"Resuming from {existing_state.current_stage} stage")
                print(f"✓ Resuming from {existing_state.current_stage} stage\n")
                return existing_state
            else:
                # Non-interactive mode or user doesn't want to resume - start fresh
                self.logger.info("Starting fresh workflow")
                print("Starting fresh workflow...\n")
                self.state_manager.archive_checkpoint("latest")
                return ThreatForestState(
                    project_path=str(self.config.project_path),
                    threat_model_path=self.config.threat_model_path,
                    aws_profile=self.config.aws_profile,
                    bedrock_model=self.config.bedrock_model
                )
        
        return ThreatForestState(
            project_path=str(self.config.project_path),
            threat_model_path=self.config.threat_model_path,
            aws_profile=self.config.aws_profile,
            bedrock_model=self.config.bedrock_model
        )
    
    def execute_workflow(self) -> Dict[str, Any]:
        """Execute the complete ThreatForest workflow with state management (SYNCHRONOUS)"""
        # Emit immediate start event
        self.progress_emitter.emit(ProgressEvent(
            type=ProgressEventType.STAGE_START,
            stage="setup",
            percentage=0.0,
            message="Starting workflow"
        ))
        
        # Initialize or resume state
        self.state = self._initialize_state()
        context = Context()
        context.add("workflow_state", self.state.model_dump())
        
        try:
            # Skip setup validation when called from UI (already validated)
            # Mark setup as complete to proceed directly to workflow
            if not self.state.setup_complete:
                self.state.setup_complete = True
                self.state.setup_result = {
                    "setup_complete": True,
                    "aws_status": "valid",
                    "bedrock_status": "accessible",
                    "skipped": "UI pre-validated"
                }
                self.state_manager.save_checkpoint(self.state)
            
            # Emit context analysis start
            self.progress_emitter.emit(ProgressEvent(
                type=ProgressEventType.STAGE_START,
                stage="context_analysis",
                percentage=10.0,
                message="Analyzing project context"
            ))
            
            # Step 2: Context analysis
            if not self.state.context_complete:
                self.state.advance_to(WorkflowStage.CONTEXT_ANALYSIS)
                context_result = self.context_tool.run(
                    project_path=str(self.config.project_path)
                )
                self.state.context_files = context_result
                self.state.context_complete = True
                self.state_manager.save_checkpoint(self.state)
                context.add("context_files", context_result)
                context.add("workflow_state", self.state.model_dump())
                
                # Emit context complete
                self.progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.STAGE_COMPLETE,
                    stage="context_analysis",
                    percentage=20.0,
                    message="Context analysis complete"
                ))
            else:
                context.add("context_files", self.state.context_files)
            
            # Emit extraction start
            self.progress_emitter.emit(ProgressEvent(
                type=ProgressEventType.STAGE_START,
                stage="extraction",
                percentage=20.0,
                message="Extracting project information with AI"
            ))
            
            # Step 3: Information extraction (using new agent-based architecture)
            if not self.state.extraction_complete:
                self.state.advance_to(WorkflowStage.EXTRACTION)
                
                # Add project path to context for agents
                context_files = dict(self.state.context_files)
                context_files['project_path'] = str(self.config.project_path)
                
                # Pass threat_model_path as threat_file_path for agent-based extraction
                extraction_result = self.extraction_tool.run(
                    context_files=context_files,
                    bedrock_model=self.config.bedrock_model,
                    aws_profile=self.config.aws_profile,
                    threat_file_path=self.config.threat_model_path  # New parameter for agent workflow
                )
                self.state.extracted_info = extraction_result
                self.state.extraction_complete = True
                self.state_manager.save_checkpoint(self.state)
                context.add("extracted_info", extraction_result)
                context.add("workflow_state", self.state.model_dump())
                
                # Emit extraction complete
                self.progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.STAGE_COMPLETE,
                    stage="extraction",
                    percentage=40.0,
                    message="Information extraction complete"
                ))
            else:
                context.add("extracted_info", self.state.extracted_info)
                extraction_result = self.state.extracted_info
            
            # Determine application name for output directory
            app_name = extraction_result.get("project_info", {}).get("application_name", "unknown_app")
            project_name = self.config.project_path.name.replace(' ', '_').lower()
            
            # Use project_path/threatforest directory structure
            output_dir = self.config.project_path / "threatforest" / "attack_trees"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Emit tree generation start
            high_threat_count = len(extraction_result.get("high_severity_threats", []))
            self.progress_emitter.emit(ProgressEvent(
                type=ProgressEventType.STAGE_START,
                stage="tree_generation",
                percentage=40.0,
                message=f"Generating attack trees for {high_threat_count} threats",
                details={"threat_count": high_threat_count}
            ))
            
            # Check if all threats are already complete
            state_file = output_dir / ".threatforest_state.json"
            if state_file.exists() and not self.state.tree_generation_complete:
                try:
                    import json
                    import os
                    with open(state_file) as f:
                        state_data = json.load(f)
                        threat_status = state_data.get('threat_status', {})
                        successful = [tid for tid, status in threat_status.items() if status == 'success']
                        failed = [tid for tid, status in threat_status.items() if status == 'failed']
                        
                        if successful and not failed:
                            # All threats successful - delete files and regenerate
                            self.logger.info(f"Found {len(successful)} existing attack trees - regenerating all")
                            print(f"\n✓ Found {len(successful)} existing attack trees")
                            print(f"  Deleting and regenerating all trees...\n")
                            
                            # Delete state file
                            if state_file.exists():
                                os.remove(state_file)
                            
                            # Delete JSON export
                            json_file = output_dir / "threatforest_data.json"
                            if json_file.exists():
                                os.remove(json_file)
                            
                            # Delete report
                            report_file = output_dir / "threatforest_analysis_report.md"
                            if report_file.exists():
                                os.remove(report_file)
                            
                            # Delete attack tree markdown files
                            for tree_file in output_dir.glob("attack_tree_*.md"):
                                os.remove(tree_file)
                except Exception as e:
                    self.logger.warning(f"Failed to check/delete state files: {e}")
            
            # Step 4: Generate attack trees (High severity only)
            if not self.state.tree_generation_complete:
                self.state.advance_to(WorkflowStage.TREE_GENERATION)
                attack_trees = self.tree_generator_tool.run(
                    threat_statements=extraction_result.get("threat_statements", []),
                    extracted_info=extraction_result,
                    bedrock_model=self.config.bedrock_model,
                    aws_profile=self.config.aws_profile,
                    output_dir=str(output_dir),
                    progress_emitter=self.progress_emitter
                )
                self.state.attack_trees = attack_trees.get("attack_trees", [])
                self.state.tree_generation_complete = True
                self.state_manager.save_checkpoint(self.state)
                context.add("attack_trees", attack_trees)
                context.add("workflow_state", self.state.model_dump())
                
                # Emit tree generation complete
                self.progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.STAGE_COMPLETE,
                    stage="tree_generation",
                    percentage=80.0,
                    message="Attack tree generation complete"
                ))
            else:
                attack_trees = {"attack_trees": self.state.attack_trees}
                context.add("attack_trees", attack_trees)
            
            # Emit TTC mapping start
            self.progress_emitter.emit(ProgressEvent(
                type=ProgressEventType.STAGE_START,
                stage="ttc_enrichment",
                percentage=70.0,
                message="Mapping attack trees to MITRE ATT&CK techniques"
            ))
            
            # Step 4.5: TTC Mapping
            if not self.state.mapping_complete:
                try:
                    self.state.advance_to(WorkflowStage.MAPPING)
                    num_trees = len(attack_trees.get('attack_trees', []))
                    self.logger.info(f"Starting TTC mapping for {num_trees} attack trees")
                    # Console output removed for cleaner display
                    
                    ttc_mapped = self.ttc_tool.run(
                        attack_trees=attack_trees,
                        bedrock_model=self.config.bedrock_model,
                        aws_profile=self.config.aws_profile
                    )
                    
                    # Log mapping summary
                    mapping_summary = ttc_mapped.get('mapping_summary', {})
                    total_mappings = mapping_summary.get('total_mappings', 0)
                    successful_mappings = mapping_summary.get('successful_mappings', 0)
                    self.logger.info(f"TTC mapping complete: {successful_mappings}/{total_mappings} mappings above threshold")
                    # Console output removed for cleaner display
                    
                    # Update attack_trees with mapped versions
                    attack_trees = ttc_mapped
                    self.state.mapped_trees = ttc_mapped.get("ttc_mapped_trees", [])
                    self.state.attack_trees = ttc_mapped.get("ttc_mapped_trees", [])
                    self.state.mapping_complete = True
                    self.state_manager.save_checkpoint(self.state)
                    context.add("attack_trees", attack_trees)
                    context.add("workflow_state", self.state.model_dump())
                    
                    # Emit TTC mapping complete
                    self.progress_emitter.emit(ProgressEvent(
                        type=ProgressEventType.STAGE_COMPLETE,
                        stage="ttc_enrichment",
                        percentage=85.0,
                        message="TTC mapping complete"
                    ))
                except Exception as ttc_error:
                    error_msg = f"TTC mapping failed: {str(ttc_error)}"
                    self.logger.error(error_msg)
                    self.logger.error(f"Traceback: {traceback.format_exc()}")
                    print(f"\n❌ TTC mapping error: {error_msg}")
                    print("Continuing workflow without TTC mappings...")
                    # Don't raise - continue workflow without mappings
                    self.state.mapping_complete = True
            
            # Emit summary start
            self.progress_emitter.emit(ProgressEvent(
                type=ProgressEventType.STAGE_START,
                stage="summary",
                percentage=85.0,
                message="Generating analysis report"
            ))
            
            # Step 5: Generate summary
            if not self.state.summary_complete:
                try:
                    self.state.advance_to(WorkflowStage.SUMMARY)
                    summary = self.summary_tool.run(
                        attack_trees=attack_trees,
                        extracted_info=extraction_result,
                        output_dir=str(output_dir)
                    )
                    self.state.output_files = summary.get("output_files", [])
                    self.state.summary_complete = True
                    self.state.advance_to(WorkflowStage.COMPLETE)
                    self.state_manager.save_checkpoint(self.state)
                    context.add("summary", summary)
                    context.add("workflow_state", self.state.model_dump())
                    
                    # Emit workflow complete
                    self.progress_emitter.emit(ProgressEvent(
                        type=ProgressEventType.STAGE_COMPLETE,
                        stage="complete",
                        percentage=100.0,
                        message="Workflow complete"
                    ))
                    
                    # Archive and cleanup completed state
                    self.state_manager.archive_checkpoint("latest")
                    self.state_manager.cleanup_completed_states()
                except Exception as summary_error:
                    error_msg = f"Summary generation failed: {str(summary_error)}"
                    self.logger.error(error_msg)
                    self.logger.error(f"Traceback: {traceback.format_exc()}")
                    raise Exception(error_msg) from summary_error
            else:
                summary = {"output_files": self.state.output_files}
                context.add("summary", summary)
            
            return {
                "status": "success",
                "context": context.to_dict(),
                "output_files": summary.get("output_files", []),
                "output_directory": str(output_dir),
                "application_name": app_name
            }
            
        except Exception as e:
            # Log the full error with traceback
            error_details = f"Workflow failed at stage {self.state.current_stage if self.state else 'unknown'}: {str(e)}"
            self.logger.error(error_details)
            self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            
            # Also print to console for visibility
            print(f"\n❌ Error: {error_details}")
            print(f"See log file for full traceback")
            
            return {
                "status": "error",
                "error": error_details,
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "stage": self.state.current_stage if self.state else "unknown",
                "context": context.to_dict()
            }
    


def run_threatforest(project_path: str, **kwargs) -> Dict[str, Any]:
    """Main entry point for running ThreatForest (SYNCHRONOUS)"""
    config = ThreatForestConfig(
        project_path=Path(project_path),
        **kwargs
    )
    
    orchestrator = ThreatForestOrchestrator(config)
    return orchestrator.execute_workflow()
