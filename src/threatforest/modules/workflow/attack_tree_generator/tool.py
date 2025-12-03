"""Main Attack Tree Generator Tool - Orchestrates tree generation"""
from typing import Dict, List, Any, Optional
from ...utils.logger import ThreatForestLogger
from ...core import BaseAgent
from ...agents.tree_generator_agent import TreeGenerator
from .state_manager import StateManager

# Import progress types if available
try:
    from ...core import ProgressEmitter, ProgressEvent, ProgressEventType
    PROGRESS_AVAILABLE = True
except ImportError:
    PROGRESS_AVAILABLE = False


class AttackTreeGeneratorTool(BaseAgent):
    """Tool for generating attack trees in Mermaid format using Strands
    
    Fully synchronous implementation with modular architecture.
    """
    
    def __init__(self, console=None):
        self.name = "attack_tree_generator"
        self.description = "Generate attack trees in Mermaid format for high severity threats"
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        self.console = console  # Optional Rich console for progress display
        
        # Initialize modules
        self.generator = TreeGenerator(self.logger)
        self.state_manager = StateManager(self.logger)
    
    def run(self, threat_statements: List[Dict[str, Any]], 
               extracted_info: Dict[str, Any], bedrock_model: str,
               aws_profile: Optional[str] = None,
               existing_status: Optional[Dict[str, str]] = None,
               output_dir: Optional[str] = None,
               progress_emitter: Optional['ProgressEmitter'] = None) -> Dict[str, Any]:
        """Execute attack tree generation (fully synchronous)
        
        Args:
            threat_statements: List of threat dicts
            extracted_info: Project information
            bedrock_model: Bedrock model ID
            aws_profile: Optional AWS profile
            existing_status: Optional existing threat statuses
            output_dir: Optional output directory for state file
            progress_emitter: Optional progress emitter
            
        Returns:
            Dict with attack_trees, threat_status, generation_summary
        """
        # Load existing state if not provided
        if existing_status is None and output_dir:
            existing_status = self.state_manager.load_state(output_dir)
        
        # Filter for high severity threats
        high_threats = self._filter_high_severity_threats(threat_statements)
        
        if not high_threats:
            return self._no_threats_result()
        
        # Filter out already successful threats
        threats_to_process, skipped_count = self.state_manager.filter_threats_to_process(
            high_threats, existing_status
        )
        
        if skipped_count > 0:
            self.logger.info(f"Skipping {skipped_count} already successful threats")
        
        if not threats_to_process:
            return self._all_complete_result(high_threats, existing_status)
        
        self.logger.info(f"Generating attack trees for {len(threats_to_process)} threats")
        
        # Process threats with optional progress bar
        attack_trees = []
        threat_status = dict(existing_status or {})
        
        if self.console:
            self._process_with_progress_bar(
                threats_to_process, extracted_info, bedrock_model,
                attack_trees, threat_status, progress_emitter
            )
        else:
            self._process_without_progress_bar(
                threats_to_process, extracted_info, bedrock_model,
                attack_trees, threat_status, progress_emitter
            )
        
        # Calculate results
        successful = len([t for t in attack_trees if "mermaid_code" in t])
        failed = len([t for t in attack_trees if "error" in t])
        
        self.logger.info(f"Attack tree generation complete: {successful} successful, {failed} failed")
        
        # Save state if output_dir provided
        if output_dir:
            self.state_manager.save_state(output_dir, threat_status)
        
        return {
            "attack_trees": attack_trees,
            "threat_status": threat_status,
            "generation_summary": {
                "total_high_threats": len(high_threats),
                "processed_this_run": len(threats_to_process),
                "skipped_successful": skipped_count,
                "successful_generations": successful,
                "failed_generations": failed
            }
        }
    
    def _filter_high_severity_threats(self, threat_statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter for high severity threats only"""
        # Try "severity" field first
        high_threats = [t for t in threat_statements if t.get("severity") == "High"]
        
        # If no threats with "severity", try "priority" field
        if not high_threats:
            self.logger.debug("No threats with severity='High', trying priority field")
            high_threats = [t for t in threat_statements if t.get("priority") == "High"]
        
        return high_threats
    
    def _process_with_progress_bar(self, threats: List, extracted_info: Dict, bedrock_model: str,
                                   attack_trees: List, threat_status: Dict, progress_emitter):
        """Process threats with Rich progress bar"""
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Generating attack trees...", total=len(threats))
            
            for idx, threat in enumerate(threats, 1):
                threat_id = threat.get("id", "unknown")
                category = threat.get('category', 'Unknown')
                # Show friendly name: "Threat X (Category)" instead of UUID
                progress.update(task, description=f"[cyan]Processing Threat {idx} ({category})")
                
                self._process_single_threat(
                    threat, idx, len(threats), extracted_info, bedrock_model,
                    attack_trees, threat_status, progress_emitter
                )
                
                progress.advance(task)
    
    def _process_without_progress_bar(self, threats: List, extracted_info: Dict, bedrock_model: str,
                                      attack_trees: List, threat_status: Dict, progress_emitter):
        """Process threats without progress bar"""
        for idx, threat in enumerate(threats, 1):
            threat_id = threat.get("id", "unknown")
            self.logger.info(f"Processing threat {idx}/{len(threats)}: {threat_id}")
            
            self._process_single_threat(
                threat, idx, len(threats), extracted_info, bedrock_model,
                attack_trees, threat_status, progress_emitter
            )
    
    def _process_single_threat(self, threat: Dict, idx: int, total: int,
                              extracted_info: Dict, bedrock_model: str,
                              attack_trees: List, threat_status: Dict,
                              progress_emitter):
        """Process a single threat (synchronous)"""
        threat_id = threat.get("id", "unknown")
        
        # Emit progress if available
        if progress_emitter and PROGRESS_AVAILABLE:
            progress_emitter.emit(ProgressEvent(
                type=ProgressEventType.THREAT_START,
                stage="tree_generation",
                percentage=40.0 + ((idx - 1) / total) * 40.0,
                message=f"Generating attack tree for {threat_id}",
                details={"threat_id": threat_id, "index": idx, "total": total}
            ))
        
        try:
            # Generate tree (synchronous Strands call)
            tree = self.generator.generate_attack_tree(threat, extracted_info, bedrock_model)
            
            if tree:
                attack_trees.append(tree)
                
                # Mark success/failure based on result
                if "mermaid_code" in tree:
                    threat_status[threat_id] = "success"
                    self.logger.info(f"✓ Successfully generated attack tree for {threat_id}")
                    
                    if progress_emitter and PROGRESS_AVAILABLE:
                        progress_emitter.emit(ProgressEvent(
                            type=ProgressEventType.THREAT_COMPLETE,
                            stage="tree_generation",
                            percentage=40.0 + (idx / total) * 40.0,
                            message=f"Completed attack tree for {threat_id}",
                            details={"threat_id": threat_id, "success": True}
                        ))
                else:
                    threat_status[threat_id] = "failed"
                    self.logger.error(f"✗ {threat_id}: {tree.get('error', 'Unknown error')}")
                    
                    if progress_emitter and PROGRESS_AVAILABLE:
                        progress_emitter.emit(ProgressEvent(
                            type=ProgressEventType.ERROR,
                            stage="tree_generation",
                            percentage=40.0 + (idx / total) * 40.0,
                            message=f"Failed to generate attack tree for {threat_id}",
                            details={"threat_id": threat_id, "error": tree.get('error')}
                        ))
                
        except Exception as e:
            error_msg = f"Failed to generate attack tree: {str(e)}"
            self.logger.error(f"✗ {threat_id}: {error_msg}")
            threat_status[threat_id] = "failed"
            attack_trees.append({"threat_id": threat_id, "error": error_msg})
            
            if progress_emitter and PROGRESS_AVAILABLE:
                progress_emitter.emit(ProgressEvent(
                    type=ProgressEventType.ERROR,
                    stage="tree_generation",
                    percentage=40.0 + (idx / total) * 40.0,
                    message=f"Failed to generate attack tree for {threat_id}",
                    details={"threat_id": threat_id, "error": error_msg}
                ))
    
    def _no_threats_result(self) -> Dict[str, Any]:
        """Return result when no high severity threats found"""
        self.logger.info("No high severity threats found")
        return {
            "attack_trees": [],
            "threat_status": {},
            "message": "No high severity threats found for attack tree generation"
        }
    
    def _all_complete_result(self, high_threats: List, existing_status: Dict) -> Dict[str, Any]:
        """Return result when all threats already processed"""
        self.logger.info("All threats already have successful attack trees")
        return {
            "attack_trees": [],
            "threat_status": existing_status,
            "generation_summary": {
                "total_high_threats": len(high_threats),
                "processed_this_run": 0,
                "skipped_successful": len(high_threats),
                "successful_generations": 0,
                "failed_generations": 0,
                "all_complete": True
            },
            "message": "All threats already processed successfully. Use existing results or delete state file to regenerate."
        }
