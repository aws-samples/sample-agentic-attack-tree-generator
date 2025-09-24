"""
Orchestrator Agent for ThreatForest multi-agent system.

This module implements the main orchestrator that coordinates all agents
in the ThreatForest workflow using the Strand framework.
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..models import ContextInformation, ThreatStatement, AttackTree, ValidationStatus
from ..utils.bedrock_client import BedrockClient
from ..utils.file_manager import FileManager
from ..error_handler import ErrorHandler, ErrorCategory, ErrorSeverity
from .context_detection import ContextDetectionAgent
from .information_extraction import InformationExtractionAgent
from .attack_tree_generator import AttackTreeGeneratorAgent
from .ttc_mapping import TTCMappingAgent


logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """
    Main orchestrator agent that manages the ThreatForest workflow.
    
    Coordinates all specialized agents and manages the complete pipeline
    from context detection through attack tree generation and enhancement.
    """
    
    def __init__(
        self,
        bedrock_client: BedrockClient,
        file_manager: FileManager,
        config: Dict[str, Any],
        error_handler: Optional[ErrorHandler] = None
    ):
        """
        Initialize the orchestrator with required dependencies.
        
        Args:
            bedrock_client: Client for Amazon Bedrock API
            file_manager: File I/O operations manager
            config: Configuration dictionary
            error_handler: Optional error handler instance
        """
        self.bedrock_client = bedrock_client
        self.file_manager = file_manager
        self.config = config
        self.error_handler = error_handler or ErrorHandler(logger)
        
        # Initialize agents
        from ..config import FileConfig
        file_config = FileConfig()  # Use default file config
        
        self.context_agent = ContextDetectionAgent(file_config)
        self.extraction_agent = InformationExtractionAgent(bedrock_client)
        self.generator_agent = AttackTreeGeneratorAgent(bedrock_client)
        # Initialize STIX processor for TTC mapping
        from ..utils.stix_processor import STIXProcessor
        aaf_bundle_path = config.get('ttc', {}).get('aaf_bundle_path', './aaf-bundle.json')
        stix_processor = STIXProcessor(aaf_bundle_path)
        
        self.mapping_agent = TTCMappingAgent(
            stix_processor=stix_processor,
            alignment_threshold=config.get('ttc', {}).get('alignment_threshold', 0.8)
        )
        
        # Workflow state
        self.workflow_state = {
            'started_at': None,
            'completed_at': None,
            'current_phase': None,
            'errors': [],
            'results': {}
        }
        
        logger.info("Orchestrator agent initialized")
    
    async def execute_workflow(self, directory_path: str) -> Dict[str, Any]:
        """
        Execute the complete ThreatForest workflow.
        
        Args:
            directory_path: Path to the directory to analyze
            
        Returns:
            Dictionary containing workflow results and metadata
        """
        self.workflow_state['started_at'] = datetime.now()
        logger.info(f"Starting ThreatForest workflow for directory: {directory_path}")
        
        try:
            # Phase 1: Context Detection
            await self._execute_phase("context_detection", directory_path)
            
            # Phase 2: Information Extraction
            await self._execute_phase("information_extraction")
            
            # Phase 3: Attack Tree Generation
            await self._execute_phase("attack_tree_generation")
            
            # Phase 4: TTC Mapping Enhancement
            await self._execute_phase("ttc_mapping")
            
            # Phase 5: Summary Generation
            await self._execute_phase("summary_generation")
            
            self.workflow_state['completed_at'] = datetime.now()
            logger.info("ThreatForest workflow completed successfully")
            
            return self._generate_workflow_summary()
            
        except Exception as e:
            error_context = self.error_handler.handle_workflow_error(
                e, self.workflow_state.get('current_phase', 'unknown')
            )
            
            self.workflow_state['errors'].append({
                'phase': self.workflow_state.get('current_phase', 'unknown'),
                'error': str(e),
                'error_context': error_context.to_dict(),
                'timestamp': datetime.now()
            })
            
            # Attempt to save partial results
            await self._save_partial_results()
            raise
    
    async def _execute_phase(self, phase_name: str, *args) -> None:
        """
        Execute a specific workflow phase with error handling.
        
        Args:
            phase_name: Name of the phase to execute
            *args: Arguments to pass to the phase handler
        """
        self.workflow_state['current_phase'] = phase_name
        logger.info(f"Executing phase: {phase_name}")
        
        try:
            phase_handler = getattr(self, f"_phase_{phase_name}")
            await phase_handler(*args)
            logger.info(f"Phase {phase_name} completed successfully")
            
        except Exception as e:
            error_context = self.error_handler.handle_workflow_error(e, phase_name)
            
            self.workflow_state['errors'].append({
                'phase': phase_name,
                'error': str(e),
                'error_context': error_context.to_dict(),
                'timestamp': datetime.now()
            })
            
            # Determine if we can continue with remaining phases
            if self._is_critical_phase(phase_name) or error_context.severity == ErrorSeverity.CRITICAL:
                logger.critical(f"Critical phase {phase_name} failed, stopping workflow")
                raise
            else:
                logger.warning(f"Continuing workflow despite {phase_name} failure")
                # Apply graceful degradation if possible
                await self._apply_graceful_degradation(phase_name, error_context)
    
    async def _phase_context_detection(self, directory_path: str) -> None:
        """Execute context detection phase."""
        try:
            # Note: scan_directory is synchronous, not async
            context_files = self.context_agent.scan_directory(directory_path)
            
            # Handle both ContextScanResult and list return types (for backward compatibility)
            if hasattr(context_files, 'detected_files'):
                # ContextScanResult object
                detected_files = context_files.detected_files
            else:
                # List of files (for tests)
                detected_files = context_files
            
            if not detected_files:
                error_context = self.error_handler.handle_error(
                    ValueError(f"No context files found in directory: {directory_path}"),
                    ErrorCategory.FILE_SYSTEM,
                    {"directory_path": directory_path},
                    "context detection"
                )
                raise ValueError(f"No context files found in directory: {directory_path}")
            
            self.workflow_state['results']['context_files'] = detected_files
            logger.info(f"Found {len(detected_files)} context files")
            
        except Exception as e:
            self.error_handler.handle_agent_error(e, "context_detection", "scan_directory")
            raise
    
    async def _phase_information_extraction(self) -> None:
        """Execute information extraction phase."""
        context_files = self.workflow_state['results']['context_files']
        
        # Extract information from context files
        extracted_info = self.extraction_agent.extract_information(context_files)
        
        # Validate with user (in a real implementation, this would be interactive)
        # For now, we'll assume validation passes
        validated_info = await self._validate_extracted_information(extracted_info)
        
        # Save validated information
        info_file = self.file_manager.write_context_information(validated_info)
        
        self.workflow_state['results']['context_information'] = validated_info
        self.workflow_state['results']['info_file'] = info_file
        logger.info("Information extraction completed")
    
    async def _phase_attack_tree_generation(self) -> None:
        """Execute attack tree generation phase."""
        context_files = self.workflow_state['results']['context_files']
        context_info = self.workflow_state['results']['context_information']
        
        # Find threat statement files
        threat_files = [f for f in context_files if 'threat' in f.name.lower()]
        
        if not threat_files:
            logger.warning("No threat statement files found")
            self.workflow_state['results']['attack_trees'] = []
            return
        
        attack_trees = []
        
        for threat_file in threat_files:
            try:
                # Parse threat statements from file
                threat_statements = await self._parse_threat_statements(threat_file)
                
                # Filter for high-severity threats only
                high_severity_threats = [
                    t for t in threat_statements 
                    if t.severity.lower() == 'high'
                ]
                
                if not high_severity_threats:
                    logger.info(f"No high-severity threats found in {threat_file.name}")
                    continue
                
                # Generate attack trees for high-severity threats
                for threat in high_severity_threats:
                    try:
                        attack_tree = self.generator_agent.generate_attack_tree(
                            threat, context_info
                        )
                        attack_trees.append(attack_tree)
                        
                        # Save attack tree to file
                        tree_file = self.file_manager.write_attack_tree(attack_tree)
                        logger.info(f"Generated attack tree: {tree_file}")
                        
                    except Exception as tree_error:
                        error_context = self.error_handler.handle_agent_error(
                            tree_error, "attack_tree_generator", f"threat_{threat.id}"
                        )
                        logger.warning(f"Failed to generate attack tree for threat {threat.id}, continuing with others")
                        continue
                    
            except Exception as e:
                error_context = self.error_handler.handle_file_error(e, str(threat_file))
                logger.error(f"Failed to process threat file {threat_file.name}: {str(e)}")
                continue
        
        self.workflow_state['results']['attack_trees'] = attack_trees
        logger.info(f"Generated {len(attack_trees)} attack trees")
    
    async def _phase_ttc_mapping(self) -> None:
        """Execute TTC mapping enhancement phase."""
        attack_trees = self.workflow_state['results'].get('attack_trees', [])
        
        if not attack_trees:
            logger.warning("No attack trees available for TTC mapping")
            return
        
        enhanced_trees = []
        
        for attack_tree in attack_trees:
            try:
                enhanced_tree = self.mapping_agent.enhance_attack_tree(attack_tree)
                enhanced_trees.append(enhanced_tree)
                
                # Save enhanced attack tree
                tree_file = self.file_manager.write_attack_tree(enhanced_tree)
                logger.info(f"Enhanced attack tree with TTC mapping: {tree_file}")
                
            except Exception as e:
                error_context = self.error_handler.handle_agent_error(
                    e, "ttc_mapping", f"tree_{attack_tree.threat_id}"
                )
                logger.warning(f"Failed to enhance attack tree {attack_tree.threat_id}, keeping original")
                # Keep original tree if enhancement fails
                enhanced_trees.append(attack_tree)
        
        self.workflow_state['results']['attack_trees'] = enhanced_trees
        logger.info("TTC mapping enhancement completed")
    
    async def _phase_summary_generation(self) -> None:
        """Execute summary generation phase."""
        attack_trees = self.workflow_state['results'].get('attack_trees', [])
        context_info = self.workflow_state['results'].get('context_information')
        
        # Generate comprehensive summary
        summary = await self._generate_analysis_summary(attack_trees, context_info)
        
        # Save summary to file
        summary_file = self.file_manager.generate_summary_report(summary)
        
        self.workflow_state['results']['summary_file'] = summary_file
        logger.info(f"Generated summary report: {summary_file}")
    
    async def _validate_extracted_information(
        self, 
        extracted_info: ContextInformation
    ) -> ContextInformation:
        """
        Validate extracted information with user.
        
        In a real implementation, this would present the information to the user
        for validation and allow modifications. For now, we'll return as-is.
        
        Args:
            extracted_info: Information extracted from context files
            
        Returns:
            Validated context information
        """
        # TODO: Implement interactive validation
        extracted_info.validation_status = ValidationStatus.APPROVED
        return extracted_info
    
    async def _parse_threat_statements(self, threat_file: Path) -> List[ThreatStatement]:
        """
        Parse threat statements from a file.
        
        Args:
            threat_file: Path to threat statement file
            
        Returns:
            List of parsed threat statements
        """
        content = self.file_manager.read_context_file(threat_file)
        
        # This is a simplified parser - in reality, you'd need to handle
        # various formats (JSON, YAML, structured markdown, etc.)
        threat_statements = []
        
        if threat_file.suffix.lower() == '.json':
            import json
            data = json.loads(content)
            
            if isinstance(data, list):
                for item in data:
                    threat_statements.append(ThreatStatement(**item))
            elif isinstance(data, dict) and 'threats' in data:
                for item in data['threats']:
                    threat_statements.append(ThreatStatement(**item))
        
        return threat_statements
    
    async def _generate_analysis_summary(
        self, 
        attack_trees: List[AttackTree],
        context_info: Optional[ContextInformation]
    ) -> Dict[str, Any]:
        """
        Generate comprehensive analysis summary.
        
        Args:
            attack_trees: Generated attack trees
            context_info: Extracted context information
            
        Returns:
            Summary data dictionary
        """
        summary = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_attack_trees': len(attack_trees),
                'workflow_duration': self._calculate_workflow_duration(),
                'errors_encountered': len(self.workflow_state['errors'])
            },
            'context_summary': {},
            'threat_analysis': [],
            'files_generated': []
        }
        
        if context_info:
            summary['context_summary'] = {
                'technologies': context_info.technologies,
                'programming_languages': context_info.programming_languages,
                'sector': context_info.sector,
                'security_objectives': context_info.security_objectives
            }
        
        for tree in attack_trees:
            summary['threat_analysis'].append({
                'threat_id': tree.threat_id,
                'title': tree.title,
                'attack_steps_count': len(tree.attack_steps),
                'ttc_mappings_count': len(tree.ttc_mappings),
                'file_path': f"{tree.threat_id}_attack_tree.mmd"
            })
        
        return summary
    
    def _calculate_workflow_duration(self) -> Optional[float]:
        """Calculate workflow execution duration in seconds."""
        if self.workflow_state['started_at'] and self.workflow_state['completed_at']:
            duration = self.workflow_state['completed_at'] - self.workflow_state['started_at']
            return duration.total_seconds()
        return None
    
    def _is_critical_phase(self, phase_name: str) -> bool:
        """Determine if a phase failure should stop the entire workflow."""
        critical_phases = {'context_detection', 'information_extraction'}
        return phase_name in critical_phases
    
    async def _save_partial_results(self) -> None:
        """Save partial results when workflow fails."""
        try:
            results = self.workflow_state['results']
            
            # Save any attack trees that were generated
            if 'attack_trees' in results:
                for tree in results['attack_trees']:
                    self.file_manager.write_attack_tree(tree)
            
            # Save extracted information if available
            if 'context_information' in results:
                self.file_manager.write_context_information(
                    results['context_information']
                )
            
            logger.info("Partial results saved successfully")
            
        except Exception as e:
            self.error_handler.handle_file_error(e, "partial_results")
            logger.error(f"Failed to save partial results: {str(e)}")
    
    def _generate_workflow_summary(self) -> Dict[str, Any]:
        """Generate final workflow summary."""
        error_summary = self.error_handler.get_error_summary()
        
        return {
            'status': 'completed' if not self.workflow_state['errors'] else 'completed_with_errors',
            'started_at': self.workflow_state['started_at'].isoformat(),
            'completed_at': self.workflow_state['completed_at'].isoformat(),
            'duration_seconds': self._calculate_workflow_duration(),
            'phases_completed': list(self.workflow_state['results'].keys()),
            'errors': self.workflow_state['errors'],
            'error_summary': error_summary,
            'results': self.workflow_state['results']
        }
    
    async def _apply_graceful_degradation(self, phase_name: str, error_context) -> None:
        """
        Apply graceful degradation strategies for non-critical phase failures.
        
        Args:
            phase_name: Name of the failed phase
            error_context: Error context from the failure
        """
        logger.info(f"Applying graceful degradation for phase: {phase_name}")
        
        if phase_name == "ttc_mapping":
            # TTC mapping failure - continue with unenhanced attack trees
            logger.info("TTC mapping failed, continuing with unenhanced attack trees")
            
        elif phase_name == "attack_tree_generation":
            # Attack tree generation failure - create empty results
            logger.info("Attack tree generation failed, creating empty results")
            self.workflow_state['results']['attack_trees'] = []
            
        elif phase_name == "summary_generation":
            # Summary generation failure - create basic summary
            logger.info("Summary generation failed, creating basic summary")
            basic_summary = {
                'analysis_metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'status': 'partial_failure',
                    'error': str(error_context.message)
                }
            }
            self.workflow_state['results']['summary'] = basic_summary