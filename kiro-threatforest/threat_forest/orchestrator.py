"""
Main orchestrator for ThreatForest application.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional

from .config import ThreatForestConfig
from .file_scanner import FileScanner, ScanResult
from .context_parser import ContextParser, ParsedContent
from .info_extractor import InfoExtractor
from .user_validator import UserValidator
from .info_saver import InfoSaver
from .threat_parser import ThreatParser
from .llm_client import LLMClient
from .attack_tree_generator import AttackTreeGenerator
from .stix_processor import STIXProcessor, STIXMapper
from .tree_enhancer import TreeEnhancer
from .summary_generator import SummaryGenerator
from .models import ApplicationInfo, ThreatStatement, AttackTree
from .exceptions import ThreatForestError, ConfigurationError, STIXProcessingError
from .utils import get_logger, ensure_output_directory


class ThreatForestOrchestrator:
    """Main orchestrator that coordinates all ThreatForest components."""
    
    def __init__(
        self,
        input_directory: str,
        output_directory: str,
        config: ThreatForestConfig,
        skip_user_validation: bool = False,
        high_threats_only: bool = True
    ):
        self.input_directory = Path(input_directory)
        self.output_directory = Path(output_directory)
        self.config = config
        self.skip_user_validation = skip_user_validation
        self.high_threats_only = high_threats_only
        
        self.logger = get_logger(__name__)
        
        # Initialize components
        self.file_scanner = FileScanner()
        self.context_parser = ContextParser()
        self.user_validator = UserValidator()
        self.info_saver = InfoSaver(str(output_directory))
        
        # Initialize LLM client
        try:
            self.llm_client = LLMClient(config.llm)
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize LLM client: {e}")
        
        # Initialize components that depend on LLM
        self.info_extractor = InfoExtractor(self.llm_client)
        self.threat_parser = ThreatParser(self.llm_client)
        self.attack_tree_generator = AttackTreeGenerator(self.llm_client, str(output_directory))
        self.summary_generator = SummaryGenerator(str(output_directory))
        
        # Initialize STIX components if enabled
        self.stix_processor = None
        self.stix_mapper = None
        self.tree_enhancer = None
        
        if config.stix.enable_mapping:
            try:
                self.stix_processor = STIXProcessor(config.stix.bundle_path)
                self.stix_mapper = STIXMapper(self.stix_processor, config.stix.confidence_threshold)
                self.tree_enhancer = TreeEnhancer(self.stix_processor, self.stix_mapper)
                self.logger.info("STIX processing enabled")
            except STIXProcessingError as e:
                self.logger.warning(f"STIX processing disabled due to error: {e}")
                config.stix.enable_mapping = False
    
    def run(self) -> bool:
        """
        Run the complete ThreatForest analysis pipeline.
        
        Returns:
            True if analysis completed successfully, False otherwise
        """
        try:
            self.logger.info("Starting ThreatForest analysis pipeline")
            
            # Step 1: Scan directory for context files
            scan_result = self._scan_directory()
            if not self._validate_scan_result(scan_result):
                return False
            
            # Step 2: Parse context files
            parsed_files = self._parse_context_files(scan_result)
            if not parsed_files:
                self.logger.error("No context files could be parsed")
                return False
            
            # Store for statistics
            self._parsed_files = parsed_files
            
            # Step 3: Extract and validate application information
            app_info = self._extract_and_validate_info(parsed_files)
            if not app_info:
                return False
            
            # Step 4: Save validated information
            self._save_application_info(app_info)
            
            # Step 5: Parse and filter threat statements
            threats = self._parse_threats(parsed_files)
            if not threats:
                self.logger.warning("No threats found to process")
                return True  # Not an error, just no threats to process
            
            # Step 6: Generate attack trees
            attack_trees = self._generate_attack_trees(threats, app_info)
            
            # Step 7: Enhance attack trees with MITRE ATT&CK (if enabled)
            if self.tree_enhancer and attack_trees:
                attack_trees = self._enhance_attack_trees(attack_trees)
            
            # Step 8: Generate comprehensive summary
            self._generate_summary(app_info, threats, attack_trees)
            
            self.logger.info("ThreatForest analysis completed successfully")
            return True
            
        except ThreatForestError as e:
            self.logger.error(f"ThreatForest analysis failed: {e}")
            return False
        except Exception as e:
            self.logger.critical(f"Unexpected error during analysis: {e}", exc_info=True)
            return False
    
    def _scan_directory(self) -> ScanResult:
        """Scan input directory for context files."""
        self.logger.info(f"Scanning directory: {self.input_directory}")
        
        scan_result = self.file_scanner.scan_directory(str(self.input_directory))
        
        self.logger.info(f"Found {len(scan_result.files_found)} context files")
        
        # Log found files
        for file_info in scan_result.files_found:
            self.logger.debug(f"Found {file_info.file_type.value}: {file_info.path.name}")
        
        return scan_result
    
    def _validate_scan_result(self, scan_result: ScanResult) -> bool:
        """Validate scan results and provide guidance if needed."""
        # Check for scan errors
        if scan_result.scan_errors:
            self.logger.warning("Scan errors encountered:")
            for error in scan_result.scan_errors:
                self.logger.warning(f"  - {error}")
        
        # Validate files
        validation_errors = self.file_scanner.validate_files(scan_result)
        if validation_errors:
            self.logger.error("File validation errors:")
            for error in validation_errors:
                self.logger.error(f"  - {error}")
            return False
        
        # Check for required files
        if not scan_result.has_required_files:
            self.logger.error("Missing required files:")
            guidance = self.file_scanner.get_missing_files_guidance(scan_result.missing_file_types)
            for guide in guidance:
                self.logger.error(f"  - {guide}")
            return False
        
        return True
    
    def _parse_context_files(self, scan_result: ScanResult) -> List[ParsedContent]:
        """Parse all discovered context files."""
        self.logger.info("Parsing context files")
        
        parsed_files = self.context_parser.parse_files(scan_result.files_found)
        
        if not parsed_files:
            self.logger.error("No files could be parsed successfully")
            return []
        
        # Log parsing summary
        content_summary = self.context_parser.get_content_summary(parsed_files)
        self.logger.info(f"Parsed {content_summary['total_files']} files, "
                        f"total size: {content_summary['total_size']} characters")
        
        return parsed_files
    
    def _extract_and_validate_info(self, parsed_files: List[ParsedContent]) -> Optional[ApplicationInfo]:
        """Extract and validate application information."""
        self.logger.info("Extracting application information")
        
        try:
            # Extract information using LLM
            app_info = self.info_extractor.extract_application_info(parsed_files)
            
            # Enhance with metadata
            app_info = self.info_extractor.enhance_with_metadata(app_info, parsed_files)
            
            # Validate with user (unless skipped)
            if self.skip_user_validation:
                app_info = self.user_validator.skip_validation(app_info)
            else:
                app_info = self.user_validator.validate_application_info(app_info)
            
            return app_info
            
        except Exception as e:
            self.logger.error(f"Failed to extract application information: {e}")
            return None
    
    def _save_application_info(self, app_info: ApplicationInfo) -> None:
        """Save validated application information."""
        self.logger.info("Saving application information")
        
        try:
            output_file = self.info_saver.save_application_info(app_info)
            self.logger.info(f"Application information saved to: {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save application information: {e}")
            raise
    
    def _parse_threats(self, parsed_files: List[ParsedContent]) -> List[ThreatStatement]:
        """Parse and filter threat statements."""
        self.logger.info("Parsing threat statements")
        
        try:
            # Parse all threats
            all_threats = self.threat_parser.parse_threats(parsed_files)
            
            if not all_threats:
                self.logger.warning("No threat statements found in context files")
                return []
            
            # Get threat summary
            threat_summary = self.threat_parser.get_threat_summary(all_threats)
            self.logger.info(f"Threat summary: {threat_summary}")
            
            # Filter for high-severity threats if requested
            if self.high_threats_only:
                filtered_threats = self.threat_parser.filter_high_severity_threats(all_threats)
                
                if not filtered_threats:
                    self.logger.warning(
                        f"No high-severity threats found out of {len(all_threats)} total threats. "
                        "Consider reviewing threat severity detection or running with --no-high-threats-only"
                    )
                
                return filtered_threats
            else:
                return all_threats
                
        except Exception as e:
            self.logger.error(f"Failed to parse threats: {e}")
            return []
    
    def _generate_attack_trees(self, threats: List[ThreatStatement], app_info: ApplicationInfo) -> List[AttackTree]:
        """Generate attack trees for threats."""
        if not threats:
            self.logger.warning("No threats to generate attack trees for")
            return []
        
        self.logger.info(f"Generating attack trees for {len(threats)} threats")
        
        try:
            attack_trees = self.attack_tree_generator.generate_attack_trees(threats, app_info)
            
            # Log generation summary
            summary = self.attack_tree_generator.get_generation_summary(attack_trees)
            self.logger.info(f"Attack tree generation summary: {summary}")
            
            return attack_trees
            
        except Exception as e:
            self.logger.error(f"Failed to generate attack trees: {e}")
            return []
    
    def _enhance_attack_trees(self, attack_trees: List[AttackTree]) -> List[AttackTree]:
        """Enhance attack trees with MITRE ATT&CK mappings."""
        if not self.tree_enhancer:
            self.logger.warning("Tree enhancer not available, skipping enhancement")
            return attack_trees
        
        self.logger.info("Enhancing attack trees with MITRE ATT&CK mappings")
        
        try:
            enhanced_trees = self.tree_enhancer.enhance_attack_trees(attack_trees)
            
            # Log enhancement summary
            summary = self.tree_enhancer.get_enhancement_summary(enhanced_trees)
            self.logger.info(f"Enhancement summary: {summary}")
            
            return enhanced_trees
            
        except Exception as e:
            self.logger.error(f"Failed to enhance attack trees: {e}")
            return attack_trees
    
    def _generate_summary(
        self, 
        app_info: ApplicationInfo, 
        threats: List[ThreatStatement], 
        attack_trees: List[AttackTree]
    ) -> None:
        """Generate comprehensive summary reports."""
        self.logger.info("Generating summary reports")
        
        try:
            # Collect processing statistics
            processing_stats = {
                'files_processed': len(getattr(self, '_parsed_files', [])),
                'threats_found': len(threats),
                'attack_trees_generated': len(attack_trees),
                'stix_enabled': self.config.stix.enable_mapping,
                'stix_techniques_available': len(self.stix_processor.techniques) if self.stix_processor else 0
            }
            
            # Generate markdown summary
            summary_file = self.summary_generator.generate_summary(
                app_info, threats, attack_trees, processing_stats
            )
            
            # Generate JSON summary
            json_summary_file = self.summary_generator.generate_json_summary(
                app_info, threats, attack_trees, processing_stats
            )
            
            self.logger.info(f"Summary reports generated: {summary_file}, {json_summary_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate summary: {e}")
            raise