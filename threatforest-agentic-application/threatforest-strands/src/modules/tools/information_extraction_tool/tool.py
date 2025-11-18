"""Main Information Extraction Tool - Orchestrates all extraction operations"""
from typing import Dict, List, Any, Optional
from ...utils.logger import ThreatForestLogger
from ...core import BaseAgent
from ...parsers import (
    ParserChain, JSONThreatParser, YAMLThreatParser,
    MarkdownThreatParser, ThreatComposerParser
)
from .file_utils import is_text_file, is_binary_file
from .threat_formatter import ThreatFormatter
from .threat_parser import ThreatParser
from .project_extractor import ProjectExtractor
from .threat_generator import ThreatGenerator


class InformationExtractionTool(BaseAgent):
    """Tool for extracting key information from context files
    
    Orchestrates threat parsing, project metadata extraction, and threat generation
    using specialized modules for each responsibility.
    """
    
    def __init__(self):
        self.name = "information_extraction"
        self.description = "Extract key information including threat statements, technologies, and security objectives"
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Initialize parser chain with priority ordering
        self.parser_chain = ParserChain()
        self.parser_chain.register(ThreatComposerParser(), priority=4)
        self.parser_chain.register(JSONThreatParser(), priority=3)
        self.parser_chain.register(YAMLThreatParser(), priority=2)
        self.parser_chain.register(MarkdownThreatParser(), priority=1)
        self.logger.debug("Parser chain initialized with 4 parsers")
        
        # Initialize specialized modules
        self.formatter = ThreatFormatter(self.logger)
        self.parser = ThreatParser(self.logger, self.parser_chain, self.formatter)
        self.project_extractor = ProjectExtractor(self.logger)
        self.threat_generator = ThreatGenerator(self.logger, self.formatter)
    
    def run(self, context_files: Dict[str, Any], bedrock_model: str,
               aws_profile: Optional[str] = None, interactive: bool = False) -> Dict[str, Any]:
        """Execute information extraction with threat generation if needed
        
        Args:
            context_files: Dict with discovered files and content
            bedrock_model: Bedrock model ID to use
            aws_profile: Optional AWS profile name
            interactive: Whether to prompt user for validation
            
        Returns:
            Dict with threat_statements, project_info, and extraction_summary
        """
        # Add model_id to context_files for downstream operations
        if bedrock_model:
            context_files['model_id'] = bedrock_model
        
        # Parse existing threat statements using ThreatParser
        threat_statements = self.parser.parse_threat_statements(context_files)
        
        # Extract key project information using ProjectExtractor
        project_info = self.project_extractor.extract_project_info(
            context_files, bedrock_model, aws_profile
        )
        
        # If no threat statements found, generate them using ThreatGenerator
        if not threat_statements:
            threat_files_without_statements = context_files.get("threat_files_without_statements", [])
            
            if threat_files_without_statements:
                self.logger.info("Found threat model files but no proper threat statements - generating from existing content...")
                generated_threats = self.threat_generator.generate_threats_from_existing_content(
                    threat_files_without_statements, project_info, bedrock_model, aws_profile
                )
                threat_statements.extend(generated_threats)
            else:
                self.logger.info("No threat statements found - generating threat statements using AI analysis...")
                generated_threats = self.threat_generator.generate_threats_with_bedrock(
                    context_files, project_info, bedrock_model, aws_profile
                )
                threat_statements.extend(generated_threats)
        
        # User validation if interactive
        if interactive and not project_info.get("error"):
            project_info = self.project_extractor.validate_with_user(project_info)
        
        # Filter high severity threats
        high_severity_threats = [t for t in threat_statements if t.get("severity") == "High"]
        
        self.logger.debug(f"Total threats extracted: {len(threat_statements)}")
        self.logger.debug(f"High severity threats: {len(high_severity_threats)}")
        for threat in high_severity_threats:
            self.logger.debug(f"  - {threat.get('id', 'Unknown')}: {threat.get('severity', 'Unknown')} priority")
        
        # Merge enhanced context into project_info
        if context_files.get('enhanced_context'):
            enhanced_context = context_files['enhanced_context']
            project_info.update(enhanced_context)
            self.logger.debug(f"Enhanced context merged: {list(enhanced_context.keys())}")
        
        return {
            "threat_statements": threat_statements,
            "high_severity_threats": high_severity_threats,
            "project_info": project_info,
            "extraction_summary": {
                "total_threats": len(threat_statements),
                "high_severity_count": len(high_severity_threats),
                "technologies_identified": len(project_info.get("technologies", [])),
                "has_security_objectives": bool(project_info.get("security_objectives")),
                "user_validated": interactive and not project_info.get("error")
            }
        }
