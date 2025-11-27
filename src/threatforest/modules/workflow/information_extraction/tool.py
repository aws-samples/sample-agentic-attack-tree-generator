"""Main Information Extraction Tool - Orchestrates all extraction operations"""
from typing import Dict, List, Any, Optional
from ...utils.logger import ThreatForestLogger
from ...core.base_agent import BaseAgent


class InformationExtractionTool(BaseAgent):
    """Tool for extracting key information from context files
    
    Orchestrates threat parsing, project metadata extraction, and threat generation
    using specialized Strands agents for each responsibility.
    """
    
    def __init__(self, console=None):
        self.name = "information_extraction"
        self.description = "Extract key information including threat statements, technologies, and security objectives"
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Initialize console display - wrap Rich Console in AgentConsole if needed
        from ...utils.agent_console import AgentConsole
        if console and not isinstance(console, AgentConsole):
            # Console is a Rich Console, wrap it in AgentConsole
            self.console_display = AgentConsole(console)
        elif console:
            # Already an AgentConsole
            self.console_display = console
        else:
            # Create new AgentConsole
            self.console_display = AgentConsole()
        
        # Lazy import to avoid circular dependencies
        from ...agents import RepositoryAnalysisAgent, ParserAgent, ThreatGenerationAgent
        
        # Initialize specialized agents with shared console
        self.repository_agent = RepositoryAnalysisAgent(self.logger, self.console_display)
        self.parser_agent = ParserAgent(self.logger, self.console_display)
        self.threat_generator = ThreatGenerationAgent(self.logger, self.console_display)
        
        self.logger.debug("Initialized agents: RepositoryAnalysisAgent, ParserAgent, ThreatGenerationAgent")
    
    def run(self, context_files: Dict[str, Any], bedrock_model: str,
               aws_profile: Optional[str] = None, interactive: bool = False,
               threat_file_path: Optional[str] = None) -> Dict[str, Any]:
        """Execute information extraction using Strands agents
        
        Args:
            context_files: Dict with discovered files and content
            bedrock_model: Bedrock model ID to use
            aws_profile: Optional AWS profile name
            interactive: Whether to prompt user for validation
            threat_file_path: Optional path to existing threat statements file
            
        Returns:
            Dict with threat_statements, project_info, and extraction_summary
        """
        project_path = context_files.get('project_path', '.')
        
        # Decision point: Parse existing threats or generate new ones?
        if threat_file_path:
            # User provided threat file - use ParserAgent
            self.logger.info(f"Parsing existing threat statements from: {threat_file_path}")
            self.console_display.console.print(f"\n📋 [bold cyan]User provided threat file - parsing existing threats[/bold cyan]")
            
            threat_statements = self.parser_agent.parse_threats(
                threat_file_path=threat_file_path,
                model_name=bedrock_model
            )
            
            # Still need project context for downstream operations
            self.logger.info("Analyzing repository for project context...")
            self.console_display.console.print(f"\n🔍 [bold cyan]Analyzing repository for project context[/bold cyan]")
            
            project_info = self.repository_agent.analyze_repository(
                project_path=project_path,
                model_name=bedrock_model
            )
            
        else:
            # No threat file - autonomous generation workflow
            self.logger.info("No threat file provided - starting autonomous analysis...")
            self.console_display.console.print(f"\n🤖 [bold cyan]No threat file provided - agents will auto-generate threats[/bold cyan]")
            
            # Step 1: Repository Analysis Agent explores the project
            self.logger.info("Repository Analysis Agent exploring project...")
            project_info = self.repository_agent.analyze_repository(
                project_path=project_path,
                model_name=bedrock_model
            )
            
            # Show collaboration
            tech_summary = f"{len(project_info.get('technologies', []))} technologies, "
            tech_summary += f"{len(project_info.get('data_assets', []))} data assets, "
            tech_summary += f"{len(project_info.get('entry_points', []))} entry points"
            
            self.console_display.show_collaboration(
                "Repository Analysis Agent",
                "Threat Generation Agent",
                tech_summary
            )
            
            # Step 2: Threat Generation Agent creates threats from context
            self.logger.info("Threat Generation Agent creating threat statements...")
            threat_statements = self.threat_generator.generate_threats(
                project_context=project_info,
                project_path=project_path,
                model_name=bedrock_model
            )
        
        # Filter high severity threats
        high_severity_threats = [t for t in threat_statements if t.get("severity") == "High"]
        
        self.logger.debug(f"Total threats extracted: {len(threat_statements)}")
        self.logger.debug(f"High severity threats: {len(high_severity_threats)}")
        for threat in high_severity_threats:
            self.logger.debug(f"  - {threat.get('id', 'Unknown')}: {threat.get('severity', 'Unknown')} priority")
        
        # Merge enhanced context if available
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
                "agent_based": True,
                "threat_source": "user_provided" if threat_file_path else "ai_generated"
            }
        }
