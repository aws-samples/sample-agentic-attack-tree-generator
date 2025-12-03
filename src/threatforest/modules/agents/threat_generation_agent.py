"""Threat Generation Agent - Generate threat statements using AI analysis"""
from typing import Dict, Any, List, Optional
from pathlib import Path
from ..core.base_agent import BaseAgent
from ..workflow.information_extraction.text_utils import parse_json_response
from ..workflow.information_extraction.threat_formatter import ThreatFormatter


class ThreatGenerationAgent(BaseAgent):
    """Agent that generates threat statements through LLM analysis
    
    Collaborates with RepositoryAnalysisAgent to create contextual
    threat statements when none exist in the repository.
    """
    
    def __init__(self, logger=None, console=None):
        """Initialize the threat generation agent
        
        Args:
            logger: Optional logger instance
            console: Optional AgentConsole for display
        """
        self.name = "threat_generation"
        self.description = "Generate threat statements using AI analysis"
        if logger:
            self.logger = logger
        else:
            from ..utils.logger import ThreatForestLogger
            self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Initialize console display
        if console:
            self.console_display = console
        else:
            from ..utils.agent_console import AgentConsole
            from threatforest.config import config
            show_errors = config.get('cli', {}).get('show_errors', True)
            self.console_display = AgentConsole(show_errors=show_errors)
        
        self.formatter = ThreatFormatter(self.logger)
    
    def generate_threats(
        self, 
        project_context: Dict[str, Any],
        project_path: str,
        model_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Generate threat statements based on project context
        
        Uses the context provided by RepositoryAnalysisAgent to generate
        relevant, targeted threat statements for the application.
        
        Args:
            project_context: Context dict from RepositoryAnalysisAgent containing:
                - application_name
                - technologies
                - architecture_type
                - deployment_environment
                - sector
                - data_assets
                - entry_points
                etc.
            project_path: Path to project for saving generated threats
            model_name: Optional model name override
            
        Returns:
            List of generated threat dictionaries
        """
        self.logger.info("Generating threat statements from project context")
        
        # Show agent start
        app_name = project_context.get('application_name', 'Unknown')
        self.console_display.show_agent_start(
            "Threat Generation Agent",
            f"Generating threat statements for: {app_name}"
        )
        
        # Create agent for threat generation (no tools needed - pure reasoning)
        # Summarization not enabled by default as threat generation is typically single-turn
        agent = self.get_strands_agent(
            prompt_file='threat-generation-new.md',
            tools=[],  # No tools - just LLM reasoning
            temperature=0,
            use_summarization=False  # Can be enabled if multi-turn threat refinement is needed
        )
        
        # Build comprehensive user prompt with all context
        tech_count = len(project_context.get('technologies', []))
        self.console_display.show_agent_action(
            f"Building generation prompt with project context",
            f"{tech_count} technologies, {project_context.get('architecture_type', 'Unknown')} architecture"
        )
        
        user_prompt = self._build_generation_prompt(project_context)
        
        try:
            # Run agent to generate threats
            with self.console_display.show_agent_spinner("Analyzing security risks and generating threats..."):
                result = agent(user_prompt)
            self.console_display.show_agent_action("✓ Threat analysis complete")
            
            # Parse the generated threats
            with self.console_display.show_agent_spinner("Extracting threat statements from generation..."):
                threats = self._parse_generation_response(str(result))
            
            if not threats:
                self.logger.warning("No threats generated, using fallback")
                self.console_display.show_agent_action("Using fallback threat templates...")
                threats = self._get_fallback_threats(project_context)
            
            # Show generated threat summary
            if threats:
                high_severity = sum(1 for t in threats if t.get('severity') == 'High')
                self.console_display.show_agent_action(
                    f"Generated {len(threats)} threat statements",
                    f"{high_severity} High severity, {len(threats) - high_severity} Medium/Low"
                )
            
            # Create markdown file with generated threats
            with self.console_display.show_agent_spinner("Saving threats to markdown file..."):
                pass
            filename = self.formatter.create_threats_markdown_file(
                threats, 
                project_path, 
                project_context
            )
            
            self.logger.info(f"Generated {len(threats)} threat statements")
            self.logger.info(f"Threats saved to {filename}")
            
            self.console_display.show_agent_complete(
                f"Generation complete - {len(threats)} threats created and saved"
            )
            
            return threats
            
        except Exception as e:
            self.logger.error(f"Threat generation failed: {e}")
            self.console_display.show_agent_action("Generation failed, using fallback threats...")
            
            threats = self._get_fallback_threats(project_context)
            
            # Still try to save fallback threats
            filename = self.formatter.create_threats_markdown_file(
                threats,
                project_path,
                project_context
            )
            self.logger.info(f"Fallback threats saved to {filename}")
            
            self.console_display.show_agent_complete(
                f"Fallback complete - {len(threats)} generic threats created",
                success=False
            )
            
            return threats
    
    def _build_generation_prompt(self, context: Dict[str, Any]) -> str:
        """Build comprehensive prompt for threat generation
        
        Args:
            context: Project context from RepositoryAnalysisAgent
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""Generate comprehensive threat statements for this application.

## Application Context

**Application Name:** {context.get('application_name', 'Unknown')}
**Technologies:** {', '.join(context.get('technologies', []))}
**Architecture:** {context.get('architecture_type', 'Unknown')}
**Deployment:** {context.get('deployment_environment', 'Unknown')}
**Sector:** {context.get('sector', 'General')}

"""
        
        # Add data assets if available
        if context.get('data_assets'):
            prompt += f"\n**Data Assets:** {', '.join(context['data_assets'])}"
        
        # Add entry points if available
        if context.get('entry_points'):
            prompt += f"\n**Entry Points:** {', '.join(context['entry_points'])}"
        
        # Add security objectives if available
        if context.get('security_objectives'):
            prompt += f"\n**Security Objectives:** {', '.join(context['security_objectives'])}"
        
        # Add summary if available
        if context.get('summary'):
            prompt += f"\n\n**Additional Context:**\n{context['summary']}"
        
        prompt += """

## Task

Generate 8-12 high-quality threat statements that are specific to this application.
Focus on realistic threats based on the technologies, architecture, and deployment environment.

Each threat should follow this structure:
- id: T001, T002, etc.
- statement: Full threat statement
- priority: High, Medium, or Low
- category: Threat category (e.g., Authentication, Data Breach, Injection, etc.)
- threatSource: Who/what could execute this threat
- prerequisites: What attacker needs
- threatAction: What the attacker does
- threatImpact: Immediate impact
- impactedGoal: CIA goal affected (confidentiality/integrity/availability)
- impactedAssets: What assets are affected

Return the threats as a JSON object with a "threats" array."""

        return prompt
    
    def _parse_generation_response(self, agent_output: str) -> List[Dict[str, Any]]:
        """Parse agent's threat generation response
        
        Args:
            agent_output: Raw text output from agent
            
        Returns:
            List of generated threat dictionaries
        """
        try:
            # Parse JSON response
            threat_data = parse_json_response(agent_output)
            
            # Extract threats array
            threats = threat_data.get('threats', [])
            
            # Normalize threat structure
            normalized_threats = []
            for threat in threats:
                normalized = {
                    "id": threat.get('id', ''),
                    "statement": threat.get('statement', ''),
                    "severity": threat.get('priority', 'Medium'),
                    "category": threat.get('category', 'General'),
                    "threatSource": threat.get('threatSource', ''),
                    "prerequisites": threat.get('prerequisites', ''),
                    "threatAction": threat.get('threatAction', ''),
                    "threatImpact": threat.get('threatImpact', ''),
                    "impactedGoal": threat.get('impactedGoal', ''),
                    "impactedAssets": threat.get('impactedAssets', ''),
                    "source": "AI Generated"
                }
                normalized_threats.append(normalized)
            
            return normalized_threats
            
        except Exception as e:
            self.logger.warning(f"Could not parse generation response: {e}")
            return []
    
    def _get_fallback_threats(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Provide fallback threats when generation fails
        
        Args:
            context: Project context for customization
            
        Returns:
            List of generic but relevant threat dictionaries
        """
        app_name = context.get('application_name', 'application')
        
        return [
            {
                "id": "T001",
                "statement": f"A malicious attacker with network access can exploit weak authentication mechanisms in {app_name}, which leads to unauthorized system access, resulting in reduced confidentiality of application data.",
                "severity": "High",
                "category": "Authentication",
                "threatSource": "malicious attacker",
                "prerequisites": "network access",
                "threatAction": "exploit weak authentication mechanisms",
                "threatImpact": "unauthorized system access",
                "impactedGoal": "confidentiality",
                "impactedAssets": "application data",
                "source": "Fallback"
            },
            {
                "id": "T002",
                "statement": f"A malicious user with application access can perform injection attacks against {app_name}, which leads to data manipulation or extraction, resulting in reduced integrity of database records.",
                "severity": "High",
                "category": "Injection",
                "threatSource": "malicious user",
                "prerequisites": "application access",
                "threatAction": "perform injection attacks",
                "threatImpact": "data manipulation or extraction",
                "impactedGoal": "integrity",
                "impactedAssets": "database records",
                "source": "Fallback"
            },
            {
                "id": "T003",
                "statement": f"A distributed attacker with internet connectivity can launch denial of service attacks against {app_name}, which leads to service unavailability, resulting in reduced availability of application services.",
                "severity": "Medium",
                "category": "Availability",
                "threatSource": "distributed attacker",
                "prerequisites": "internet connectivity",
                "threatAction": "launch denial of service attacks",
                "threatImpact": "service unavailability",
                "impactedGoal": "availability",
                "impactedAssets": "application services",
                "source": "Fallback"
            },
            {
                "id": "T004",
                "statement": f"A network eavesdropper with packet capture capabilities can intercept unencrypted communications from {app_name}, which leads to sensitive data exposure, resulting in reduced confidentiality of transmitted data.",
                "severity": "Medium",
                "category": "Cryptography",
                "threatSource": "network eavesdropper",
                "prerequisites": "packet capture capabilities",
                "threatAction": "intercept unencrypted communications",
                "threatImpact": "sensitive data exposure",
                "impactedGoal": "confidentiality",
                "impactedAssets": "transmitted data",
                "source": "Fallback"
            }
        ]
