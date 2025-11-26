"""Repository Analysis Agent - Autonomous exploration of project repositories"""
from typing import Dict, Any, Optional
from pathlib import Path
from strands_tools import file_read, editor, image_reader
from ..core.base_agent import BaseAgent


class RepositoryAnalysisAgent(BaseAgent):
    """Agent that autonomously explores and analyzes repository structure and content
    
    Uses Strands tools to:
    - Navigate directory structure
    - Read and analyze files
    - Process architecture diagrams
    - Extract project context and security-relevant information
    """
    
    def __init__(self, logger=None, console=None):
        """Initialize the repository analysis agent
        
        Args:
            logger: Optional logger instance
            console: Optional AgentConsole for display
        """
        self.name = "repository_analysis"
        self.description = "Autonomously explore and analyze project repositories"
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
            self.console_display = AgentConsole()
    
    def analyze_repository(self, project_path: str, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze a repository to extract project context and security information
        
        The agent will autonomously:
        1. View the directory structure
        2. Identify and read relevant files (README, config, source code)
        3. Process any architecture diagrams
        4. Extract technologies, architecture patterns, and security concerns
        
        Args:
            project_path: Absolute path to the project repository
            model_name: Optional model name override (uses config default if not provided)
            
        Returns:
            Dict containing:
                - application_name: Detected application name
                - technologies: List of technologies used
                - architecture_type: Type of architecture (e.g., "microservices", "monolith")
                - deployment_environment: Where it's deployed (e.g., "AWS", "on-premise")
                - sector: Industry sector (e.g., "healthcare", "finance")
                - security_objectives: List of security goals
                - data_assets: Sensitive data identified
                - entry_points: External interfaces and APIs
                - trust_boundaries: Security boundary information
        """
        project_path = Path(project_path).resolve()
        
        self.logger.info(f"Starting autonomous repository analysis: {project_path}")
        
        # Show agent start
        self.console_display.show_agent_start(
            "Repository Analysis Agent",
            f"Exploring project repository: {project_path.name}"
        )
        
        # Create agent with tools for exploration
        agent = self.get_strands_agent(
            prompt_file='repository-analysis.md',
            tools=[file_read, editor, image_reader],
            temperature=0
        )
        
        # Provide the agent with the project path and let it explore
        user_prompt = f"""Analyze the repository located at: {project_path}

Your goal is to autonomously explore this repository and extract comprehensive project context.

You have access to these tools:
- file_read: Read specific files you identify as important
- editor: View directory structure (use command="view" on directories)
- image_reader: Analyze architecture diagrams and visual documentation

Begin by viewing the directory structure, then strategically read files to understand:
1. What this application does
2. What technologies it uses
3. How it's architected
4. Where it's deployed
5. What security concerns might exist

Be thorough but efficient - focus on files that provide the most context."""

        try:
            # Run the agent - it will autonomously explore using tools
            self.console_display.show_agent_action("Starting autonomous exploration...")
            result = agent(user_prompt)
            
            # Parse the agent's findings
            self.console_display.show_agent_action("Parsing agent findings...")
            analysis = self._parse_analysis_results(str(result))
            
            # Show what was found
            tech_count = len(analysis.get('technologies', []))
            self.console_display.show_agent_action(
                f"Discovered {tech_count} technologies",
                ", ".join(analysis.get('technologies', [])[:5])
            )
            
            if analysis.get('data_assets'):
                self.console_display.show_agent_action(
                    f"Identified {len(analysis['data_assets'])} data assets"
                )
            
            if analysis.get('entry_points'):
                self.console_display.show_agent_action(
                    f"Found {len(analysis['entry_points'])} entry points"
                )
            
            self.logger.info(f"Repository analysis complete. Found {tech_count} technologies")
            self.console_display.show_agent_complete(
                f"Analysis complete - {tech_count} technologies, {analysis.get('architecture_type', 'Unknown')} architecture"
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Repository analysis failed: {e}")
            self.console_display.show_agent_error(str(e))
            
            # Return minimal fallback structure
            return {
                "application_name": project_path.name,
                "technologies": [],
                "architecture_type": "Unknown",
                "deployment_environment": "Unknown",
                "sector": "Unknown",
                "security_objectives": [],
                "data_assets": [],
                "entry_points": [],
                "trust_boundaries": [],
                "error": str(e)
            }
    
    def _parse_analysis_results(self, agent_output: str) -> Dict[str, Any]:
        """Parse the agent's analysis output into structured format
        
        Args:
            agent_output: Raw text output from the agent
            
        Returns:
            Structured dictionary with extracted information
        """
        # Import JSON parsing utility
        from ..tools.information_extraction_tool.text_utils import parse_json_response
        
        try:
            # Try to parse as JSON first
            parsed = parse_json_response(agent_output)
            
            # Ensure all expected keys exist with defaults
            return {
                "application_name": parsed.get("application_name", "Unknown Application"),
                "technologies": parsed.get("technologies", []),
                "architecture_type": parsed.get("architecture_type", "Unknown"),
                "deployment_environment": parsed.get("deployment_environment", "Unknown"),
                "sector": parsed.get("sector", "General"),
                "security_objectives": parsed.get("security_objectives", []),
                "data_assets": parsed.get("data_assets", []),
                "entry_points": parsed.get("entry_points", []),
                "trust_boundaries": parsed.get("trust_boundaries", []),
                "summary": parsed.get("summary", ""),
            }
            
        except Exception as e:
            self.logger.warning(f"Could not parse agent output as JSON: {e}")
            
            # Fallback: Extract information from text
            return self._extract_from_text(agent_output)
    
    def _extract_from_text(self, text: str) -> Dict[str, Any]:
        """Extract structured information from plain text output
        
        Args:
            text: Plain text output from agent
            
        Returns:
            Structured dictionary with best-effort extraction
        """
        import re
        
        # Initialize result structure
        result = {
            "application_name": "Unknown Application",
            "technologies": [],
            "architecture_type": "Unknown",
            "deployment_environment": "Unknown",
            "sector": "General",
            "security_objectives": [],
            "data_assets": [],
            "entry_points": [],
            "trust_boundaries": [],
            "summary": text[:500],  # Include excerpt
        }
        
        # Try to extract application name
        app_name_patterns = [
            r"application[:\s]+([^\n]+)",
            r"project[:\s]+([^\n]+)",
            r"name[:\s]+([^\n]+)",
        ]
        for pattern in app_name_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                result["application_name"] = match.group(1).strip()
                break
        
        # Extract technologies (common tech keywords)
        tech_keywords = [
            "Python", "Java", "JavaScript", "TypeScript", "Go", "Rust",
            "React", "Vue", "Angular", "Node.js", "Django", "Flask",
            "Docker", "Kubernetes", "AWS", "Azure", "GCP",
            "PostgreSQL", "MySQL", "MongoDB", "Redis",
            "REST", "GraphQL", "gRPC"
        ]
        for tech in tech_keywords:
            if re.search(rf"\b{tech}\b", text, re.IGNORECASE):
                result["technologies"].append(tech)
        
        # Extract architecture mentions
        arch_patterns = {
            "microservices": r"\bmicroservices?\b",
            "serverless": r"\bserverless\b",
            "monolith": r"\bmonolith(ic)?\b",
            "event-driven": r"\bevent[- ]driven\b",
        }
        for arch_type, pattern in arch_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                result["architecture_type"] = arch_type
                break
        
        return result
