"""Repository Analysis Agent - Autonomous exploration of project repositories"""
from typing import Dict, Any, Optional
from pathlib import Path
from strands_tools import file_read, image_reader
from ..tools.read_only_editor import read_only_editor
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
        
        # Import structured output model
        from ..models import ProjectInfo
        
        # Create agent with tools and callback handler
        # Enable summarization for long repository explorations
        agent = self.get_strands_agent(
            prompt_file='repository-analysis.md',
            tools=[file_read, read_only_editor, image_reader],
            temperature=0,
            use_summarization=False
        )
        
        # Provide the agent with the project path and let it explore
        user_prompt = f"""Analyze the repository located at: {project_path}

Your goal is to autonomously explore this repository and extract comprehensive project context.

IMPORTANT: Return a structured ProjectInfo response with these fields:
- application_name: Name of the application
- technologies: List of technologies used
- architecture_type: Type of architecture
- deployment_environment: Where deployed
- sector: Industry sector
- security_objectives: List of security goals
- data_assets: Sensitive data identified
- entry_points: External interfaces
- trust_boundaries: Security boundaries

Begin by viewing the directory structure, then strategically read files."""

        try:
            # Run the agent with structured output - it will autonomously explore using tools
            with self.console_display.show_agent_spinner("Analyzing repository structure and files..."):
                result = agent(
                    user_prompt,
                    structured_output_model=ProjectInfo
                )
            self.console_display.show_agent_action("✓ Repository analysis complete")
            
            # Extract validated ProjectInfo from structured output
            with self.console_display.show_agent_spinner("Processing project information..."):
                pass  # Quick operation, spinner for consistency
            
            if result.structured_output:
                # Convert Pydantic model to dict for compatibility
                analysis = result.structured_output.model_dump()
            else:
                self.logger.warning("No structured output received, using fallback")
                analysis = self._get_fallback_analysis(project_path)
            
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
        from ..workflow.information_extraction.text_utils import parse_json_response
        
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
    
    def _get_fallback_analysis(self, project_path: Path) -> Dict[str, Any]:
        """Get fallback analysis when structured output fails
        
        Args:
            project_path: Path to project
            
        Returns:
            Basic project info structure
        """
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
            "summary": f"Analysis of {project_path.name}"
        }
    
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
