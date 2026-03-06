"""Parser Agent - Parse existing threat statement files"""
from typing import Dict, Any, List, Optional
from pathlib import Path
from strands_tools import file_read, editor, image_reader
from ..core.base_agent import BaseAgent


class ParserAgent(BaseAgent):
    """Agent that parses and extracts threat statements from existing files
    
    Uses Strands file_read tool to access threat files and employs
    the existing parser chain to extract structured threat data.
    """
    
    def __init__(self, logger=None, console=None):
        """Initialize the parser agent
        
        Args:
            logger: Optional logger instance
            console: Optional AgentConsole for display
        """
        self.name = "parser"
        self.description = "Parse existing threat statement files"
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
        
        self.logger.debug("ParserAgent initialized (Strands-only, no parser chain)")
    
    def parse_threats(self, threat_file_path: str, model_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse threat statements from a file using Strands agent
        
        The agent will:
        1. Use file_read tool to access the threat file
        2. Determine the file format
        3. Extract and structure threat statements
        4. Validate the extracted threats
        
        Args:
            threat_file_path: Path to the threat statement file
            model_name: Optional model name override
            
        Returns:
            List of threat dictionaries with structure:
                {
                    "id": "T001",
                    "description": "threat statement",
                    "severity": "High|Medium|Low",
                    "category": "category name",
                    "source_file": "file path",
                    ...additional fields...
                }
        """
        threat_file_path = Path(threat_file_path).resolve()
        
        if not threat_file_path.exists():
            self.logger.error(f"Threat file not found: {threat_file_path}")
            self.console_display.show_agent_error(f"Threat file not found: {threat_file_path}")
            return []
        
        self.logger.info(f"Parsing threat statements from: {threat_file_path}")
        
        # Show agent start
        self.console_display.show_agent_start(
            "Parser Agent",
            f"Parsing threat statements from: {threat_file_path.name}"
        )
        
        # Import structured output models
        from ..models import ThreatList
        
        # Create agent with file_read tool and structured output
        # Summarization not enabled by default as parsing is typically single-turn
        agent = self.get_strands_agent(
            prompt_file='threat-parsing.md',
            tools=[file_read, editor, image_reader],
            temperature=0,
            use_summarization=False  # Can be enabled for complex multi-file parsing scenarios
        )
        
        user_prompt = f"""Parse threat statements from the file: {threat_file_path}

Your goal is to:
1. Read the file using the file_read tool
2. Identify the format (JSON, YAML, Markdown, ThreatComposer)
3. Extract all threat statements

IMPORTANT: Return a structured response with:
- threats: array of threat objects
- Each threat must have: id, statement, priority, category
- Optional fields: threatSource, prerequisites, threatAction, threatImpact, impactedGoal, impactedAssets"""

        try:
            # Run the agent with structured output - it will use file_read to access the file
            with self.console_display.show_agent_spinner("Reading and analyzing threat file..."):
                # Use structured output for guaranteed parsing
                result = agent(
                    user_prompt,
                    structured_output_model=ThreatList
                )
            self.console_display.show_agent_action("✓ Read threat file")
            
            # Extract threats from structured output
            with self.console_display.show_agent_spinner("Extracting threat statements..."):
                pass  # Extraction is fast, spinner just for consistency
            
            if result.structured_output and result.structured_output.threats:
                # Convert Pydantic models to dicts
                threats = []
                for threat in result.structured_output.threats:
                    threat_dict = {
                        "id": threat.id,
                        "description": threat.statement,  # Map 'statement' to 'description'
                        "severity": threat.priority,  # Map 'priority' to 'severity'
                        "category": threat.category,
                        "source_file": str(threat_file_path),
                    }
                    
                    # Add optional fields if present
                    if threat.threatSource:
                        threat_dict["threatSource"] = threat.threatSource
                    if threat.prerequisites:
                        threat_dict["prerequisites"] = threat.prerequisites
                    if threat.threatAction:
                        threat_dict["threatAction"] = threat.threatAction
                    if threat.threatImpact:
                        threat_dict["threatImpact"] = threat.threatImpact
                    if threat.impactedGoal:
                        threat_dict["impactedGoal"] = threat.impactedGoal
                    if threat.impactedAssets:
                        threat_dict["impactedAssets"] = threat.impactedAssets
                    
                    threats.append(threat_dict)
            else:
                self.logger.warning("Structured output had no threats")
                threats = []
            
            # Show what was parsed
            if threats:
                high_severity = sum(1 for t in threats if t.get('severity') == 'High')
                self.console_display.show_agent_action(
                    f"Extracted {len(threats)} threats",
                    f"{high_severity} High severity, {len(threats) - high_severity} Medium/Low"
                )
                
                self.logger.info(f"Successfully parsed {len(threats)} threats from {threat_file_path.name}")
                self.console_display.show_agent_complete(
                    f"Parsing complete - {len(threats)} threat statements extracted"
                )
            else:
                self.logger.warning(f"No threats extracted from {threat_file_path.name}")
                self.console_display.show_agent_error("No threat statements could be extracted")
            
            return threats
            
        except Exception as e:
            self.logger.error(f"Agent parsing failed: {e}")
            self.console_display.show_agent_error(f"Parsing failed: {str(e)}")
            return []
    
    def _parse_threat_response(self, agent_output: str, source_file: Path) -> List[Dict[str, Any]]:
        """Parse agent's threat extraction response
        
        Args:
            agent_output: Raw text output from agent
            source_file: Source file path for attribution
            
        Returns:
            List of structured threat dictionaries
        """
        from ..workflow.information_extraction.text_utils import parse_json_response
        
        try:
            # Try to parse as JSON
            parsed = parse_json_response(agent_output)
            
            # Handle different response structures
            if isinstance(parsed, list):
                threats = parsed
            elif isinstance(parsed, dict) and 'threats' in parsed:
                threats = parsed['threats']
            else:
                self.logger.warning("Unexpected response structure")
                return []
            
            # Normalize threat structure
            normalized_threats = []
            for threat in threats:
                normalized = {
                    "id": threat.get("id", "T000"),
                    "description": threat.get("description") or threat.get("statement", ""),
                    "severity": threat.get("severity") or threat.get("priority", "Medium"),
                    "category": threat.get("category", "General"),
                    "source_file": str(source_file),
                }
                
                # Include any additional fields
                for key, value in threat.items():
                    if key not in normalized and value:
                        normalized[key] = value
                
                normalized_threats.append(normalized)
            
            return normalized_threats
            
        except Exception as e:
            self.logger.warning(f"Could not parse agent output as JSON: {e}")
            return []
