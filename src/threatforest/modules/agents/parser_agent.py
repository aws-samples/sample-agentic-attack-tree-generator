"""Parser Agent - Parse existing threat statement files"""
from typing import Dict, Any, List, Optional
from pathlib import Path
from strands_tools import file_read
from ..core.base_agent import BaseAgent
from ..parsers import (
    ParserChain, JSONThreatParser, YAMLThreatParser,
    MarkdownThreatParser, ThreatComposerParser
)


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
        
        # Initialize parser chain with priority ordering
        self.parser_chain = ParserChain()
        self.parser_chain.register(ThreatComposerParser(), priority=4)
        self.parser_chain.register(JSONThreatParser(), priority=3)
        self.parser_chain.register(YAMLThreatParser(), priority=2)
        self.parser_chain.register(MarkdownThreatParser(), priority=1)
        self.logger.debug("Parser chain initialized with 4 parsers")
    
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
        
        # Create agent with file_read tool
        agent = self.get_strands_agent(
            prompt_file='threat-parsing.md',
            tools=[file_read],
            temperature=0
        )
        
        user_prompt = f"""Parse threat statements from the file: {threat_file_path}

Your goal is to:
1. Read the file using the file_read tool
2. Identify the format (JSON, YAML, Markdown, ThreatComposer)
3. Extract all threat statements
4. Structure them in a consistent format

Each threat should include:
- id: Unique identifier (e.g., T001, T002)
- description/statement: The threat description
- severity/priority: High, Medium, or Low
- category: Threat category
- Any additional metadata from the source file

Return the threats as a JSON array."""

        try:
            # Run the agent - it will use file_read to access the file
            self.console_display.show_agent_action("Reading and analyzing threat file...")
            result = agent(user_prompt)
            
            # Parse the agent's response
            self.console_display.show_agent_action("Extracting threat statements from agent output...")
            threats = self._parse_threat_response(str(result), threat_file_path)
            
            # Also try the parser chain as fallback/validation
            if not threats:
                self.console_display.show_agent_action("Using parser chain fallback...")
                chain_threats = self._parse_with_chain(threat_file_path)
            else:
                chain_threats = []
            
            # Use agent results if available, otherwise use chain
            final_threats = threats if threats else chain_threats
            
            # Show what was parsed
            if final_threats:
                high_severity = sum(1 for t in final_threats if t.get('severity') == 'High')
                self.console_display.show_agent_action(
                    f"Extracted {len(final_threats)} threats",
                    f"{high_severity} High severity, {len(final_threats) - high_severity} Medium/Low"
                )
            
            self.logger.info(f"Successfully parsed {len(final_threats)} threats from {threat_file_path.name}")
            self.console_display.show_agent_complete(
                f"Parsing complete - {len(final_threats)} threat statements extracted"
            )
            return final_threats
            
        except Exception as e:
            self.logger.error(f"Agent parsing failed, falling back to parser chain: {e}")
            self.console_display.show_agent_action("Agent parsing failed, using fallback parser...")
            
            # Fallback to traditional parser chain
            threats = self._parse_with_chain(threat_file_path)
            
            if threats:
                self.console_display.show_agent_complete(
                    f"Fallback successful - {len(threats)} threats parsed",
                    success=True
                )
            else:
                self.console_display.show_agent_error("No threats could be parsed")
            
            return threats
    
    def _parse_threat_response(self, agent_output: str, source_file: Path) -> List[Dict[str, Any]]:
        """Parse agent's threat extraction response
        
        Args:
            agent_output: Raw text output from agent
            source_file: Source file path for attribution
            
        Returns:
            List of structured threat dictionaries
        """
        from ..tools.information_extraction_tool.text_utils import parse_json_response
        
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
    
    def _parse_with_chain(self, threat_file_path: Path) -> List[Dict[str, Any]]:
        """Parse threat file using traditional parser chain
        
        Args:
            threat_file_path: Path to threat file
            
        Returns:
            List of threat dictionaries
        """
        try:
            # Read file content
            with open(threat_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try each parser in the chain
            file_info = {
                "path": str(threat_file_path),
                "content": content
            }
            
            threats = self.parser_chain.parse(file_info)
            
            # Add source file to each threat
            for threat in threats:
                threat["source_file"] = str(threat_file_path)
            
            return threats
            
        except Exception as e:
            self.logger.error(f"Parser chain failed: {e}")
            return []
