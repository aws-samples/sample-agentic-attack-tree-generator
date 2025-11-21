"""Threat parsing from various file formats"""
import re
import json
import subprocess
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
from ...parsers import ParserChain
from .file_utils import is_text_file, is_binary_file, is_correct_format, analyze_threat_file
from .text_utils import extract_field
from .threat_formatter import ThreatFormatter


class ThreatParser:
    """Parses threat statements from various file formats"""
    
    def __init__(self, logger, parser_chain: ParserChain, formatter: ThreatFormatter):
        """Initialize parser
        
        Args:
            logger: Logger instance
            parser_chain: Parser chain for multiple formats
            formatter: ThreatFormatter for output creation
        """
        self.logger = logger
        self.parser_chain = parser_chain
        self.formatter = formatter
    
    def parse_threat_statements(self, context_files: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse threat statements from manually specified or discovered files
        
        Args:
            context_files: Dict containing threat model paths and discovered files
            
        Returns:
            List of parsed threat dicts
        """
        threats = []
        
        # Check if user manually specified a threat model path
        manual_threat_path = context_files.get("threat_model_path")
        
        if manual_threat_path:
            self.logger.info(f"Processing manually specified threat model: {Path(manual_threat_path).name}")
            try:
                # Analyze the manually specified file
                analysis = analyze_threat_file(manual_threat_path)
                
                if analysis['is_correct_format']:
                    self.logger.info(f"File is correctly formatted, extracting threats directly")
                    threats = self.extract_threats_from_content(analysis['content'], manual_threat_path)
                else:
                    self.logger.info(f"File needs reformatting, processing with reformatter")
                    threats = self.process_threat_file(manual_threat_path, context_files)
                
                if threats:
                    self.logger.info(f"Found {len(threats)} threats in manually specified file")
                    return threats
                else:
                    self.logger.warning(f"No threats found in manually specified file")
                    
            except Exception as e:
                self.logger.error(f"Failed to process manually specified threat model: {e}")
        
        # Fallback to auto-discovery if no manual path or manual path failed
        self.logger.info("Auto-discovering threat files from project...")
        
        # Get threat_models from the discovered files
        threat_models = []
        if "threat_models" in context_files:
            threat_models = context_files["threat_models"]
        elif "discovered_files" in context_files and "threat_models" in context_files["discovered_files"]:
            threat_models = context_files["discovered_files"]["threat_models"]
        
        self.logger.debug(f"Found {len(threat_models)} potential threat files")
        
        # Process discovered threat files
        for threat_file_path in threat_models:
            try:
                if not is_text_file(threat_file_path):
                    continue
                
                if is_binary_file(threat_file_path):
                    if 'binary_files' not in context_files:
                        context_files['binary_files'] = []
                    context_files['binary_files'].append(threat_file_path)
                    continue
                
                if 'threat' in Path(threat_file_path).name.lower():
                    file_threats = self.process_threat_file(threat_file_path, context_files)
                    threats.extend(file_threats)
                else:
                    if 'context_files' not in context_files:
                        context_files['context_files'] = []
                    context_files['context_files'].append(threat_file_path)
                    
            except Exception as e:
                self.logger.warning(f"Failed to process file {threat_file_path}: {e}")
        
        if threats:
            self.logger.info(f"Found {len(threats)} existing threat statements")
        else:
            self.logger.info("No properly formatted threat statements found")
        
        return threats
    
    def process_threat_file(self, threat_file_path: str, context_files: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a threat file and determine if it needs reformatting
        
        Args:
            threat_file_path: Path to threat file
            context_files: Context files dict
            
        Returns:
            List of parsed threats
        """
        self.logger.info(f"Processing threat file: {Path(threat_file_path).name}")
        
        # Try parser chain first
        parsed_threats = self._parse_with_parser_chain(threat_file_path)
        if parsed_threats is not None:
            return parsed_threats
        
        # Fallback to legacy parsing logic
        self.logger.debug("Falling back to legacy parsing logic")
        
        # Check if this is a ThreatComposer file (.tc.json)
        file_path = Path(threat_file_path)
        is_threatcomposer = file_path.name.lower().endswith('.tc.json')
        
        if is_threatcomposer:
            self.logger.info(f"Detected ThreatComposer file - using JQ parser")
            return self._process_threatcomposer_file(threat_file_path)
        
        # Read the file content for non-ThreatComposer files
        with open(threat_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file already matches the correct format
        if is_correct_format(content):
            self.logger.info(f"File already in correct format - using directly")
            return self.extract_threats_from_content(content, threat_file_path)
        
        # File needs reformatting - handled by threat_generator
        self.logger.info(f"File needs reformatting - will reformat via generator")
        # Note: Actual reformatting will be done by ThreatGenerator
        return []
    
    def _parse_with_parser_chain(self, threat_file_path: str) -> Optional[List[Dict[str, Any]]]:
        """Try to parse threat file using parser chain
        
        Args:
            threat_file_path: Path to threat file
            
        Returns:
            List of threats if successfully parsed, None otherwise
        """
        file_path = Path(threat_file_path)
        
        try:
            # Try to parse with parser chain
            parsed_data = self.parser_chain.parse(file_path)
            
            if parsed_data is None:
                self.logger.debug(f"Parser chain could not handle {file_path.name}")
                return None
            
            self.logger.info(f"Successfully parsed {file_path.name} using {parsed_data.get('format', 'unknown')} parser")
            
            # Convert parsed data to threat format
            threats = []
            
            if parsed_data.get('format') == 'threatcomposer':
                threats = self._convert_threatcomposer_threats(parsed_data, file_path)
            elif parsed_data.get('format') in ['json', 'yaml']:
                threats = self._convert_json_yaml_threats(parsed_data, file_path)
            elif parsed_data.get('format') == 'markdown':
                threats = self._convert_markdown_threats(parsed_data)
            
            if threats:
                self.logger.info(f"Extracted {len(threats)} threats using parser chain")
                return threats
            else:
                self.logger.warning(f"Parser chain parsed file but found no threats")
                return None
                
        except Exception as e:
            self.logger.warning(f"Parser chain failed for {file_path.name}: {e}")
            return None
    
    def _convert_threatcomposer_threats(self, parsed_data: Dict, file_path: Path) -> List[Dict[str, Any]]:
        """Convert ThreatComposer parsed data to threat format"""
        threats = []
        
        for threat in parsed_data.get('threats', []):
            # Extract priority from metadata array
            priority = 'Medium'
            for meta in threat.get('metadata', []):
                if meta.get('key') == 'Priority':
                    priority = meta.get('value', 'Medium')
                    break
            
            # Build threat statement from components if not present
            statement = threat.get('statement', '')
            if not statement:
                source = threat.get('threatSource', '')
                prereq = threat.get('prerequisites', '')
                action = threat.get('threatAction', '')
                impact = threat.get('threatImpact', '')
                goals = threat.get('impactedGoal', [])
                assets = threat.get('impactedAssets', [])
                
                goal_str = ', '.join(goals) if isinstance(goals, list) else str(goals)
                asset_str = ', '.join(assets) if isinstance(assets, list) else str(assets)
                
                statement = f"A {source} {prereq}, can {action}, which leads to {impact}, resulting in reduced {goal_str} of {asset_str}."
            
            # Extract category from tags
            category = ', '.join(threat.get('tags', [])) if threat.get('tags') else 'Unknown'
            
            threats.append({
                'id': threat.get('id', f"T{len(threats)+1:03d}"),
                'numericId': threat.get('numericId'),
                'statement': statement,
                'description': statement,
                'threatSource': threat.get('threatSource', ''),
                'prerequisites': threat.get('prerequisites', ''),
                'threatAction': threat.get('threatAction', ''),
                'threatImpact': threat.get('threatImpact', ''),
                'impactedGoal': threat.get('impactedGoal', []),
                'impactedAssets': threat.get('impactedAssets', []),
                'severity': priority,
                'priority': priority,
                'category': category,
                'source': 'threatcomposer',
                'source_file': file_path
            })
        
        return threats
    
    def _convert_json_yaml_threats(self, parsed_data: Dict, file_path: Path) -> List[Dict[str, Any]]:
        """Convert JSON/YAML parsed data to threat format"""
        threats = []
        data = parsed_data.get('data', {})
        threat_data = data.get('threats', [])
        
        # Handle nested structure (e.g., {all_threats: [...], high_severity: [...]})
        if isinstance(threat_data, dict):
            self.logger.debug(f"Processing nested threat structure with keys: {list(threat_data.keys())}")
            # Flatten all nested threat arrays
            for key, value in threat_data.items():
                if isinstance(value, list):
                    self.logger.debug(f"Processing {len(value)} threats from '{key}' section")
                    threats.extend(self._process_threat_list(value, file_path, parsed_data['format']))
        # Handle flat array structure
        elif isinstance(threat_data, list):
            self.logger.debug(f"Processing flat threat array with {len(threat_data)} threats")
            threats = self._process_threat_list(threat_data, file_path, parsed_data['format'])
        else:
            self.logger.warning(f"Unexpected threats data type: {type(threat_data)}")
        
        return threats
    
    def _process_threat_list(self, threat_list: List[Dict], file_path: Path, source_format: str) -> List[Dict[str, Any]]:
        """Process a list of threat dictionaries into standardized format
        
        Args:
            threat_list: List of threat dictionaries
            file_path: Source file path
            source_format: Format of the source (json, yaml, etc.)
            
        Returns:
            List of processed threat dictionaries
        """
        threats = []
        
        for threat in threat_list:
            # Skip non-dict entries
            if not isinstance(threat, dict):
                self.logger.warning(f"Skipping non-dict threat entry: {type(threat)}")
                continue
            
            severity = threat.get('severity', threat.get('priority', 'Medium'))
            threats.append({
                'id': threat.get('id', f"T{len(threats)+1:03d}"),
                'statement': threat.get('statement', threat.get('description', '')),
                'description': threat.get('description', threat.get('statement', '')),
                'threatSource': threat.get('threatSource', ''),
                'prerequisites': threat.get('prerequisites', ''),
                'threatAction': threat.get('threatAction', ''),
                'threatImpact': threat.get('threatImpact', ''),
                'impactedGoal': threat.get('impactedGoal', ''),
                'impactedAssets': threat.get('impactedAssets', ''),
                'severity': severity,
                'priority': threat.get('priority', severity),
                'category': threat.get('category', 'Unknown'),
                'source': source_format,
                'source_file': file_path
            })
        
        return threats
    
    def _convert_markdown_threats(self, parsed_data: Dict) -> List[Dict[str, Any]]:
        """Convert markdown parsed data to threat format"""
        threats = []
        
        for threat in parsed_data.get('threats', []):
            description = threat.get('description', '')
            
            # Extract threat statement from description
            threat_statement = self._extract_threat_statement_from_text(description)
            
            # If no statement found, fall back to title (but this shouldn't happen with proper format)
            if not threat_statement:
                threat_statement = threat.get('title', '')
            
            # Extract structured fields from description if present
            threat_source = extract_field(description, 'Threat Source')
            prerequisites = extract_field(description, 'Prerequisites')
            threat_action = extract_field(description, 'Threat Action')
            threat_impact = extract_field(description, 'Threat Impact')
            impacted_goal = extract_field(description, 'Reduced Goal')
            impacted_assets = extract_field(description, 'Impacted Assets')
            priority = extract_field(description, 'Priority')
            
            # Get severity from threat or extracted priority
            severity = threat.get('severity', priority if priority else 'Medium')
            
            threats.append({
                'id': threat.get('id', f"T{len(threats)+1:03d}"),
                'statement': threat_statement,
                'description': description,
                'threatSource': threat_source,
                'prerequisites': prerequisites,
                'threatAction': threat_action,
                'threatImpact': threat_impact,
                'impactedGoal': impacted_goal,
                'impactedAssets': impacted_assets,
                'severity': severity,
                'priority': priority if priority else severity,
                'category': threat.get('category', 'Unknown'),
                'source': 'markdown',
                'source_file': parsed_data.get('file_path', 'markdown')
            })
        
        return threats
    
    def _extract_threat_statement_from_text(self, text: str) -> str:
        """Extract threat statement from text content
        
        Args:
            text: Text content containing threat statement
            
        Returns:
            Extracted threat statement or empty string
        """
        lines = text.split('\n')
        threat_statement = ""
        capturing = False
        
        for line in lines:
            if '**Threat Statement**' in line and ':' in line:
                # Extract statement from this line
                if '**Threat Statement:**' in line:
                    threat_statement = line.split('**Threat Statement:**', 1)[1].strip()
                elif '**Threat Statement**:' in line:
                    threat_statement = line.split('**Threat Statement**:', 1)[1].strip()
                capturing = True
                continue
            elif capturing and line.strip().startswith('- **'):
                # Hit the first bullet point, stop capturing
                break
            elif capturing and line.strip():
                # Continue capturing multi-line statement
                threat_statement += " " + line.strip()
        
        return threat_statement
    
    def _process_threatcomposer_file(self, threat_file_path: str) -> List[Dict[str, Any]]:
        """Process ThreatComposer file using JQ parser
        
        Args:
            threat_file_path: Path to .tc.json file
            
        Returns:
            List of parsed threats
        """
        try:
            # Get the directory containing the threat_jq.sh script
            tools_dir = Path(__file__).parent.parent
            jq_script = tools_dir / "threat_jq.sh"
            
            if not jq_script.exists():
                self.logger.error(f"JQ script not found at {jq_script}")
                return []
            
            # Make script executable
            os.chmod(jq_script, 0o755)
            
            # Extract threat data using JQ parser
            self.logger.debug(f"Extracting threats using JQ parser...")
            result = subprocess.run(
                [str(jq_script), threat_file_path, "extract"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                self.logger.error(f"JQ extraction failed: {result.stderr}")
                return []
            
            # Parse the extracted JSON data
            try:
                threat_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse JQ output: {e}")
                return []
            
            # Create formatted output file
            output_file = self.formatter.create_formatted_threat_file(threat_data, threat_file_path)
            
            if output_file:
                self.logger.info(f"Created formatted threat file: {Path(output_file).name}")
                # Extract threats from the formatted file
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                return self.extract_threats_from_content(content, output_file)
            
        except Exception as e:
            self.logger.error(f"Error processing ThreatComposer file: {e}")
        
        return []
    
    def extract_threats_from_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Extract individual threats from file content
        
        Args:
            content: File content
            file_path: File path for reference
            
        Returns:
            List of threat dicts
        """
        threats = []
        
        # Split content into threat sections by the #### pattern
        threat_sections = re.split(r'\n(?=#### [A-Za-z0-9\-]+ - )', content)
        
        self.logger.debug(f"Found {len(threat_sections)} threat sections in {Path(file_path).name}")
        
        for section in threat_sections:
            if not section.strip() or '####' not in section:
                continue
                
            # Extract threat ID and category
            threat_header_match = re.search(r'#### ([A-Za-z0-9\-]+) - (.+)', section)
            if not threat_header_match:
                continue
                
            threat_id = threat_header_match.group(1)
            category = threat_header_match.group(2).strip()
            
            # Extract threat statement - simple line-by-line approach
            threat_statement = self._extract_threat_statement(section)
            
            if not threat_statement:
                continue
            
            # Extract structured fields
            fields = self._extract_threat_fields(section)
            
            # Determine priority/severity from section position
            priority = fields.get('priority', 'Medium')
            severity = self._determine_severity(content, threat_id, priority)
            
            threat = {
                "id": threat_id,
                "description": threat_statement,
                "statement": threat_statement,
                "threatSource": fields.get('threatSource', ''),
                "prerequisites": fields.get('prerequisites', ''),
                "threatAction": fields.get('threatAction', ''),
                "threatImpact": fields.get('threatImpact', ''),
                "impactedGoal": fields.get('impactedGoal', ''),
                "impactedAssets": fields.get('impactedAssets', ''),
                "severity": severity,
                "priority": priority,
                "category": category,
                "source_file": file_path
            }
            
            threats.append(threat)
            self.logger.debug(f"Extracted threat {threat_id} with severity: {severity}")
        
        self.logger.info(f"Extracted {len(threats)} threats from {Path(file_path).name}")
        
        # If no threats found with structured format, try legacy extraction
        if not threats:
            threats = self._extract_legacy_threats(content, file_path)
        
        return threats
    
    def _extract_threat_statement(self, section: str) -> str:
        """Extract threat statement from section
        
        Args:
            section: Threat section text
            
        Returns:
            Extracted threat statement
        """
        lines = section.split('\n')
        threat_statement = ""
        capturing = False
        
        for line in lines:
            if '**Threat Statement**' in line and ':' in line:
                # Extract statement from this line
                if '**Threat Statement:**' in line:
                    threat_statement = line.split('**Threat Statement:**', 1)[1].strip()
                elif '**Threat Statement**:' in line:
                    threat_statement = line.split('**Threat Statement**:', 1)[1].strip()
                capturing = True
                continue
            elif capturing and line.strip().startswith('- **'):
                # Hit the first bullet point, stop capturing
                break
            elif capturing and line.strip():
                # Continue capturing multi-line statement
                threat_statement += " " + line.strip()
        
        return threat_statement
    
    def _extract_threat_fields(self, section: str) -> Dict[str, str]:
        """Extract structured fields from threat section
        
        Args:
            section: Threat section text
            
        Returns:
            Dict of extracted fields
        """
        fields = {}
        field_patterns = {
            'threatSource': r'- \*\*Threat Source\*\*:\s*(.+)',
            'prerequisites': r'- \*\*Prerequisites\*\*:\s*(.+)',
            'threatAction': r'- \*\*Threat Action\*\*:\s*(.+)',
            'threatImpact': r'- \*\*Threat Impact\*\*:\s*(.+)',
            'impactedGoal': r'- \*\*Reduced Goal\*\*:\s*(.+)',
            'impactedAssets': r'- \*\*Impacted Assets\*\*:\s*(.+)',
            'priority': r'- \*\*Priority\*\*:\s*(.+)',
            'category_field': r'- \*\*Category\*\*:\s*(.+)'
        }
        
        for field_name, pattern in field_patterns.items():
            match = re.search(pattern, section)
            if match:
                fields[field_name] = match.group(1).strip()
        
        return fields
    
    def _determine_severity(self, content: str, threat_id: str, default_priority: str) -> str:
        """Determine severity based on section position in file
        
        Args:
            content: Full file content
            threat_id: Threat ID to find
            default_priority: Default priority from fields
            
        Returns:
            Severity level (High/Medium/Low)
        """
        severity = default_priority
        
        # Determine which priority section this threat is in
        if '### High Priority Threats' in content:
            high_section_start = content.find('### High Priority Threats')
            medium_section_start = content.find('### Medium Priority Threats')
            low_section_start = content.find('### Low Priority Threats')
            
            threat_position = content.find(f'#### {threat_id}')
            
            if threat_position > high_section_start:
                if medium_section_start == -1 or threat_position < medium_section_start:
                    severity = 'High'
                elif low_section_start == -1 or threat_position < low_section_start:
                    severity = 'Medium'
                else:
                    severity = 'Low'
        
        return severity
    
    def _extract_legacy_threats(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Extract threats from legacy formats
        
        Args:
            content: File content
            file_path: File path for reference
            
        Returns:
            List of threat dicts
        """
        threats = []
        
        # Support multiple patterns for different threat file formats
        threat_pattern1 = r'^#### (T\d+) - (.+?)$'  # #### T001 - Category
        threat_pattern2 = r'^## Threat (\d+) - (.+?)$'  # ## Threat N - Category
        
        lines = content.split('\n')
        current_threat = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Check for threat header (generated format)
            threat_match1 = re.match(threat_pattern1, line)
            if threat_match1:
                if current_threat:
                    threats.append(current_threat)
                
                threat_id = threat_match1.group(1)
                category = threat_match1.group(2).strip()
                
                current_threat = {
                    "id": threat_id,
                    "category": category,
                    "severity": "Medium",
                    "description": "",
                    "source_file": file_path,
                    "line_number": i + 1
                }
                continue
            
            # Check for threat header (legacy format)
            threat_match2 = re.match(threat_pattern2, line)
            if threat_match2:
                if current_threat:
                    threats.append(current_threat)
                
                threat_id = f"T{threat_match2.group(1)}"
                category = threat_match2.group(2).strip()
                
                current_threat = {
                    "id": threat_id,
                    "category": category,
                    "severity": "Medium",
                    "description": "",
                    "source_file": file_path,
                    "line_number": i + 1
                }
                continue
            
            # Extract priority/severity
            if current_threat and line.startswith("- **Priority**:"):
                priority = line.replace("- **Priority**:", "").strip()
                current_threat["severity"] = priority
                continue
            
            # Extract threat statement
            if current_threat and line.startswith("**Threat Statement**:"):
                statement = line.replace("**Threat Statement**:", "").strip()
                current_threat["description"] = statement
                continue
            
            # Add to description (skip empty lines, headers, and metadata)
            elif (current_threat and line and 
                  not line.startswith('#') and 
                  not line.startswith('**') and 
                  not line.startswith('- **') and
                  not line.startswith('---')):
                if current_threat["description"]:
                    current_threat["description"] += " "
                current_threat["description"] += line
        
        # Add last threat
        if current_threat:
            threats.append(current_threat)
        
        return threats
