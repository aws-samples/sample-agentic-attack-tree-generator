"""Threat generation using Strands Agent"""
from typing import List, Dict, Any, Optional
from pathlib import Path
from ...core import BaseAgent
from .text_utils import parse_json_response
from .threat_formatter import ThreatFormatter


class ThreatGenerator(BaseAgent):
    """Generates and reformats threat statements using LLM"""
    
    def __init__(self, logger, formatter: ThreatFormatter):
        """Initialize generator
        
        Args:
            logger: Logger instance
            formatter: ThreatFormatter instance for output creation
        """
        self.logger = logger
        self.formatter = formatter
    
    def generate_threats_from_existing_content(self, threat_files_without_statements: List[Dict[str, Any]],
                                              project_info: Dict[str, Any], bedrock_model: str,
                                              aws_profile: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate threat statements from existing threat model content
        
        Args:
            threat_files_without_statements: List of file info dicts
            project_info: Project information dict
            bedrock_model: Bedrock model ID
            aws_profile: Optional AWS profile
            
        Returns:
            List of generated threats
        """
        # Combine all threat model content
        threat_model_content = ""
        for file_info in threat_files_without_statements:
            file_name = Path(file_info["path"]).name
            content = file_info["content"]
            threat_model_content += f"\n\n--- {file_name} ---\n{content}"
        
        # Build user prompt
        user_prompt = f"""Application Context:
- Application: {project_info.get('application_name', 'Unknown')}
- Technologies: {', '.join(project_info.get('technologies', []))}

Existing Threat Model Content:
{threat_model_content}
"""

        try:
            # Create Strands agent with threat-generation-existing prompt
            agent = self.get_strands_agent(
                prompt_file='threat-generation-existing.md',
                temperature=0,
                model_name=bedrock_model
            )
            
            # Run agent synchronously
            result = agent(user_prompt)
            
            # Parse JSON response
            threats_data = parse_json_response(str(result))
            
            generated_threats = []
            for threat in threats_data.get("threats", []):
                generated_threats.append({
                    "id": threat.get("id", "T000"),
                    "description": threat.get("statement", ""),
                    "severity": threat.get("priority", "Medium"),
                    "category": threat.get("category", "Unknown"),
                    "source_file": "Generated from existing threat models"
                })
            
            self.logger.info(f"Generated {len(generated_threats)} threat statements from existing content")
            return generated_threats
            
        except Exception as e:
            self.logger.warning(f"Failed to generate threats from existing content: {e}")
            return []
    
    def generate_threats_with_bedrock(self, context_files: Dict[str, Any], project_info: Dict[str, Any],
                                     bedrock_model: str, aws_profile: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate threat statements using Strands Agent when none exist
        
        Args:
            context_files: Dict with discovered files and content
            project_info: Extracted project information
            bedrock_model: Bedrock model ID
            aws_profile: Optional AWS profile
            
        Returns:
            List of generated threats
        """
        # Prepare content for analysis (reuse project extractor's method)
        from .project_extractor import ProjectExtractor
        extractor = ProjectExtractor(self.logger)
        content_summary = extractor._prepare_content(context_files)
        
        # Build user prompt
        user_prompt = f"""Application Context:
- Application: {project_info.get('application_name', 'Unknown')}
- Technologies: {', '.join(project_info.get('technologies', []))}
- Architecture: {project_info.get('architecture_type', 'Unknown')}
- Deployment: {project_info.get('deployment_environment', 'Unknown')}
- Sector: {project_info.get('sector', 'Unknown')}

Available Content and Documentation:
{content_summary}
"""

        try:
            # Create Strands agent with threat-generation-new prompt
            agent = self.get_strands_agent(
                prompt_file='threat-generation-new.md',
                temperature=0,
                model_name=bedrock_model
            )
            
            # Run agent synchronously
            result = agent(user_prompt)
            
            # Parse the JSON response with robust error handling
            try:
                threat_data = parse_json_response(str(result))
                self.logger.info("Successfully extracted complete JSON structure")
            except Exception as e:
                self.logger.warning(f"JSON parsing failed: {e}")
                print(f"Raw content: {str(result)[:500]}...")
                return self.get_fallback_threats(project_info)
            
            # Process the threat data
            threats = []
            
            for threat in threat_data.get('threats', []):
                threats.append({
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
                })
            
            # Create markdown file with generated threats
            filename = self.formatter.create_threats_markdown_file(
                threats, context_files.get('project_path', '.'), project_info
            )
            
            self.logger.info(f"Generated {len(threats)} threat statements using AI analysis")
            self.logger.info(f"Threats saved to {filename}")
            return threats
            
        except Exception as e:
            self.logger.warning(f"Failed to generate threats: {e}")
            fallback_threats = self.get_fallback_threats(project_info)
            filename = self.formatter.create_threats_markdown_file(
                fallback_threats, context_files.get('project_path', '.'), project_info
            )
            self.logger.info(f"Fallback threats saved to {filename}")
            return fallback_threats
    
    def reformat_threats(self, original_file: str, content: str, 
                        context_files: Dict[str, Any]) -> str:
        """Reformat threat file using Strands Agent
        
        Args:
            original_file: Path to original file
            content: File content to reformat
            context_files: Context with model_id
            
        Returns:
            Path to reformatted file or None on error
        """
        try:
            # Create new filename
            original_path = Path(original_file)
            new_filename = f"{original_path.stem}_reformatted_threat_statements.md"
            new_file_path = original_path.parent / new_filename
            
            # Get model from context
            model_id = context_files.get('model_id')
            if not model_id:
                raise ValueError("bedrock_model must be provided in context_files")
            
            # Create Strands agent with threat-format-fixing prompt
            agent = self.get_strands_agent(
                prompt_file='threat-format-fixing.md',
                temperature=0,
                model_name=model_id
            )
            
            # Build user prompt with original document content
            user_prompt = f"""Original document content:
{content}
"""
            
            # Run agent synchronously
            result = agent(user_prompt)
            reformatted_content = str(result)
            
            # Fix the counts by parsing the actual content
            reformatted_content = self.formatter.fix_threat_counts(reformatted_content)
            
            # Save reformatted file
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write(reformatted_content)
            
            print(f"💾 Created reformatted threat file: {new_filename}")
            return str(new_file_path)
            
        except Exception as e:
            self.logger.warning(f"Failed to reformat threats: {e}")
            return None
    
    def reformat_mixed_threats(self, original_file: str, content: str, 
                              correct_threats: List[Dict], context_files: Dict[str, Any]) -> str:
        """Reformat threat file with mixed correct/incorrect threats
        
        Args:
            original_file: Path to original file
            content: File content
            correct_threats: List of correctly formatted threats to preserve
            context_files: Context with model_id
            
        Returns:
            Path to reformatted file or None on error
        """
        try:
            # Create new filename
            original_path = Path(original_file)
            new_filename = f"{original_path.stem}_reformatted_threat_statements.md"
            new_file_path = original_path.parent / new_filename
            
            # Prepare correct threats summary
            correct_threats_summary = "\n".join([
                f"- {threat.get('description', 'No description')}" for threat in correct_threats
            ])
            
            # Get model from context
            model_id = context_files.get('model_id')
            if not model_id:
                raise ValueError("bedrock_model must be provided in context_files")
            
            # Create Strands agent with threat-mixed-format prompt
            agent = self.get_strands_agent(
                prompt_file='threat-mixed-format.md',
                temperature=0,
                model_name=model_id
            )
            
            # Build user prompt with correctly formatted threats to preserve
            user_prompt = f"""PRESERVE these correctly formatted threats exactly as they are:
{correct_threats_summary}
"""
            
            # Run agent synchronously
            result = agent(user_prompt)
            reformatted_content = str(result)
            
            # Fix the counts by parsing the actual content
            reformatted_content = self.formatter.fix_threat_counts(reformatted_content)
            
            # Save reformatted file
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write(reformatted_content)
            
            print(f"💾 Created reformatted threat file: {new_filename}")
            return str(new_file_path)
            
        except Exception as e:
            self.logger.warning(f"Failed to reformat mixed threats: {e}")
            return None
    
    def get_fallback_threats(self, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Provide basic fallback threats when AI generation fails
        
        Args:
            project_info: Project information dict
            
        Returns:
            List of fallback threat dicts
        """
        return [
            {
                "id": "T001",
                "statement": "A malicious attacker with network access, can exploit weak authentication mechanisms, which leads to unauthorized system access, resulting in reduced confidentiality of application data.",
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
                "statement": "A malicious user with application access, can perform injection attacks, which leads to data manipulation or extraction, resulting in reduced integrity of database records.",
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
                "statement": "A distributed attacker with internet connectivity, can launch denial of service attacks, which leads to service unavailability, resulting in reduced availability of application services.",
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
                "statement": "A network eavesdropper with packet capture capabilities, can intercept unencrypted communications, which leads to sensitive data exposure, resulting in reduced confidentiality of transmitted data.",
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
