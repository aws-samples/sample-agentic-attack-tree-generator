"""Information Extraction Tool for parsing threat statements and key project info"""
import re
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

from strands import Tool
import boto3


class InformationExtractionTool(Tool):
    """Tool for extracting key information from context files"""
    
    def __init__(self):
        super().__init__(
            name="information_extraction",
            description="Extract key information including threat statements, technologies, and security objectives"
        )
    
    async def execute(self, context_files: Dict[str, Any], bedrock_model: str, 
                     aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Execute information extraction"""
        
        # Parse threat statements
        threat_statements = self._parse_threat_statements(context_files)
        
        # Extract key project information using LLM
        project_info = await self._extract_project_info(context_files, bedrock_model, aws_profile)
        
        # Filter high severity threats
        high_severity_threats = [t for t in threat_statements if t.get("severity") == "High"]
        
        return {
            "threat_statements": threat_statements,
            "high_severity_threats": high_severity_threats,
            "project_info": project_info,
            "extraction_summary": {
                "total_threats": len(threat_statements),
                "high_severity_count": len(high_severity_threats),
                "technologies_identified": len(project_info.get("technologies", [])),
                "has_security_objectives": bool(project_info.get("security_objectives"))
            }
        }
    
    def _parse_threat_statements(self, context_files: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse threat statements from threat files"""
        threats = []
        
        for threat_file in context_files.get("parsed_content", {}).get("threat_statements", []):
            content = threat_file.get("content", "")
            file_threats = self._extract_threats_from_content(content, threat_file["path"])
            threats.extend(file_threats)
        
        return threats
    
    def _extract_threats_from_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Extract individual threats from file content"""
        threats = []
        
        # Pattern: ## Threat N - Category [Severity]
        threat_pattern = r'^## Threat (\d+) - (.+?)(?:\[(\w+)\])?\s*$'
        
        lines = content.split('\n')
        current_threat = None
        
        for i, line in enumerate(lines):
            match = re.match(threat_pattern, line.strip())
            
            if match:
                # Save previous threat if exists
                if current_threat:
                    threats.append(current_threat)
                
                # Start new threat
                threat_id = match.group(1)
                category = match.group(2).strip()
                severity = match.group(3) if match.group(3) else "Medium"  # Default to Medium
                
                current_threat = {
                    "id": f"T{threat_id}",
                    "category": category,
                    "severity": severity,
                    "description": "",
                    "source_file": file_path,
                    "line_number": i + 1
                }
            
            elif current_threat and line.strip() and not line.startswith('#'):
                # Add to description
                if current_threat["description"]:
                    current_threat["description"] += " "
                current_threat["description"] += line.strip()
        
        # Add last threat
        if current_threat:
            threats.append(current_threat)
        
        return threats
    
    async def _extract_project_info(self, context_files: Dict[str, Any], bedrock_model: str, 
                                   aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Extract key project information using Bedrock LLM"""
        
        # Combine README content for analysis
        readme_content = ""
        for readme in context_files.get("parsed_content", {}).get("readmes", []):
            readme_content += f"\n\n--- {readme['path']} ---\n{readme['content']}"
        
        if not readme_content.strip():
            return {"error": "No README content found for analysis"}
        
        # Prepare prompt for information extraction
        prompt = self._build_extraction_prompt(readme_content)
        
        try:
            # Call Bedrock
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            response = bedrock.invoke_model(
                modelId=bedrock_model,
                body=json.dumps(body)
            )
            
            response_body = json.loads(response['body'].read())
            extracted_text = response_body['content'][0]['text']
            
            # Parse JSON response
            return json.loads(extracted_text)
            
        except Exception as e:
            return {"error": f"Failed to extract project info: {str(e)}"}
    
    def _build_extraction_prompt(self, readme_content: str) -> str:
        """Build prompt for project information extraction"""
        return f"""Analyze the following project documentation and extract key information in JSON format:

{readme_content}

Extract the following information and return as valid JSON:
{{
    "application_name": "name of the application/project",
    "technologies": ["list", "of", "technologies", "programming languages", "frameworks"],
    "sector": "industry sector (e.g., finance, healthcare, e-commerce)",
    "security_objectives": {{
        "confidentiality": true/false,
        "integrity": true/false, 
        "availability": true/false
    }},
    "architecture_type": "type of architecture (e.g., microservices, monolith, serverless)",
    "deployment_environment": "deployment target (e.g., AWS, on-premises, hybrid)"
}}

Focus on extracting factual information. If information is not available, use null or empty arrays."""
