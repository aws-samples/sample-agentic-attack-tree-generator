"""Information Extraction Tool for parsing threat statements and key project info"""
import re
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

# Mock Strands Tool for testing
class Tool:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

import boto3


class InformationExtractionTool(Tool):
    """Tool for extracting key information from context files"""
    
    def __init__(self):
        super().__init__(
            name="information_extraction",
            description="Extract key information including threat statements, technologies, and security objectives"
        )
    
    async def execute(self, context_files: Dict[str, Any], bedrock_model: str, 
                     aws_profile: Optional[str] = None, interactive: bool = False) -> Dict[str, Any]:
        """Execute information extraction with threat generation if needed"""
        
        # Parse existing threat statements
        threat_statements = self._parse_threat_statements(context_files)
        
        # Extract key project information using LLM
        project_info = await self._extract_project_info(context_files, bedrock_model, aws_profile)
        
        # If no threat statements found, generate them using Bedrock
        if not threat_statements:
            print("🤖 No threat statements found - generating threats using AI analysis...")
            generated_threats = await self._generate_threats_with_bedrock(
                context_files, project_info, bedrock_model, aws_profile
            )
            threat_statements.extend(generated_threats)
        
        # User validation if interactive
        if interactive and not project_info.get("error"):
            project_info = self._validate_with_user(project_info)
        
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
                "has_security_objectives": bool(project_info.get("security_objectives")),
                "user_validated": interactive and not project_info.get("error")
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
        
        # Pattern: ## Threat N - Category
        threat_pattern = r'^## Threat (\d+) - (.+?)$'
        severity_pattern = r'^\[(\w+)\]$'
        
        lines = content.split('\n')
        current_threat = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Check for threat header
            threat_match = re.match(threat_pattern, line)
            if threat_match:
                # Save previous threat if exists
                if current_threat:
                    threats.append(current_threat)
                
                # Start new threat
                threat_id = threat_match.group(1)
                category = threat_match.group(2).strip()
                
                current_threat = {
                    "id": f"T{threat_id}",
                    "category": category,
                    "severity": "Medium",  # Default
                    "description": "",
                    "source_file": file_path,
                    "line_number": i + 1
                }
            
            # Check for severity on separate line
            elif current_threat and re.match(severity_pattern, line):
                severity_match = re.match(severity_pattern, line)
                current_threat["severity"] = severity_match.group(1)
            
            # Add to description (skip empty lines and headers)
            elif current_threat and line and not line.startswith('#') and not re.match(severity_pattern, line):
                if current_threat["description"]:
                    current_threat["description"] += " "
                current_threat["description"] += line
        
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
            try:
                return json.loads(extracted_text)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                import re
                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', extracted_text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(1))
                else:
                    return {"error": f"Failed to parse JSON response: {extracted_text[:200]}..."}
            
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

Focus on extracting factual information. If information is not available, use null or empty arrays.
Return ONLY the JSON object, no additional text or markdown formatting."""
    
    def _validate_with_user(self, project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Allow user to validate and modify extracted information"""
        from rich.console import Console
        from rich.panel import Panel
        from rich.prompt import Prompt, Confirm
        
        console = Console()
        
        console.print(Panel.fit(
            "[bold blue]Project Information Validation[/bold blue]\n"
            "Please review and validate the extracted information",
            border_style="blue"
        ))
        
        # Display extracted information
        console.print("\n[bold]Extracted Information:[/bold]")
        console.print(f"📱 Application: [cyan]{project_info.get('application_name', 'Unknown')}[/cyan]")
        console.print(f"🏢 Sector: [cyan]{project_info.get('sector', 'Unknown')}[/cyan]")
        console.print(f"🏗️  Architecture: [cyan]{project_info.get('architecture_type', 'Unknown')}[/cyan]")
        console.print(f"☁️  Deployment: [cyan]{project_info.get('deployment_environment', 'Unknown')}[/cyan]")
        
        if project_info.get('technologies'):
            console.print(f"🔧 Technologies: [cyan]{', '.join(project_info['technologies'])}[/cyan]")
        
        if project_info.get('security_objectives'):
            objectives = project_info['security_objectives']
            console.print(f"🔒 Security Objectives:")
            console.print(f"   • Confidentiality: [cyan]{objectives.get('confidentiality', False)}[/cyan]")
            console.print(f"   • Integrity: [cyan]{objectives.get('integrity', False)}[/cyan]")
            console.print(f"   • Availability: [cyan]{objectives.get('availability', False)}[/cyan]")
        
        # Ask for validation
        if not Confirm.ask("\n✅ Is this information correct?", default=True):
            console.print("\n[yellow]Please provide corrections:[/yellow]")
            
            # Allow corrections
            if Confirm.ask("Update application name?", default=False):
                project_info['application_name'] = Prompt.ask("Application name", default=project_info.get('application_name', ''))
            
            if Confirm.ask("Update sector?", default=False):
                project_info['sector'] = Prompt.ask("Sector", default=project_info.get('sector', ''))
            
            if Confirm.ask("Update technologies?", default=False):
                tech_input = Prompt.ask("Technologies (comma-separated)", default=', '.join(project_info.get('technologies', [])))
                project_info['technologies'] = [t.strip() for t in tech_input.split(',') if t.strip()]
            
            if Confirm.ask("Update architecture type?", default=False):
                project_info['architecture_type'] = Prompt.ask("Architecture type", default=project_info.get('architecture_type', ''))
            
            console.print("✅ [green]Information updated![/green]")
        
        # Save validated info to file
        self._save_validated_info(project_info)
        
        return project_info
    
    async def _generate_threats_with_bedrock(self, context_files: Dict[str, Any], 
                                           project_info: Dict[str, Any], bedrock_model: str, 
                                           aws_profile: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate threat statements using Bedrock when none exist"""
        
        # Prepare context for threat generation
        context_summary = self._prepare_threat_generation_context(context_files, project_info)
        
        prompt = f"""You are a cybersecurity expert analyzing an application for threat modeling.

Based on the following information, generate 8-12 realistic threat statements with priorities:

{context_summary}

Generate threats in this JSON format:
{{
  "threats": [
    {{
      "id": "T001",
      "statement": "Detailed threat description",
      "severity": "High|Medium|Low",
      "category": "category name",
      "likelihood": "High|Medium|Low",
      "impact": "impact description"
    }}
  ]
}}

Focus on:
- Common attack vectors for the identified technologies
- Architecture-specific vulnerabilities
- Data protection concerns
- Access control issues
- Network security threats

Ensure a mix of High (3-4), Medium (4-6), and Low (2-3) severity threats."""

        try:
            # Use Bedrock to generate threats
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            response = bedrock.invoke_model(
                modelId=bedrock_model,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            
            # Parse the JSON response
            threat_data = json.loads(content)
            threats = []
            
            for threat in threat_data.get('threats', []):
                threats.append({
                    "id": threat.get('id', ''),
                    "statement": threat.get('statement', ''),
                    "severity": threat.get('severity', 'Medium'),
                    "category": threat.get('category', 'General'),
                    "likelihood": threat.get('likelihood', 'Medium'),
                    "impact": threat.get('impact', ''),
                    "source": "AI Generated"
                })
            
            print(f"✅ Generated {len(threats)} threat statements using AI analysis")
            return threats
            
        except Exception as e:
            print(f"⚠️  Failed to generate threats with Bedrock: {e}")
            # Return basic fallback threats
            return self._get_fallback_threats(project_info)
    
    def _prepare_threat_generation_context(self, context_files: Dict[str, Any], 
                                         project_info: Dict[str, Any]) -> str:
        """Prepare context summary for threat generation"""
        context_parts = []
        
        # Application info
        if project_info.get('application_name'):
            context_parts.append(f"Application: {project_info['application_name']}")
        
        if project_info.get('technologies'):
            context_parts.append(f"Technologies: {', '.join(project_info['technologies'])}")
        
        if project_info.get('architecture_type'):
            context_parts.append(f"Architecture: {project_info['architecture_type']}")
        
        if project_info.get('deployment_environment'):
            context_parts.append(f"Deployment: {project_info['deployment_environment']}")
        
        # Add documentation content (first 500 chars from each file)
        parsed_content = context_files.get('parsed_content', {})
        for category, files in parsed_content.items():
            if files and category in ['readmes', 'other_docs']:
                for file_info in files[:2]:  # Max 2 files per category
                    content = file_info.get('content', '')[:500]
                    if content:
                        context_parts.append(f"{category.title()}: {content}...")
        
        # Note about diagrams
        diagrams = parsed_content.get('architecture_diagrams', [])
        if diagrams:
            context_parts.append(f"Architecture diagrams available: {len(diagrams)} files")
        
        return '\n\n'.join(context_parts)
    
    def _get_fallback_threats(self, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Provide basic fallback threats when AI generation fails"""
        return [
            {
                "id": "T001",
                "statement": "Unauthorized access to application data through weak authentication",
                "severity": "High",
                "category": "Authentication",
                "source": "Fallback"
            },
            {
                "id": "T002", 
                "statement": "Data breach through SQL injection or similar injection attacks",
                "severity": "High",
                "category": "Injection",
                "source": "Fallback"
            },
            {
                "id": "T003",
                "statement": "Denial of service attacks affecting application availability",
                "severity": "Medium",
                "category": "Availability",
                "source": "Fallback"
            },
            {
                "id": "T004",
                "statement": "Insecure data transmission exposing sensitive information",
                "severity": "Medium",
                "category": "Cryptography",
                "source": "Fallback"
            }
        ]
    
    def _save_validated_info(self, project_info: Dict[str, Any]) -> None:
        """Save validated information to markdown file"""
        from pathlib import Path
        import json
        
        # Create .tf directory if it doesn't exist
        tf_dir = Path.cwd() / ".tf"
        tf_dir.mkdir(exist_ok=True)
        
        # Save as markdown
        info_file = tf_dir / "project_info.md"
        
        content = f"""# Project Information

## Application Details
- **Name**: {project_info.get('application_name', 'Unknown')}
- **Sector**: {project_info.get('sector', 'Unknown')}
- **Architecture**: {project_info.get('architecture_type', 'Unknown')}
- **Deployment**: {project_info.get('deployment_environment', 'Unknown')}

## Technologies
{chr(10).join(f'- {tech}' for tech in project_info.get('technologies', []))}

## Security Objectives
"""
        
        if project_info.get('security_objectives'):
            objectives = project_info['security_objectives']
            content += f"""- **Confidentiality**: {objectives.get('confidentiality', False)}
- **Integrity**: {objectives.get('integrity', False)}
- **Availability**: {objectives.get('availability', False)}
"""
        
        content += f"""
## Extraction Metadata
- **Extracted on**: {__import__('datetime').datetime.now().isoformat()}
- **User validated**: Yes
"""
        
        info_file.write_text(content)
        
        # Also save as JSON for programmatic access
        json_file = tf_dir / "project_info.json"
        with open(json_file, 'w') as f:
            json.dump(project_info, f, indent=2)
