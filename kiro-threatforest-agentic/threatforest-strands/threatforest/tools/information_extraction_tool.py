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
            print("🤖 No threat statements found - generating threat statements using AI analysis...")
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
        """Extract project information using Bedrock with all discovered content including images"""
        
        # Prepare all discovered content for Bedrock analysis
        content_for_analysis = self._prepare_all_content_for_bedrock(context_files)
        
        prompt = f"""You are a cybersecurity expert analyzing an application. Extract key information from the provided content including text documents and architecture diagrams.

Content to analyze:
{content_for_analysis}

Extract and return information in this JSON format:
{{
  "application_name": "extracted application name",
  "sector": "industry sector (e.g., Healthcare, Finance, E-commerce)",
  "architecture_type": "architecture pattern (e.g., Microservices, Monolithic, Serverless)",
  "deployment_environment": "deployment type (e.g., Cloud, On-premises, Hybrid)",
  "technologies": ["list", "of", "technologies", "identified"],
  "security_objectives": {{
    "confidentiality": true/false,
    "integrity": true/false,
    "availability": true/false
  }},
  "data_types": ["types", "of", "data", "handled"],
  "external_dependencies": ["external", "services", "or", "apis"],
  "network_architecture": "network setup description from diagrams",
  "key_components": ["main", "system", "components", "from", "diagrams"]
}}

Focus on:
- Application name and purpose from documentation
- Technology stack and frameworks mentioned
- Architecture patterns and deployment model
- Data types and security requirements
- External integrations and dependencies
- Network topology and components visible in architecture diagrams
- System boundaries and data flows from diagrams
"""

        try:
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            # Prepare messages with text and images
            messages = self._prepare_bedrock_messages(prompt, context_files)
            
            response = bedrock.invoke_model(
                modelId=bedrock_model,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 200000,
                    "messages": messages
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            
            # Parse JSON response
            try:
                project_info = json.loads(content)
                return project_info
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                import re
                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(1))
                else:
                    return {"error": f"Failed to parse JSON response: {content[:200]}..."}
            
        except Exception as e:
            print(f"⚠️  Bedrock extraction failed: {e}")
            return {
                "error": str(e),
                "application_name": "Unknown Application",
                "technologies": [],
                "sector": "Unknown"
            }
    
    def _prepare_all_content_for_bedrock(self, context_files: Dict[str, Any]) -> str:
        """Prepare all discovered content for Bedrock analysis"""
        content_parts = []
        
        # Add parsed text content
        parsed_content = context_files.get('parsed_content', {})
        for category, files in parsed_content.items():
            if files:
                content_parts.append(f"\n=== {category.upper()} ===")
                for file_info in files:
                    file_path = file_info.get('path', 'unknown')
                    file_content = file_info.get('content', '')
                    content_parts.append(f"\nFile: {file_path}")
                    content_parts.append(file_content[:2000])  # Limit content length
        
        # Note about images and PDFs (will be handled separately in messages)
        discovered_files = context_files.get('discovered_files', {})
        image_files = discovered_files.get('architecture_diagrams', [])
        if image_files:
            content_parts.append(f"\n=== ARCHITECTURE DIAGRAMS ===")
            content_parts.append(f"Found {len(image_files)} architecture diagrams:")
            for img_path in image_files:
                content_parts.append(f"- {img_path}")
            content_parts.append("(Diagram content will be analyzed from the images provided)")
        
        return '\n'.join(content_parts)
    
    def _prepare_bedrock_messages(self, prompt: str, context_files: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prepare messages for Bedrock including images"""
        import base64
        
        messages = []
        content_blocks = []
        
        # Add text content
        content_blocks.append({
            "type": "text",
            "text": prompt
        })
        
        # Add images if any
        discovered_files = context_files.get('discovered_files', {})
        image_files = discovered_files.get('architecture_diagrams', [])
        
        for img_path in image_files[:3]:  # Limit to 3 images to avoid token limits
            try:
                if img_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                    with open(img_path, 'rb') as img_file:
                        img_data = base64.b64encode(img_file.read()).decode('utf-8')
                        
                    # Determine media type
                    if img_path.lower().endswith('.png'):
                        media_type = "image/png"
                    else:
                        media_type = "image/jpeg"
                    
                    content_blocks.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": img_data
                        }
                    })
                    print(f"📷 Added image to analysis: {img_path}")
            except Exception as e:
                print(f"⚠️  Failed to load image {img_path}: {e}")
        
        messages.append({
            "role": "user",
            "content": content_blocks
        })
        
        return messages
    
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
        
        if project_info.get('sector'):
            context_parts.append(f"Sector: {project_info['sector']}")
        
        # Add documentation content (first 500 chars from each file)
        parsed_content = context_files.get('parsed_content', {})
        for category, files in parsed_content.items():
            if files and category in ['readmes', 'other_docs']:
                for file_info in files[:2]:  # Max 2 files per category
                    content = file_info.get('content', '')[:500]
                    if content:
                        context_parts.append(f"{category.title()}: {content}...")
        
        # Note about diagrams
        discovered_files = context_files.get('discovered_files', {})
        diagrams = discovered_files.get('architecture_diagrams', []) if discovered_files else []
        if diagrams:
            context_parts.append(f"Architecture diagrams available: {len(diagrams)} files")
        
        return '\n\n'.join(context_parts)
    
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

Based on the following information, generate 8-12 realistic threat statements using this EXACT syntax:
"A [threat source] with [pre-requisites], can [threat action], which leads to [threat impact], resulting in [reduced goal] of [impacted assets]."

Context:
{context_summary}

Generate threats in this JSON format:
{{
  "threats": [
    {{
      "id": "T001",
      "statement": "A malicious attacker with network access, can perform SQL injection attacks, which leads to unauthorized data access, resulting in reduced confidentiality of customer database.",
      "priority": "High",
      "category": "Injection",
      "threat_source": "malicious attacker",
      "prerequisites": "network access",
      "threat_action": "perform SQL injection attacks",
      "threat_impact": "unauthorized data access",
      "reduced_goal": "confidentiality",
      "impacted_assets": "customer database"
    }}
  ]
}}

Requirements:
- Follow the EXACT syntax for each threat statement
- Include 3-4 High priority threats (critical security issues)
- Include 4-6 Medium priority threats (important but not critical)
- Include 2-3 Low priority threats (minor security concerns)
- Focus on realistic threats for the identified technologies and architecture
- Ensure each threat has all required components: source, prerequisites, action, impact, goal, assets"""

        try:
            # Use Bedrock to generate threats
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            bedrock = session.client('bedrock-runtime', region_name='us-east-1')
            
            response = bedrock.invoke_model(
                modelId=bedrock_model,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 200000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            
            # Parse the JSON response with better error handling
            try:
                threat_data = json.loads(content)
            except json.JSONDecodeError as e:
                print(f"⚠️  JSON parsing failed: {e}")
                print(f"Raw content: {content[:500]}...")
                # Try to extract JSON from markdown code blocks
                import re
                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                if json_match:
                    try:
                        threat_data = json.loads(json_match.group(1))
                    except json.JSONDecodeError:
                        print("⚠️  Failed to parse JSON from code block, using fallback")
                        return self._get_fallback_threats(project_info)
                else:
                    print("⚠️  No JSON found in response, using fallback")
                    return self._get_fallback_threats(project_info)
            threats = []
            
            for threat in threat_data.get('threats', []):
                threats.append({
                    "id": threat.get('id', ''),
                    "statement": threat.get('statement', ''),
                    "severity": threat.get('priority', 'Medium'),  # Map priority to severity
                    "category": threat.get('category', 'General'),
                    "threat_source": threat.get('threat_source', ''),
                    "prerequisites": threat.get('prerequisites', ''),
                    "threat_action": threat.get('threat_action', ''),
                    "threat_impact": threat.get('threat_impact', ''),
                    "reduced_goal": threat.get('reduced_goal', ''),
                    "impacted_assets": threat.get('impacted_assets', ''),
                    "source": "AI Generated"
                })
            
            # Create markdown file with generated threats
            filename = self._create_threats_markdown_file(threats, context_files.get('project_path', '.'), project_info)
            
            print(f"✅ Generated {len(threats)} threat statements using AI analysis")
            print(f"📄 Threats saved to {filename}")
            return threats
            
        except Exception as e:
            print(f"⚠️  Failed to generate threats with Bedrock: {e}")
            # Return basic fallback threats with proper syntax
            fallback_threats = self._get_fallback_threats(project_info)
            filename = self._create_threats_markdown_file(fallback_threats, context_files.get('project_path', '.'), project_info)
            print(f"📄 Fallback threats saved to {filename}")
            return fallback_threats
    
    def _create_threats_markdown_file(self, threats: List[Dict[str, Any]], project_path: str, project_info: Dict[str, Any] = None) -> str:
        """Create a markdown file with generated threat statements"""
        
        # Generate filename with application name
        app_name = "Unknown"
        if project_info and project_info.get('application_name'):
            app_name = project_info['application_name']
        
        # Clean application name for filename
        clean_app_name = re.sub(r'[^\w\s-]', '', app_name).strip()
        clean_app_name = re.sub(r'[-\s]+', '_', clean_app_name)
        filename = f"{clean_app_name}_generated_threat_statements.md"
        
        markdown_content = f"""# Generated Threat Statements - {app_name}

*This file was automatically generated by ThreatForest AI analysis.*

## Application Context
- **Application**: {app_name}
- **Generated**: {Path().cwd()}
- **Total Threats**: {len(threats)}
- **High Priority**: {len([t for t in threats if t.get('severity') == 'High'])}
- **Medium Priority**: {len([t for t in threats if t.get('severity') == 'Medium'])}
- **Low Priority**: {len([t for t in threats if t.get('severity') == 'Low'])}

## Threat Statements

"""
        
        # Group threats by priority
        high_threats = [t for t in threats if t.get('severity') == 'High']
        medium_threats = [t for t in threats if t.get('severity') == 'Medium']
        low_threats = [t for t in threats if t.get('severity') == 'Low']
        
        for priority, threat_list in [("High", high_threats), ("Medium", medium_threats), ("Low", low_threats)]:
            if threat_list:
                markdown_content += f"### {priority} Priority Threats\n\n"
                
                for threat in threat_list:
                    markdown_content += f"#### {threat.get('id', 'T000')} - {threat.get('category', 'General')}\n\n"
                    markdown_content += f"**Threat Statement**: {threat.get('statement', '')}\n\n"
                    
                    # Add breakdown if available
                    if threat.get('threat_source'):
                        markdown_content += f"- **Threat Source**: {threat.get('threat_source', '')}\n"
                        markdown_content += f"- **Prerequisites**: {threat.get('prerequisites', '')}\n"
                        markdown_content += f"- **Threat Action**: {threat.get('threat_action', '')}\n"
                        markdown_content += f"- **Threat Impact**: {threat.get('threat_impact', '')}\n"
                        markdown_content += f"- **Reduced Goal**: {threat.get('reduced_goal', '')}\n"
                        markdown_content += f"- **Impacted Assets**: {threat.get('impacted_assets', '')}\n"
                    
                    markdown_content += f"- **Priority**: {priority}\n"
                    markdown_content += f"- **Category**: {threat.get('category', 'General')}\n\n"
                    markdown_content += "---\n\n"
        
        markdown_content += """
## Usage Notes

These threat statements were generated using AI analysis of your application context. They follow the standard threat modeling syntax:

**"A [threat source] with [pre-requisites], can [threat action], which leads to [threat impact], resulting in [reduced goal] of [impacted assets]."**

### Next Steps
1. Review and validate these threat statements
2. Modify or add threats as needed for your specific context
3. Use these threats as input for attack tree generation
4. Consider implementing mitigations for high-priority threats

### Customization
You can edit this file to:
- Add more specific threat statements
- Adjust priority levels
- Include additional context or mitigations
- Remove threats that don't apply to your application
"""
        
        # Write to file
        output_path = Path(project_path) / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        return filename
    
    def _get_fallback_threats(self, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Provide basic fallback threats with proper syntax when AI generation fails"""
        return [
            {
                "id": "T001",
                "statement": "A malicious attacker with network access, can exploit weak authentication mechanisms, which leads to unauthorized system access, resulting in reduced confidentiality of application data.",
                "severity": "High",
                "category": "Authentication",
                "threat_source": "malicious attacker",
                "prerequisites": "network access",
                "threat_action": "exploit weak authentication mechanisms",
                "threat_impact": "unauthorized system access",
                "reduced_goal": "confidentiality",
                "impacted_assets": "application data",
                "source": "Fallback"
            },
            {
                "id": "T002", 
                "statement": "A malicious user with application access, can perform injection attacks, which leads to data manipulation or extraction, resulting in reduced integrity of database records.",
                "severity": "High",
                "category": "Injection",
                "threat_source": "malicious user",
                "prerequisites": "application access",
                "threat_action": "perform injection attacks",
                "threat_impact": "data manipulation or extraction",
                "reduced_goal": "integrity",
                "impacted_assets": "database records",
                "source": "Fallback"
            },
            {
                "id": "T003",
                "statement": "A distributed attacker with internet connectivity, can launch denial of service attacks, which leads to service unavailability, resulting in reduced availability of application services.",
                "severity": "Medium",
                "category": "Availability",
                "threat_source": "distributed attacker",
                "prerequisites": "internet connectivity",
                "threat_action": "launch denial of service attacks",
                "threat_impact": "service unavailability",
                "reduced_goal": "availability",
                "impacted_assets": "application services",
                "source": "Fallback"
            },
            {
                "id": "T004",
                "statement": "A network eavesdropper with packet capture capabilities, can intercept unencrypted communications, which leads to sensitive data exposure, resulting in reduced confidentiality of transmitted data.",
                "severity": "Medium",
                "category": "Cryptography",
                "threat_source": "network eavesdropper",
                "prerequisites": "packet capture capabilities",
                "threat_action": "intercept unencrypted communications",
                "threat_impact": "sensitive data exposure",
                "reduced_goal": "confidentiality",
                "impacted_assets": "transmitted data",
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
