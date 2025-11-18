"""Project metadata extraction using Strands Agent"""
import json
from typing import Dict, Any, Optional
from pathlib import Path
from src.config import config
from boto3 import Session
from strands import Agent
from strands.models import BedrockModel
from strands.handlers import null_callback_handler
from .text_utils import parse_json_response


class ProjectExtractor:
    """Extracts project metadata and context using LLM analysis"""
    
    def __init__(self, logger):
        """Initialize extractor
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
    
    def extract_project_info(self, context_files: Dict[str, Any], bedrock_model: str,
                            aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Extract project information using Strands Agent
        
        Args:
            context_files: Dict containing discovered files and content
            bedrock_model: Bedrock model ID to use
            aws_profile: Optional AWS profile name
            
        Returns:
            Dict with extracted project information
        """
        # Prepare all discovered content for analysis
        content_for_analysis = self._prepare_content(context_files)
        
        # Build user prompt
        user_prompt = f"""Content to analyze:
{content_for_analysis}
"""
        
        try:
            # Create Strands agent directly
            session = Session(profile_name=aws_profile) if aws_profile else Session()
            model = BedrockModel(model_id=bedrock_model, boto_session=session, temperature=0)
            
            # Load system prompt
            prompt_path = Path(__file__).parent.parent.parent.parent / "prompts" / "project-analysis.md"
            with open(prompt_path, 'r') as f:
                system_prompt = f.read()
            
            agent = Agent(model=model, system_prompt=system_prompt, tools=[], callback_handler=null_callback_handler())
            
            # Run agent synchronously
            result = agent(user_prompt)
            
            # Parse JSON response
            project_info = parse_json_response(str(result))
            
            # Log extracted project information
            self._log_extraction_results(project_info)
            
            return project_info
            
        except Exception as e:
            self.logger.error(f"Project info extraction failed: {e}")
            print(f"❌ Failed to extract project info: {str(e)}")
            return {
                "error": str(e),
                "application_name": "Unknown Application",
                "technologies": [],
                "sector": "Unknown"
            }
    
    def _prepare_content(self, context_files: Dict[str, Any]) -> str:
        """Prepare all discovered content for analysis
        
        Args:
            context_files: Dict containing discovered files
            
        Returns:
            Formatted content string for LLM analysis
        """
        content_parts = []
        
        self.logger.info("=== PREPARING CONTENT FOR ANALYSIS ===")
        
        # Add ThreatComposer metadata if present
        tc_file = self._find_threatcomposer_file(context_files)
        if tc_file:
            content_parts.extend(self._extract_threatcomposer_metadata(tc_file))
        
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
        
        # Add data flow diagrams (.mmd files)
        discovered_files = context_files.get('discovered_files', {})
        dfd_files = discovered_files.get('data_flow_diagrams', [])
        if dfd_files:
            self.logger.info(f"✓ Including {len(dfd_files)} data flow diagram(s)")
            content_parts.append(f"\n=== DATA FLOW DIAGRAMS ===")
            for dfd_path in dfd_files:
                try:
                    if dfd_path.endswith('.mmd'):
                        with open(dfd_path, 'r', encoding='utf-8') as f:
                            dfd_content = f.read()
                        content_parts.append(f"\nFile: {dfd_path}")
                        content_parts.append(f"Mermaid Diagram:\n{dfd_content[:2000]}")
                except Exception as e:
                    self.logger.warning(f"Failed to read data flow diagram {dfd_path}: {e}")
        
        # Note about images
        image_files = discovered_files.get('architecture_diagrams', [])
        if image_files:
            self.logger.info(f"✓ Including {len(image_files)} architecture diagram(s)")
            content_parts.append(f"\n=== ARCHITECTURE DIAGRAMS ===")
            content_parts.append(f"Found {len(image_files)} architecture diagrams:")
            for img_path in image_files:
                content_parts.append(f"- {img_path}")
            content_parts.append("(Diagram content will be analyzed from the images provided)")
        
        return '\n'.join(content_parts)
    
    def _find_threatcomposer_file(self, context_files: Dict[str, Any]) -> Optional[str]:
        """Find ThreatComposer file in context
        
        Args:
            context_files: Context files dict
            
        Returns:
            Path to ThreatComposer file or None
        """
        # Check manually specified threat model path
        threat_model_path = context_files.get("threat_model_path")
        if threat_model_path and threat_model_path.endswith('.tc.json'):
            return threat_model_path
        
        # Check discovered threat models
        threat_models = []
        if "threat_models" in context_files:
            threat_models = context_files["threat_models"]
        elif "discovered_files" in context_files and "threat_models" in context_files["discovered_files"]:
            threat_models = context_files["discovered_files"]["threat_models"]
        
        for tm_path in threat_models:
            if tm_path.endswith('.tc.json'):
                return tm_path
        
        return None
    
    def _extract_threatcomposer_metadata(self, tc_file: str) -> list:
        """Extract metadata from ThreatComposer file
        
        Args:
            tc_file: Path to ThreatComposer file
            
        Returns:
            List of content parts
        """
        content_parts = []
        
        try:
            self.logger.info(f"✓ Found ThreatComposer file: {Path(tc_file).name}")
            with open(tc_file, 'r') as f:
                tc_data = json.load(f)
            
            # Add application info
            if 'applicationInfo' in tc_data:
                app_info = tc_data['applicationInfo']
                self.logger.info(f"  - Application: {app_info.get('name', 'N/A')}")
                content_parts.append("\n=== THREATCOMPOSER APPLICATION INFO ===")
                content_parts.append(f"Name: {app_info.get('name', 'N/A')}")
                content_parts.append(f"Description: {app_info.get('description', 'N/A')[:1000]}")
            
            # Add architecture description
            if 'architecture' in tc_data and tc_data['architecture'].get('description'):
                self.logger.info(f"  - Architecture description found")
                content_parts.append("\n=== THREATCOMPOSER ARCHITECTURE ===")
                content_parts.append(tc_data['architecture']['description'][:2000])
            
            # Add dataflow information
            if 'dataflow' in tc_data and tc_data['dataflow']:
                self.logger.info(f"  - Dataflow information found")
                content_parts.append("\n=== THREATCOMPOSER DATAFLOW ===")
                dataflow = tc_data['dataflow']
                if isinstance(dataflow, dict):
                    for key, value in list(dataflow.items())[:10]:
                        content_parts.append(f"{key}: {str(value)[:500]}")
                elif isinstance(dataflow, list):
                    for idx, item in enumerate(dataflow[:10]):
                        content_parts.append(f"Flow {idx+1}: {str(item)[:500]}")
            
            self.logger.info(f"✓ ThreatComposer metadata extracted successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to extract ThreatComposer metadata: {e}")
        
        return content_parts
    
    def _log_extraction_results(self, project_info: Dict[str, Any]) -> None:
        """Log extracted project information
        
        Args:
            project_info: Extracted project information
        """
        self.logger.info("=== EXTRACTED PROJECT INFORMATION ===")
        self.logger.info(f"Application Name: {project_info.get('application_name', 'N/A')}")
        self.logger.info(f"Sector/Industry: {project_info.get('sector', 'N/A')}")
        self.logger.info(f"Architecture Type: {project_info.get('architecture_type', 'N/A')}")
        self.logger.info(f"Deployment Environment: {project_info.get('deployment_environment', 'N/A')}")
        
        technologies = project_info.get('technologies', [])
        self.logger.info(f"Technologies Identified: {len(technologies)}")
        for tech in technologies[:10]:  # Log first 10
            self.logger.info(f"  - {tech}")
        if len(technologies) > 10:
            self.logger.info(f"  ... and {len(technologies) - 10} more")
    
    def validate_with_user(self, project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Allow user to validate and modify extracted information
        
        Args:
            project_info: Extracted project information
            
        Returns:
            Validated (possibly modified) project information
        """
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
                project_info['application_name'] = Prompt.ask("Application name", 
                                                            default=project_info.get('application_name', ''))
            
            if Confirm.ask("Update sector?", default=False):
                project_info['sector'] = Prompt.ask("Sector", default=project_info.get('sector', ''))
            
            if Confirm.ask("Update technologies?", default=False):
                tech_input = Prompt.ask("Technologies (comma-separated)", 
                                      default=', '.join(project_info.get('technologies', [])))
                project_info['technologies'] = [t.strip() for t in tech_input.split(',') if t.strip()]
            
            if Confirm.ask("Update architecture type?", default=False):
                project_info['architecture_type'] = Prompt.ask("Architecture type", 
                                                              default=project_info.get('architecture_type', ''))
            
            console.print("[green]Information updated![/green]")
        
        # Save validated info to file
        self.save_validated_info(project_info)
        
        return project_info
    
    def save_validated_info(self, project_info: Dict[str, Any]) -> None:
        """Save validated information to markdown file
        
        Args:
            project_info: Validated project information
        """
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
