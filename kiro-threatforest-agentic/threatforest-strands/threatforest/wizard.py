#!/usr/bin/env python3
"""ThreatForest Interactive Setup Wizard"""

import os
import sys
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
import subprocess

try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("❌ Rich library not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from threatforest.tools.setup_tool import SetupTool
from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool
from threatforest.tools.attack_tree_generator_tool import AttackTreeGeneratorTool
from threatforest.tools.ttc_mapping_tool import TTCMappingTool
from threatforest.tools.summary_generator_tool import SummaryGeneratorTool


class ThreatForestWizard:
    """Interactive wizard for ThreatForest setup and execution"""
    
    def __init__(self):
        self.console = Console()
        self.config = {}
        
    def run(self):
        """Run the complete wizard"""
        try:
            asyncio.run(self._run_wizard())
        except KeyboardInterrupt:
            self.console.print("\n👋 Wizard cancelled by user. Goodbye!")
        except Exception as e:
            self.console.print(f"\n❌ Error: {e}")
            
    async def _run_wizard(self):
        """Main wizard flow"""
        
        # Welcome
        self._show_welcome()
        
        # Step 1: AWS Setup
        await self._setup_aws_credentials()
        
        # Step 2: Model Selection
        self._select_bedrock_model()
        
        # Step 3: Project Path
        self._select_project_path()
        
        # Step 4: Configuration Review
        self._review_configuration()
        
        # Step 5: Execute Analysis
        if Confirm.ask("🚀 Ready to run ThreatForest analysis?"):
            await self._run_analysis()
        else:
            self.console.print("👋 Analysis cancelled. Run the wizard again when ready!")
    
    def _show_welcome(self):
        """Show welcome message"""
        
        welcome_text = """
🌳 Welcome to ThreatForest!

ThreatForest is an AI-powered threat modeling tool that automatically generates 
attack trees and maps them to MITRE ATT&CK techniques.

What ThreatForest does:
• 📁 Analyzes your project files (README, threat statements, diagrams)
• 🤖 Extracts project information using AWS Bedrock
• 🌳 Generates detailed attack trees for high-severity threats
• 🎯 Maps attack steps to MITRE ATT&CK techniques
• 📄 Creates comprehensive security reports

Let's get started with the setup!
        """
        
        self.console.print(Panel(welcome_text, title="🌳 ThreatForest Setup Wizard", border_style="green"))
    
    async def _setup_aws_credentials(self):
        """Setup AWS credentials"""
        
        self.console.print("\n📋 Step 1: AWS Configuration", style="bold blue")
        self.console.print("ThreatForest uses AWS Bedrock for AI analysis. Let's configure your AWS access.")
        
        # Check existing AWS configuration without SetupTool
        try:
            import boto3
            session = boto3.Session()
            # Try to get credentials
            credentials = session.get_credentials()
            if credentials:
                self.console.print("✅ AWS credentials already configured!")
                
                # Show available profiles
                profiles = self._get_aws_profiles()
                if profiles:
                    self.console.print(f"📋 Available AWS profiles: {', '.join(profiles)}")
                    
                    if len(profiles) > 1:
                        profile_choice = Prompt.ask(
                            "Which AWS profile would you like to use?",
                            choices=["default"] + [p for p in profiles if p != "default"],
                            default="default"
                        )
                        self.config["aws_profile"] = profile_choice if profile_choice != "default" else None
                    else:
                        self.config["aws_profile"] = None
                else:
                    self.config["aws_profile"] = None
            else:
                raise Exception("No credentials found")
                
        except Exception:
            self.console.print("❌ AWS credentials not found.")
            self.console.print("\n🔧 To configure AWS credentials, you have several options:")
            self.console.print("1. Run: aws configure")
            self.console.print("2. Set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
            self.console.print("3. Use IAM roles (if running on EC2)")
            
            if not Confirm.ask("Have you configured AWS credentials?"):
                self.console.print("❌ AWS credentials are required. Please configure them and run the wizard again.")
                sys.exit(1)
            
            self.config["aws_profile"] = None
        
        # Test Bedrock access
        self.console.print("\n🧪 Testing AWS Bedrock access...")
        
        try:
            import boto3
            session = boto3.Session(profile_name=self.config.get("aws_profile"))
            bedrock = session.client('bedrock', region_name='us-east-1')
            bedrock.list_foundation_models()
            self.console.print("✅ AWS Bedrock access confirmed!")
        except Exception as e:
            self.console.print(f"❌ Bedrock access failed: {e}")
            self.console.print("💡 Make sure you have Bedrock permissions in us-east-1 region")
            if not Confirm.ask("Continue anyway?"):
                sys.exit(1)
    
    def _select_bedrock_model(self):
        """Select Bedrock model"""
        
        self.console.print("\n🤖 Step 2: AI Model Selection", style="bold blue")
        self.console.print("Choose the AWS Bedrock model for analysis:")
        
        models = [
            ("Claude Sonnet 4", "us.anthropic.claude-sonnet-4-20250514-v1:0", "⭐ Recommended - Best balance of speed and accuracy"),
            ("Claude Opus 4.1", "us.anthropic.claude-opus-4-1-20250805-v1:0", "🚀 Most powerful - Highest accuracy, slower"),
            ("Claude 3.5 Sonnet", "anthropic.claude-3-5-sonnet-20241022-v2:0", "⚡ Fast - Good for quick analysis"),
            ("Claude 3 Haiku", "anthropic.claude-3-haiku-20240307-v1:0", "💨 Fastest - Basic analysis")
        ]
        
        table = Table(title="Available Models")
        table.add_column("Option", style="cyan")
        table.add_column("Model", style="green")
        table.add_column("Description", style="yellow")
        
        for i, (name, model_id, desc) in enumerate(models, 1):
            table.add_row(str(i), name, desc)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "Select model",
            choices=[str(i) for i in range(1, len(models) + 1)],
            default="1"
        )
        
        selected_model = models[int(choice) - 1]
        self.config["bedrock_model"] = selected_model[1]
        
        self.console.print(f"✅ Selected: {selected_model[0]}")
        self.console.print(f"💡 {selected_model[2]}")
    
    def _select_project_path(self):
        """Select project path with enhanced threat model discovery"""
        
        self.console.print("\n📁 Step 3: Project Path Selection", style="bold blue")
        self.console.print("ThreatForest analyzes your project files to understand the application.")
        
        self.console.print("\n🔍 Enhanced File Discovery:")
        self.console.print("• 🎯 Threat Models (ThreatComposer .tc, threat.json, security.yaml)")
        self.console.print("• 📖 README files (project description, technologies)")
        self.console.print("• 🏗️  Architecture diagrams (.mmd, .drawio, .puml)")
        self.console.print("• 📄 Documentation files")
        
        # Suggest current directory first
        current_dir = Path.cwd()
        self.console.print(f"\n📂 Current directory: {current_dir}")
        
        if Confirm.ask("Use current directory?", default=True):
            project_path = current_dir
        else:
            # Ask for custom path
            while True:
                path_input = Prompt.ask(
                    "Enter project path",
                    default=str(current_dir)
                )
                project_path = Path(path_input).expanduser().resolve()
                
                if project_path.exists() and project_path.is_dir():
                    break
                else:
                    self.console.print(f"❌ Path not found: {project_path}")
                    if not Confirm.ask("Try again?"):
                        self.console.print("❌ Valid project path is required. Exiting.")
                        sys.exit(1)
        
        self.config["project_path"] = str(project_path)
        
        # Enhanced file discovery preview
        self.console.print(f"\n📋 Enhanced Scanning {project_path}...")
        
        # Use enhanced discovery
        threat_models = self._discover_threat_files_preview(str(project_path))
        readme_files = list(project_path.glob("**/README*")) + list(project_path.glob("**/readme*"))
        diagram_files = list(project_path.glob("**/*.mmd")) + list(project_path.glob("**/*.drawio")) + list(project_path.glob("**/*.puml"))
        
        # Show enhanced results
        if threat_models:
            self.console.print(f"🎯 Found {len(threat_models)} threat model files:")
            for tm in threat_models[:3]:  # Show first 3
                file_name = Path(tm).name
                format_type = "ThreatComposer" if "threatcomposer" in tm.lower() or tm.endswith('.tc') else "Generic"
                self.console.print(f"   • {file_name} ({format_type})")
            if len(threat_models) > 3:
                self.console.print(f"   • ... and {len(threat_models) - 3} more")
        else:
            self.console.print("⚠️  No threat model files found")
        
        self.console.print(f"📖 Found {len(readme_files)} README files")
        self.console.print(f"🏗️  Found {len(diagram_files)} diagram files")
        
        # Enhanced validation
        if len(threat_models) == 0 and len(readme_files) == 0:
            self.console.print("⚠️  No threat models or README files found")
            self.console.print("💡 ThreatForest works best with:")
            self.console.print("   • ThreatComposer workspace files (.tc)")
            self.console.print("   • Threat statement files (threat.json, security.yaml)")
            self.console.print("   • README files with project description")
            
            if not Confirm.ask("Continue with limited analysis?"):
                self.console.print("💡 Add threat model files or README and try again.")
                sys.exit(1)
        elif len(threat_models) > 0:
            self.console.print("✅ Threat models found - analysis will be comprehensive!")
        else:
            self.console.print("⚠️  No threat models found - using README-based analysis")
    
    def _discover_threat_files_preview(self, project_path: str) -> List[str]:
        """Preview threat file discovery"""
        threat_files = []
        supported_formats = ['.json', '.tc', '.yaml', '.yml']
        threat_keywords = ['threat', 'risk', 'vulnerability', 'attack', 'security']
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check by extension and keywords
                if any(file.lower().endswith(ext) for ext in supported_formats):
                    if any(keyword in file.lower() for keyword in threat_keywords):
                        threat_files.append(file_path)
                    elif 'threatcomposer' in file.lower() or file.endswith('.tc'):
                        threat_files.append(file_path)
        
        return threat_files
    
    def _review_configuration(self):
        """Review configuration before execution"""
        
        self.console.print("\n📋 Step 4: Configuration Review", style="bold blue")
        
        config_table = Table(title="ThreatForest Configuration")
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="green")
        
        config_table.add_row("AWS Profile", self.config.get("aws_profile", "default"))
        config_table.add_row("Bedrock Model", self.config["bedrock_model"].split("/")[-1])
        config_table.add_row("Project Path", self.config["project_path"])
        
        self.console.print(config_table)
        
        if not Confirm.ask("Configuration looks good?"):
            self.console.print("❌ Please restart the wizard to reconfigure.")
            sys.exit(0)
    
    async def _run_analysis(self):
        """Run the complete ThreatForest analysis"""
        
        self.console.print("\n🚀 Step 5: Running ThreatForest Analysis", style="bold blue")
        
        # Create output directory
        project_name = Path(self.config["project_path"]).name.replace(" ", "_").lower()
        output_dir = Path.cwd() / "threatforest_output" / project_name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Step 1: Context Analysis
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("📁 Analyzing project context...", total=None)
                
                context_tool = ContextAnalysisTool()
                context_result = await context_tool.execute(self.config["project_path"])
                
                progress.update(task, description="✅ Context analysis complete")
            
            self.console.print(f"📊 Analysis complete:")
            self.console.print(context_result['summary'])
            
            # Get threat count from threat_analysis
            threat_count = context_result.get('threat_analysis', {}).get('total_threats', 0)
            if threat_count > 0:
                self.console.print(f"🎯 Found {threat_count} threats for analysis")
            
            # Step 2: Information Extraction
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("🤖 Extracting project information with AI...", total=None)
                
                extraction_tool = InformationExtractionTool()
                extraction_result = await extraction_tool.execute(
                    context_files=context_result,
                    bedrock_model=self.config["bedrock_model"],
                    aws_profile=self.config.get("aws_profile"),
                    interactive=False
                )
                
                progress.update(task, description="✅ Information extraction complete")
            
            project_info = extraction_result['project_info']
            high_threats = extraction_result['high_severity_threats']
            
            self.console.print(f"🎯 Application: {project_info.get('application_name', 'Unknown')}")
            self.console.print(f"🔧 Technologies: {len(project_info.get('technologies', []))} identified")
            self.console.print(f"⚠️  High severity threats: {len(high_threats)}")
            
            if len(high_threats) == 0:
                self.console.print("❌ No high severity threats found. Analysis complete.")
                return
            
            # Step 3: Attack Tree Generation
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task(f"🌳 Generating attack trees for {len(high_threats)} threats...", total=None)
                
                tree_generator = AttackTreeGeneratorTool()
                trees_result = await tree_generator.execute(
                    threat_statements=high_threats[:5],  # Limit to 5 to avoid long processing
                    extracted_info=extraction_result,
                    bedrock_model=self.config["bedrock_model"],
                    aws_profile=self.config.get("aws_profile")
                )
                
                progress.update(task, description="✅ Attack tree generation complete")
            
            successful_trees = [t for t in trees_result['attack_trees'] if 'mermaid_code' in t]
            self.console.print(f"🌳 Generated {len(successful_trees)} attack trees successfully")
            
            # Step 4: TTC Mapping
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("🎯 Mapping to MITRE ATT&CK techniques...", total=None)
                
                ttc_mapper = TTCMappingTool(threshold=0.5)
                mapped_result = await ttc_mapper.execute(
                    trees_result,
                    bedrock_model=self.config["bedrock_model"],
                    aws_profile=self.config.get("aws_profile")
                )
                
                progress.update(task, description="✅ TTC mapping complete")
            
            mapping_summary = mapped_result['mapping_summary']
            self.console.print(f"🎯 Mapped {mapping_summary.get('total_mappings', 0)} attack steps to MITRE ATT&CK")
            
            # Step 5: Summary Generation
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("📄 Generating comprehensive reports...", total=None)
                
                summary_generator = SummaryGeneratorTool()
                summary_result = await summary_generator.execute(
                    attack_trees=mapped_result,
                    extracted_info=extraction_result,
                    output_dir=str(output_dir)
                )
                
                progress.update(task, description="✅ Report generation complete")
            
            # Success summary
            self._show_success_summary(output_dir, summary_result, extraction_result, mapping_summary)
            
        except Exception as e:
            self.console.print(f"\n❌ Analysis failed: {e}")
            self.console.print("💡 Check your AWS credentials and try again")
    
    def _show_success_summary(self, output_dir: Path, summary_result: Dict[str, Any], 
                             extraction_result: Dict[str, Any], mapping_summary: Dict[str, Any]):
        """Show success summary"""
        
        project_info = extraction_result['project_info']
        
        success_panel = f"""
🎉 ThreatForest Analysis Complete!

📊 Results Summary:
• Application: {project_info.get('application_name', 'Unknown')}
• Technologies: {len(project_info.get('technologies', []))} identified
• Threats analyzed: {len(extraction_result.get('high_severity_threats', []))}
• Attack trees generated: {len([f for f in summary_result.get('output_files', []) if 'attack_tree' in f])}
• MITRE ATT&CK mappings: {mapping_summary.get('total_mappings', 0)}

📁 Output Directory: {output_dir}

📄 Generated Files:
{chr(10).join(f'• {Path(f).name}' for f in summary_result.get('output_files', []))}

🔍 Next Steps:
1. Review the main analysis report
2. Examine individual attack trees
3. Check MITRE ATT&CK mappings
4. Implement recommended security controls
        """
        
        self.console.print(Panel(success_panel, title="✅ Analysis Complete", border_style="green"))
        
        if Confirm.ask("Open output directory?"):
            import webbrowser
            webbrowser.open(f"file://{output_dir}")
    
    def _get_aws_profiles(self) -> list:
        """Get available AWS profiles"""
        try:
            import boto3
            session = boto3.Session()
            return session.available_profiles
        except:
            return []


def main():
    """Main entry point"""
    wizard = ThreatForestWizard()
    wizard.run()


if __name__ == "__main__":
    main()
