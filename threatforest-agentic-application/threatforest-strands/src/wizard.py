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

from modules.utils.logger import ThreatForestLogger
from modules.tools.setup_tool import SetupTool
from modules.tools.context_analysis_tool import ContextAnalysisTool
from modules.tools.information_extraction_tool import InformationExtractionTool
from modules.tools.attack_tree_generator_tool import AttackTreeGeneratorTool
from modules.tools.ttc_mapping_tool import TTCMappingTool
from modules.tools.summary_generator_tool import SummaryGeneratorTool


class ThreatForestWizard:
    """Interactive wizard for ThreatForest setup and execution"""
    
    def __init__(self):
        self.console = Console()
        self.config = {}
        self.logger = None
        self.log_file_path = None
        
    def _setup_logging(self):
        """Setup centralized logging"""
        # Use threatforest-strands/output as base directory
        strands_root = Path(__file__).parent.parent
        output_dir = strands_root / "output"
        self.log_file_path = ThreatForestLogger.initialize(output_dir)
        self.logger = ThreatForestLogger.get_logger('Wizard')
        self.logger.info("Wizard initialized")
        
    def run(self):
        """Run the complete wizard"""
        # Setup logging first
        self._setup_logging()
        
        try:
            asyncio.run(self._run_wizard())
            self.console.print(f"\n✅ Analysis complete!")
            self.console.print(f"📋 Detailed logs: {self.log_file_path}")
        except KeyboardInterrupt:
            self.logger.warning("Wizard cancelled by user")
            self.console.print("\n👋 Cancelled. Goodbye!")
            self.console.print(f"📋 Logs: {self.log_file_path}")
        except Exception as e:
            self.logger.error(f"Wizard failed: {e}", exc_info=True)
            self.console.print(f"\n❌ Error: {e}")
            self.console.print(f"📋 Check logs: {self.log_file_path}")
        finally:
            ThreatForestLogger.close()
            
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
        
        # Step 4: Threat Model Document
        self._select_threat_model_document()
        
        # Step 5: Configuration Review
        self._review_configuration()
        
        # Step 6: Execute Analysis
        if Confirm.ask("🚀 Ready to run ThreatForest analysis?"):
            await self._run_analysis()
        else:
            self.console.print("👋 Analysis cancelled. Run the wizard again when ready!")
    
    def _show_welcome(self):
        """Show welcome message"""
        
        welcome_text = """
🌳 Welcome to ThreatForest!

ThreatForest is an AI-powered threat modeling tool that automatically generates 
attack trees and comprehensive security reports.

What ThreatForest does:
• 📁 Analyzes ALL project content (docs, configs, images, threat models)
• 👁️ Uses multimodal AI to analyze architecture diagrams and images
• 🤖 Extracts project information using AWS Bedrock vision capabilities
• 🎯 Generates standardized threat statements (T001, T002, T003...)
• 🌳 Creates detailed attack trees for high-severity threats
• 📄 Aligns attack steps to known intelligence sources such as the AWS TTC, MITRE ATT&CK, or Wiz Cloud Security Framework

Let's get started with the setup!
        """
        
        self.console.print(Panel(welcome_text, title="🌳 ThreatForest Setup Wizard", border_style="green"))
    
    async def _setup_aws_credentials(self):
        """Setup AWS credentials"""
        
        self.console.print("\n📋 Step 1: AWS Configuration", style="bold blue")
        self.console.print("ThreatForest uses AWS Bedrock for AI analysis. Let's configure your AWS access.")
        self.logger.info("Starting AWS credentials setup")
        
        # Check existing AWS configuration without SetupTool
        try:
            import boto3
            session = boto3.Session()
            # Try to get credentials
            credentials = session.get_credentials()
            if credentials:
                self.logger.info("AWS credentials found")
                self.console.print("✅ AWS credentials already configured!")
                
                # Show available profiles
                profiles = self._get_aws_profiles()
                if profiles:
                    self.logger.debug(f"Available AWS profiles: {profiles}")
                    self.console.print("\n📋 Available AWS profiles:")
                    
                    if len(profiles) > 1:
                        for i, profile in enumerate(profiles, 1):
                            self.console.print(f"  {i}. {profile}")
                        
                        choice = Prompt.ask(
                            "\nSelect profile number",
                            choices=[str(i) for i in range(1, len(profiles) + 1)],
                            default="1"
                        )
                        selected_profile = profiles[int(choice) - 1]
                        self.config["aws_profile"] = selected_profile if selected_profile != "default" else None
                        self.logger.info(f"User selected AWS profile: {selected_profile}")
                    else:
                        self.console.print(f"  1. {profiles[0]}")
                        self.config["aws_profile"] = None
                        self.logger.info("Using default AWS profile")
                else:
                    self.config["aws_profile"] = None
                    self.logger.info("No AWS profiles found, using default")
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
        """Select Bedrock model dynamically from available models"""
        
        self.console.print("\n🤖 Step 2: AI Model Selection", style="bold blue")
        self.console.print("Fetching available AWS Bedrock models...")
        self.logger.info("Starting model selection process")
        
        # Fetch available models from Bedrock
        try:
            import boto3
            session = boto3.Session(profile_name=self.config.get("aws_profile"))
            bedrock = session.client('bedrock', region_name='us-east-1')
            self.logger.debug(f"Created Bedrock client for region: us-east-1")
            
            response = bedrock.list_foundation_models()
            self.logger.info(f"Retrieved {len(response.get('modelSummaries', []))} total models from Bedrock")
            
            # Try to get inference profiles for models that require them
            inference_profiles = {}
            try:
                profiles_response = bedrock.list_inference_profiles()
                self.logger.debug(f"Retrieved {len(profiles_response.get('inferenceProfileSummaries', []))} inference profiles")
                
                for profile in profiles_response.get('inferenceProfileSummaries', []):
                    profile_arn = profile.get('inferenceProfileArn', '')
                    # Map model IDs to their inference profile ARNs
                    for model in profile.get('models', []):
                        model_id = model.get('modelArn', '').split('/')[-1]
                        if model_id and 'claude' in model_id.lower():
                            inference_profiles[model_id] = profile_arn
                            self.logger.debug(f"Mapped inference profile for {model_id}: {profile_arn}")
                            
                if inference_profiles:
                    self.logger.info(f"Found {len(inference_profiles)} inference profiles for Claude models")
            except Exception as e:
                # Inference profiles might not be available in all regions
                self.logger.warning(f"Could not fetch inference profiles: {e}")
            
            # Filter for Claude models with text generation capability
            # Use a dict to deduplicate by model family, keeping the best version
            model_families = {}
            
            for model in response.get('modelSummaries', []):
                model_id = model.get('modelId', '')
                model_name = model.get('modelName', '')
                inference_profile_required = model.get('inferenceTypesSupported', [])
                
                # Only include Claude models that support text generation
                if 'claude' in model_id.lower() and 'TEXT' in model.get('outputModalities', []):
                    self.logger.debug(f"Processing model: {model_name} ({model_id})")
                    
                    # Skip models that require inference profiles but don't have one available
                    if 'PROVISIONED' in inference_profile_required and model_id not in inference_profiles:
                        self.logger.debug(f"Skipping {model_id} - requires inference profile but none available")
                        continue
                    
                    # Determine model family key for deduplication
                    family_key = self._get_model_family_key(model_id, model_name)
                    
                    # Get priority score (lower is better)
                    priority = self._get_model_priority(model_id)
                    
                    # Use inference profile ARN if available, otherwise use model ID
                    effective_id = inference_profiles.get(model_id, model_id)
                    if effective_id != model_id:
                        self.logger.debug(f"Using inference profile for {model_id}")
                    
                    # Keep the best version of each model family
                    if family_key not in model_families or priority < model_families[family_key]['priority']:
                        recommendation = self._get_model_recommendation(model_id, model_name)
                        self.logger.debug(f"Selected {model_name} for family {family_key} (priority: {priority})")
                        model_families[family_key] = {
                            'name': model_name,
                            'id': effective_id,
                            'recommendation': recommendation,
                            'priority': priority
                        }
            
            # Convert to list
            available_models = [
                {'name': m['name'], 'id': m['id'], 'recommendation': m['recommendation']}
                for m in model_families.values()
            ]
            
            self.logger.info(f"Found {len(available_models)} unique Claude model families")
            for model in available_models:
                self.logger.debug(f"  - {model['name']}: {model['id']}")
            
            if not available_models:
                self.logger.warning("No Claude models found, using fallback list")
                self.console.print("⚠️  No Claude models found. Using fallback list.")
                available_models = self._get_fallback_models()
            
            # Sort models by recommendation priority (recommended first)
            available_models.sort(key=lambda x: (
                0 if '⭐ Recommended' in x['recommendation'] else
                1 if '🚀' in x['recommendation'] else
                2 if '⚡' in x['recommendation'] else
                3 if '🔬' in x['recommendation'] else
                4 if '💨' in x['recommendation'] else 5
            ))
            
        except Exception as e:
            self.logger.error(f"Failed to fetch models from Bedrock: {e}", exc_info=True)
            self.console.print(f"⚠️  Could not fetch models: {e}")
            self.console.print("Using fallback model list...")
            available_models = self._get_fallback_models()
        
        # Display available models
        self.console.print("\nChoose the AWS Bedrock model for analysis:")
        
        table = Table(title="Available Models")
        table.add_column("Option", style="cyan")
        table.add_column("Model", style="green")
        table.add_column("Description", style="yellow")
        
        for i, model in enumerate(available_models, 1):
            table.add_row(str(i), model['name'], model['recommendation'])
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "Select model",
            choices=[str(i) for i in range(1, len(available_models) + 1)],
            default="1"
        )
        
        selected_model = available_models[int(choice) - 1]
        self.config["bedrock_model"] = selected_model['id']
        
        self.logger.info(f"User selected model: {selected_model['name']} ({selected_model['id']})")
        
        self.console.print(f"✅ Selected: {selected_model['name']}")
        self.console.print(f"💡 {selected_model['recommendation']}")
    
    def _get_model_family_key(self, model_id: str, model_name: str) -> str:
        """Generate a family key for deduplication"""
        model_id_lower = model_id.lower()
        
        # Create family keys based on model type - check more specific versions first
        if 'sonnet-4-5' in model_id_lower or 'sonnet-4.5' in model_id_lower:
            return 'sonnet-4.5'
        elif 'sonnet-4' in model_id_lower and 'claude-3' not in model_id_lower:
            return 'sonnet-4'
        elif 'opus-4' in model_id_lower:
            return 'opus-4'
        elif 'sonnet' in model_id_lower and ('3-5' in model_id_lower or '3.5' in model_id_lower):
            return 'sonnet-3.5'
        elif 'haiku' in model_id_lower and 'claude-3' in model_id_lower:
            return 'haiku-3'
        elif 'opus' in model_id_lower and 'claude-3' in model_id_lower:
            return 'opus-3'
        elif 'sonnet' in model_id_lower and 'claude-3' in model_id_lower:
            return 'sonnet-3'
        elif 'instant' in model_id_lower:
            return 'instant'
        else:
            # For other models, use the model name as key
            return model_name.lower().replace(' ', '-')
    
    def _get_model_priority(self, model_id: str) -> int:
        """Get priority score for model selection (lower is better)"""
        model_id_lower = model_id.lower()
        
        # Prefer cross-region models (us. prefix) over regional models
        priority = 0 if model_id.startswith('us.') else 10
        
        # Prefer newer versions (higher dates)
        if '2025' in model_id:
            priority += 0
        elif '2024' in model_id:
            priority += 5
        else:
            priority += 10
        
        return priority
    
    def _get_model_recommendation(self, model_id: str, model_name: str) -> str:
        """Generate recommendation text based on model ID"""
        model_id_lower = model_id.lower()
        
        # Sonnet 4.5 - Newest and most recommended
        if 'sonnet-4-5' in model_id_lower or 'sonnet-4.5' in model_id_lower:
            return "⭐ Recommended - Latest model with best performance"
        # Sonnet 4 - Latest and recommended
        elif 'sonnet-4' in model_id_lower and 'claude-3' not in model_id_lower:
            return "⭐ Recommended - Best balance of speed and accuracy"
        # Opus 4 - Most powerful
        elif 'opus-4' in model_id_lower:
            return "🚀 Most powerful - Highest accuracy, slower"
        # Sonnet 3.5 - Fast and capable
        elif 'sonnet' in model_id_lower and ('3-5' in model_id_lower or '3.5' in model_id_lower):
            return "⚡ Fast - Good for quick analysis"
        # Haiku - Fastest
        elif 'haiku' in model_id_lower:
            return "💨 Fastest - Basic analysis"
        # Opus 3 - Powerful but older
        elif 'opus' in model_id_lower:
            return "🔬 Powerful - High accuracy"
        # Default for other models
        else:
            return "📊 Available for analysis"
    
    def _get_fallback_models(self) -> List[Dict[str, str]]:
        """Fallback model list if API call fails"""
        return [
            {
                'name': 'Claude Sonnet 4',
                'id': 'us.anthropic.claude-sonnet-4-20250514-v1:0',
                'recommendation': '⭐ Recommended - Best balance of speed and accuracy'
            },
            {
                'name': 'Claude Opus 4.1',
                'id': 'us.anthropic.claude-opus-4-1-20250805-v1:0',
                'recommendation': '🚀 Most powerful - Highest accuracy, slower'
            },
            {
                'name': 'Claude 3.5 Sonnet',
                'id': 'anthropic.claude-3-5-sonnet-20241022-v2:0',
                'recommendation': '⚡ Fast - Good for quick analysis'
            },
            {
                'name': 'Claude 3 Haiku',
                'id': 'anthropic.claude-3-haiku-20240307-v1:0',
                'recommendation': '💨 Fastest - Basic analysis'
            }
        ]
    
    def _select_project_path(self):
        """Select project path with enhanced threat model discovery"""
        
        self.console.print("\n📁 Step 3: Project Path Selection", style="bold blue")
        self.console.print("ThreatForest analyzes your project files to understand the application.")
        
        self.console.print("\n🔍 Enhanced File Discovery:")
        self.console.print("• 🎯 Threat Models (.tc.json, .md with threat content)")
        self.console.print("• 📖 Documentation (README, config files, docker-compose)")
        self.console.print("• 🏗️  Architecture diagrams (.png, .jpg, .pdf, .mmd, .drawio)")
        self.console.print("• ⚙️  Configuration files (.json, .yaml, .yml)")
        self.console.print("• 👁️ AI vision analysis of images and diagrams")
        
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
        self.console.print(f"\n📋 Scanning {project_path}...")
        self.logger.info(f"Scanning project path: {project_path}")
        
        # Use enhanced discovery that matches context analysis
        readme_files = self._discover_readme_files_preview(str(project_path))
        diagram_files = self._discover_diagram_files_preview(str(project_path))
        
        self.logger.debug(f"Found {len(readme_files)} readme files")
        self.logger.debug(f"Found {len(diagram_files)} diagram files")
        
        # Convert to sets to avoid double-counting files that appear in multiple categories
        readme_set = set(readme_files)
        diagram_set = set(diagram_files)
        
        # Remove diagrams from readme count (images shouldn't be counted as docs)
        readme_only = readme_set - diagram_set
        
        # Calculate total unique files
        all_files = readme_set | diagram_set
        total_files = len(all_files)
        
        self.logger.info(f"Total unique files found: {total_files} ({len(readme_only)} docs, {len(diagram_set)} diagrams)")
        for file in sorted(all_files):
            self.logger.debug(f"  - {file}")
        
        # Show simplified results
        self.console.print(f"✅ Found {total_files} files for analysis:")
        self.console.print(f"   • 📖 {len(readme_only)} documentation files")
        self.console.print(f"   • 🏗️  {len(diagram_set)} diagram files")
        
        # Simplified validation
        if total_files == 0:
            self.console.print("\n⚠️  No project files found for analysis")
            self.console.print("💡 ThreatForest works best with:")
            self.console.print("   • Documentation (README.md, config files)")
            self.console.print("   • Architecture diagrams (.png, .jpg, .pdf)")
            self.console.print("   • ThreatComposer files (.tc.json)")
            
            if not Confirm.ask("Continue with very limited analysis?"):
                self.console.print("💡 Add some documentation or diagrams and try again.")
                sys.exit(1)
    
    def _select_threat_model_document(self):
        """Select threat model document"""
        
        self.console.print("\n📄 Step 4: Threat Model Document", style="bold blue")
        
        if Confirm.ask("Do you have an existing threat model document?"):
            while True:
                threat_model_path = Prompt.ask("Enter the full path to your threat model document")
                
                # Expand user path and resolve
                threat_model_path = Path(threat_model_path).expanduser().resolve()
                
                if threat_model_path.exists() and threat_model_path.is_file():
                    self.config["threat_model_path"] = str(threat_model_path)
                    self.console.print(f"✅ Threat model document: {threat_model_path.name}")
                    break
                else:
                    self.console.print(f"❌ File not found: {threat_model_path}")
                    if not Confirm.ask("Try again?"):
                        self.config["threat_model_path"] = None
                        break
        else:
            self.config["threat_model_path"] = None
            self.console.print("ℹ️  No threat model document specified - will analyze project for threats")
    
    
    def _discover_threat_files_preview(self, project_path: str) -> List[str]:
        """Preview threat file discovery"""
        threat_files = []
        supported_formats = ['.json', '.tc', '.yaml', '.yml', '.md', '.txt']
        threat_keywords = ['threat', 'risk', 'vulnerability', 'attack', 'security']
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file contains 'threat' in filename (any extension)
                if 'threat' in file.lower():
                    threat_files.append(file_path)
                # Check by extension and keywords
                elif any(file.lower().endswith(ext) for ext in supported_formats):
                    if any(keyword in file.lower() for keyword in threat_keywords):
                        threat_files.append(file_path)
                    elif 'threatcomposer' in file.lower() or file.endswith('.tc'):
                        threat_files.append(file_path)
        
        return threat_files
    
    def _discover_readme_files_preview(self, project_path: str) -> List[str]:
        """Preview README and markdown file discovery"""
        readme_files = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                name_lower = file.lower()
                
                # READMEs and markdown files
                if name_lower.startswith("readme") or file.endswith('.md'):
                    readme_files.append(file_path)
        
        return readme_files
    
    def _discover_diagram_files_preview(self, project_path: str) -> List[str]:
        """Preview architecture diagram file discovery"""
        diagram_files = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                name_lower = file.lower()
                
                # Architecture diagrams - expanded image support
                if any(keyword in name_lower for keyword in ["architecture", "arch", "design", "system", "diagram"]):
                    if file.lower().endswith(('.png', '.jpg', '.jpeg', '.pdf', '.svg', '.puml', '.md', '.mmd', '.drawio')):
                        diagram_files.append(file_path)
                # Any image files that might be diagrams
                elif file.lower().endswith(('.png', '.jpg', '.jpeg', '.pdf')):
                    diagram_files.append(file_path)
        
        return diagram_files
    
    def _review_configuration(self):
        """Review configuration before execution"""
        
        self.console.print("\n📋 Step 5: Configuration Review", style="bold blue")
        
        config_table = Table(title="ThreatForest Configuration")
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="green")
        
        config_table.add_row("AWS Profile", self.config.get("aws_profile", "default"))
        config_table.add_row("Bedrock Model", self.config["bedrock_model"].split("/")[-1])
        config_table.add_row("Project Path", self.config["project_path"])
        
        threat_model_display = self.config.get("threat_model_path")
        if threat_model_display:
            threat_model_display = Path(threat_model_display).name
        else:
            threat_model_display = "Auto-discover from project"
        config_table.add_row("Threat Model", threat_model_display)
        
        self.console.print(config_table)
        
        if not Confirm.ask("Configuration looks good?"):
            self.console.print("❌ Please restart the wizard to reconfigure.")
            sys.exit(0)
    
    async def _run_analysis(self):
        """Run the complete ThreatForest analysis"""
        
        self.console.print("\n🚀 Step 6: Running ThreatForest Analysis", style="bold blue")
        
        # Use threatforest-strands/output as base directory
        strands_root = Path(__file__).parent.parent
        output_dir = strands_root / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create attack_trees subdirectory with project name
        project_name = Path(self.config["project_path"]).name
        attack_trees_dir = output_dir / "attack_trees" / project_name
        attack_trees_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Step 1: Context Analysis
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("📁 Analyzing project context...", total=None)
                
                context_tool = ContextAnalysisTool()
                context_result = await context_tool.execute(self.config["project_path"])
                
                progress.update(task, description="✅ Context analysis complete")
            
            self.console.print(f"📊 Analysis complete:")
            self.console.print(context_result['summary'])
            
            # Step 2: Information Extraction
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("🤖 Extracting project information with AI...", total=None)
                
                # Add threat model path to context if specified
                if self.config.get("threat_model_path"):
                    context_result["threat_model_path"] = self.config["threat_model_path"]
                
                extraction_tool = InformationExtractionTool()
                extraction_result = await extraction_tool.execute(
                    context_files=context_result,
                    bedrock_model=self.config["bedrock_model"],
                    aws_profile=self.config.get("aws_profile"),
                    interactive=False
                )
                
                progress.update(task, description="✅ Information extraction complete")
            
            # Get threat count from threat_analysis or extraction result
            threat_count = context_result.get('threat_analysis', {}).get('total_threats', 0)
            extraction_threats = extraction_result.get('threat_statements', [])
            
            if threat_count > 0:
                self.console.print(f"🎯 Found {threat_count} existing threats for analysis")
            elif extraction_threats:
                self.console.print(f"🤖 Generated {len(extraction_threats)} threats using AI analysis")
                
                # Try to get application name for filename display
                app_name = extraction_result.get('project_info', {}).get('application_name', 'Unknown')
                clean_app_name = app_name.replace(' ', '_').replace('-', '_')
                filename = f"{clean_app_name}_generated_threat_statements.md"
                
                self.console.print(f"📄 Threat statements saved to {filename}")
                self.console.print(f"💡 Review and customize the generated threats as needed")
            
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
                    threat_statements=high_threats,
                    extracted_info=extraction_result,
                    bedrock_model=self.config["bedrock_model"],
                    aws_profile=self.config.get("aws_profile")
                )
                
                progress.update(task, description="✅ Attack tree generation complete")
            
            successful_trees = [t for t in trees_result['attack_trees'] if 'mermaid_code' in t]
            self.console.print(f"🌳 Generated {len(successful_trees)} attack trees successfully")
            
            # Save attack trees to disk
            self._save_attack_trees(trees_result, output_dir)
            
            # Skip TTC mapping but continue with summary generation
            self.console.print("⏭️  Skipping MITRE ATT&CK mapping as requested")
            
            # Step 4: Summary Generation (without TTC mapping)
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("📄 Generating reports (without TTC mapping)...", total=None)
                
                summary_generator = SummaryGeneratorTool()
                try:
                    summary_result = await summary_generator.execute(
                        attack_trees=trees_result,  # Use unmapped attack trees
                        extracted_info=extraction_result,
                        output_dir=str(output_dir)
                    )
                except Exception as e:
                    print(f"⚠️  Summary generation failed: {e}")
                    summary_result = {'output_files': []}
                
                progress.update(task, description="✅ Report generation complete")
            
            # Handle None summary_result
            if summary_result is None:
                summary_result = {'output_files': []}
            
            # Success summary without TTC mapping
            self._show_success_summary_no_ttc(output_dir, summary_result, extraction_result)
            
        except Exception as e:
            self.console.print(f"\n❌ Analysis failed: {e}")
            self.console.print("💡 Check your AWS credentials and try again")
    
    def _generate_filename_from_threat(self, threat: Dict[str, Any]) -> str:
        """Generate filename from threat action, removing filler words"""
        # Try different possible field names for threat action
        threat_action = (threat.get('threat_action') or 
                        threat.get('threatAction') or 
                        threat.get('Threat Action') or
                        threat.get('description', ''))
        
        if not threat_action:
            # Fallback to threat statement
            threat_action = threat.get('threat_statement', threat.get('statement', 'unknown'))
        
        # Remove common filler words
        filler_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
                       'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be',
                       'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                       'would', 'should', 'could', 'may', 'might', 'must', 'can', 'which',
                       'leads', 'resulting', 'reduced', 'that', 'this', 'these', 'those'}
        
        # Convert to lowercase, split into words, remove filler words
        words = threat_action.lower().split()
        filtered_words = [w for w in words if w not in filler_words and len(w) > 2]
        
        # Take first 5-6 meaningful words, join with underscore
        filename_base = '_'.join(filtered_words[:6])
        
        # Remove special characters
        filename_base = ''.join(c if c.isalnum() or c == '_' else '_' for c in filename_base)
        
        # Remove consecutive underscores
        while '__' in filename_base:
            filename_base = filename_base.replace('__', '_')
        
        # Remove leading/trailing underscores
        filename_base = filename_base.strip('_')
        
        return f"attack_tree_{filename_base}.md"
    
    def _save_attack_trees(self, trees_result: Dict[str, Any], output_dir: Path) -> None:
        """Save attack trees to output directory"""
        if not trees_result or 'attack_trees' not in trees_result:
            print("⚠️  No attack trees to save")
            return
        
        # Save to attack_trees/project_name subdirectory
        project_name = Path(self.config["project_path"]).name
        attack_trees_dir = output_dir / "attack_trees" / project_name
        attack_trees_dir.mkdir(parents=True, exist_ok=True)
            
        successful_trees = [tree for tree in trees_result['attack_trees'] if 'mermaid_code' in tree]
        failed_trees = [tree for tree in trees_result['attack_trees'] if 'error' in tree]
        
        print(f"🌳 Saving {len(successful_trees)} attack trees to {attack_trees_dir}")
        
        # Save successful attack trees
        for tree in successful_trees:
            threat_id = tree.get('threat_id', 'unknown')
            threat_statement = tree.get('threat_statement', 'Unknown threat')
            mermaid_code = tree.get('mermaid_code', '')
            
            # Generate filename from threat action
            filename = self._generate_filename_from_threat(tree)
            filepath = attack_trees_dir / filename
            
            # Create markdown content
            # Use category from title for short name (e.g., "T001 - Authentication")
            short_title = f"{threat_id} - {tree.get('threat_category', 'Unknown')}"
            threat_description = tree.get('threat_description', tree.get('threat_statement', 'No description available'))
            
            content = f"""# Attack Tree: {short_title}

**Threat ID**: {threat_id}  
**Description**: {threat_description}

---

## Attack Tree Diagram

```mermaid
{mermaid_code}
```

## Attack Path Analysis

This attack tree represents the potential attack paths for the identified threat. Each node in the tree represents either:
- **Attack Goal** (orange): The ultimate objective
- **Attack Step** (red): Individual attack actions
- **Fact/Condition** (blue): Prerequisites or conditions
- **Mitigation** (green): Defensive measures

Review this attack tree to:
1. Identify critical attack paths
2. Implement appropriate security controls
3. Monitor for indicators of these attack patterns
4. Develop incident response procedures

---
*Generated by ThreatForest - Attack Tree Analysis*
"""
            
            # Write to file
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"✅ Saved attack tree: {filename}")
            except Exception as e:
                print(f"❌ Failed to save {filename}: {e}")
        
        # Report failed trees
        if failed_trees:
            print(f"⚠️  {len(failed_trees)} attack trees failed to generate:")
            for tree in failed_trees:
                threat_id = tree.get('threat_id', 'unknown')
                error = tree.get('error', 'Unknown error')
                print(f"  - {threat_id}: {error}")
        
        print(f"🌳 Attack tree generation complete: {len(successful_trees)} successful, {len(failed_trees)} failed")
    
    def _show_success_summary_no_ttc(self, output_dir: Path, summary_result: Dict[str, Any], 
                                    extraction_result: Dict[str, Any]):
        """Show success summary without TTC mapping"""
        
        if extraction_result is None:
            self.console.print("⚠️  No extraction results available")
            return
            
        project_info = extraction_result.get('project_info', {})
        if not project_info:
            self.console.print("⚠️  No project information available")
            return
        
        # Handle None summary_result
        if summary_result is None:
            summary_result = {'output_files': []}
        
        # Count actual attack tree files in attack_trees subdirectory
        attack_trees_dir = output_dir / "attack_trees"
        attack_tree_count = len(list(attack_trees_dir.glob("attack_tree_*.md"))) if attack_trees_dir.exists() else 0
        
        success_panel = f"""
🎉 ThreatForest Analysis Complete!

📊 Results Summary:
• Application: {project_info.get('application_name', 'Unknown')}
• Technologies: {len(project_info.get('technologies', []))} identified
• Threats analyzed: {len(extraction_result.get('high_severity_threats', []))}
• Attack trees generated: {attack_tree_count}
• MITRE ATT&CK mapping: Skipped

📁 Output Directory: {output_dir}

📄 Generated Files:
{chr(10).join(f'• {Path(f).name}' for f in summary_result.get('output_files', []))}

🔍 Next Steps:
1. Review the main analysis report
2. Examine individual attack trees
3. Implement recommended security controls
        """
        
        self.console.print(Panel(success_panel, title="✅ Analysis Complete", border_style="green"))
        
        if Confirm.ask("Open output directory?"):
            import webbrowser
            webbrowser.open(f"file://{output_dir}")
    
    def _show_success_summary_simple(self, output_dir: Path, trees_result: Dict[str, Any], 
                                   extraction_result: Dict[str, Any]):
        """Show simplified success summary without TTC mapping"""
        
        if extraction_result is None:
            self.console.print("⚠️  No extraction results available")
            return
            
        project_info = extraction_result.get('project_info', {})
        if not project_info:
            self.console.print("⚠️  No project information available")
            return
        
        # Count actual attack tree files in attack_trees subdirectory
        attack_trees_dir = output_dir / "attack_trees"
        attack_tree_count = len(list(attack_trees_dir.glob("attack_tree_*.md"))) if attack_trees_dir.exists() else 0
        
        success_panel = f"""
🎉 ThreatForest Attack Tree Generation Complete!

📊 Results Summary:
• Application: {project_info.get('application_name', 'Unknown')}
• Technologies: {len(project_info.get('technologies', []))} identified
• Threats analyzed: {len(extraction_result.get('high_severity_threats', []))}
• Attack trees generated: {attack_tree_count}

📁 Output Directory: {output_dir}

📄 Generated Files:
{chr(10).join(f'• {f.name}' for f in attack_trees_dir.glob("attack_tree_*.md")) if attack_trees_dir.exists() else 'No attack trees generated'}

🔍 Next Steps:
1. Review the generated attack trees
2. Customize attack paths as needed
3. Implement recommended security controls
        """
        
        self.console.print(Panel(success_panel, title="✅ Attack Trees Generated", border_style="green"))
        
        if Confirm.ask("Open output directory?"):
            import webbrowser
            webbrowser.open(f"file://{output_dir}")
    
    def _show_success_summary(self, output_dir: Path, summary_result: Dict[str, Any], 
                             extraction_result: Dict[str, Any], mapping_summary: Dict[str, Any]):
        """Show success summary"""
        
        # Handle potential None values
        if extraction_result is None:
            self.console.print("⚠️  No extraction results available")
            return
            
        project_info = extraction_result.get('project_info', {})
        if not project_info:
            self.console.print("⚠️  No project information available")
            return
        
        # Handle None summary_result
        if summary_result is None:
            summary_result = {'output_files': []}
        
        # Handle None mapping_summary
        if mapping_summary is None:
            mapping_summary = {'total_mappings': 0}
        
        # Count actual attack tree files in output directory
        attack_tree_count = len(list(output_dir.glob("attack_tree_*.md")))
        
        success_panel = f"""
🎉 ThreatForest Analysis Complete!

📊 Results Summary:
• Application: {project_info.get('application_name', 'Unknown')}
• Technologies: {len(project_info.get('technologies', []))} identified
• Threats analyzed: {len(extraction_result.get('high_severity_threats', []))}
• Attack trees generated: {attack_tree_count}
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
