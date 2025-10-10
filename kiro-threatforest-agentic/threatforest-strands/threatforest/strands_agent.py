"""
ThreatForest Strands-based Orchestrator Agent
"""
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .core import Agent, Context, ThreatForestState, WorkflowStage, StateManager
from .tools.setup_tool import SetupTool
from .tools.context_analysis_tool import ContextAnalysisTool
from .tools.information_extraction_tool import InformationExtractionTool
from .tools.attack_tree_generator_tool import AttackTreeGeneratorTool
from .tools.ttc_mapping_tool import TTCMappingTool
from .tools.summary_generator_tool import SummaryGeneratorTool


@dataclass
class ThreatForestConfig:
    """Configuration for ThreatForest execution"""
    project_path: Path
    aws_profile: Optional[str] = None
    bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"
    output_dir: Optional[Path] = None
    ttc_threshold: float = 0.8
    resume: bool = False  # Enable resume from checkpoint


class ThreatForestOrchestrator(Agent):
    """Main orchestrating agent for ThreatForest attack tree generation"""
    
    def __init__(self, config: ThreatForestConfig):
        self.config = config
        self.state_manager = StateManager()
        self.state: Optional[ThreatForestState] = None
        
        # Initialize tools
        tools = [
            SetupTool(),
            ContextAnalysisTool(),
            InformationExtractionTool(),
            AttackTreeGeneratorTool(),
            TTCMappingTool(threshold=config.ttc_threshold),
            SummaryGeneratorTool()
        ]
        
        super().__init__(
            name="ThreatForestOrchestrator",
            description="Orchestrates the generation of attack trees from application context",
            tools=tools
        )
    
    def _initialize_state(self) -> ThreatForestState:
        """Initialize or resume workflow state"""
        # Check for existing state
        existing_state = self.state_manager.load_checkpoint()
        
        if existing_state:
            # Validate state
            is_valid, message = existing_state.is_valid_for_resume()
            
            if not is_valid:
                print(f"⚠️  Found existing state but it's invalid: {message}")
                print("Starting fresh workflow...")
                return ThreatForestState(
                    project_path=str(self.config.project_path),
                    aws_profile=self.config.aws_profile,
                    bedrock_model=self.config.bedrock_model
                )
            
            # Prompt user if resume flag not set
            if not self.config.resume:
                print(f"\n📋 Found existing workflow state:")
                print(f"   Stage: {existing_state.current_stage.value}")
                print(f"   Last updated: {existing_state.last_updated.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   Progress: Setup={existing_state.setup_complete}, "
                      f"Context={existing_state.context_complete}, "
                      f"Extraction={existing_state.extraction_complete}")
                
                response = input("\n🔄 Resume from checkpoint? (y/n): ").strip().lower()
                if response == 'y':
                    print(f"✓ Resuming from {existing_state.current_stage.value} stage\n")
                    return existing_state
                else:
                    print("Starting fresh workflow...\n")
            else:
                print(f"✓ Resuming from {existing_state.current_stage.value} stage\n")
                return existing_state
        
        return ThreatForestState(
            project_path=str(self.config.project_path),
            aws_profile=self.config.aws_profile,
            bedrock_model=self.config.bedrock_model
        )
    
    async def execute_workflow(self) -> Dict[str, Any]:
        """Execute the complete ThreatForest workflow with state management"""
        # Initialize or resume state
        self.state = self._initialize_state()
        context = Context()
        context.add("workflow_state", self.state.model_dump())
        
        try:
            # Step 1: Setup and validation
            if not self.state.setup_complete:
                self.state.advance_to(WorkflowStage.SETUP)
                setup_result = await self.use_tool("setup", {
                    "project_path": str(self.config.project_path),
                    "aws_profile": self.config.aws_profile,
                    "bedrock_model": self.config.bedrock_model
                })
                self.state.setup_result = setup_result
                self.state.setup_complete = setup_result.get("setup_complete", False)
                self.state_manager.save_checkpoint(self.state)
                context.add("setup", setup_result)
                context.add("workflow_state", self.state.model_dump())
                
                if not self.state.setup_complete:
                    return {
                        "status": "setup_failed",
                        "setup_result": setup_result,
                        "message": "Setup validation failed. Please check AWS credentials and Bedrock access."
                    }
            else:
                context.add("setup", self.state.setup_result)
            
            # Step 2: Context analysis
            if not self.state.context_complete:
                self.state.advance_to(WorkflowStage.CONTEXT_ANALYSIS)
                context_result = await self.use_tool("context_analysis", {
                    "project_path": str(self.config.project_path)
                })
                self.state.context_files = context_result
                self.state.context_complete = True
                self.state_manager.save_checkpoint(self.state)
                context.add("context_files", context_result)
                context.add("workflow_state", self.state.model_dump())
            else:
                context.add("context_files", self.state.context_files)
            
            # Step 3: Information extraction
            if not self.state.extraction_complete:
                self.state.advance_to(WorkflowStage.EXTRACTION)
                extraction_result = await self.use_tool("information_extraction", {
                    "context_files": self.state.context_files,
                    "bedrock_model": self.config.bedrock_model,
                    "aws_profile": self.config.aws_profile
                })
                self.state.extracted_info = extraction_result
                self.state.extraction_complete = True
                self.state_manager.save_checkpoint(self.state)
                context.add("extracted_info", extraction_result)
                context.add("workflow_state", self.state.model_dump())
            else:
                context.add("extracted_info", self.state.extracted_info)
                extraction_result = self.state.extracted_info
            
            # Determine application name for output directory
            app_name = extraction_result.get("project_info", {}).get("application_name", "unknown_app")
            output_dir = self.config.project_path / "outputs" / app_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Step 4: Generate attack trees (High severity only)
            if not self.state.tree_generation_complete:
                self.state.advance_to(WorkflowStage.TREE_GENERATION)
                attack_trees = await self.use_tool("attack_tree_generator", {
                    "threat_statements": extraction_result.get("threat_statements", []),
                    "extracted_info": extraction_result,
                    "bedrock_model": self.config.bedrock_model,
                    "aws_profile": self.config.aws_profile
                })
                self.state.attack_trees = attack_trees.get("attack_trees", [])
                self.state.tree_generation_complete = True
                self.state_manager.save_checkpoint(self.state)
                context.add("attack_trees", attack_trees)
                context.add("workflow_state", self.state.model_dump())
            else:
                attack_trees = {"attack_trees": self.state.attack_trees}
                context.add("attack_trees", attack_trees)
            
            # Step 5: Generate summary
            if not self.state.summary_complete:
                self.state.advance_to(WorkflowStage.SUMMARY)
                summary = await self.use_tool("summary_generator", {
                    "attack_trees": attack_trees,
                    "extracted_info": extraction_result,
                    "output_dir": str(output_dir)
                })
                self.state.output_files = summary.get("output_files", [])
                self.state.summary_complete = True
                self.state.advance_to(WorkflowStage.COMPLETE)
                self.state_manager.save_checkpoint(self.state)
                context.add("summary", summary)
                context.add("workflow_state", self.state.model_dump())
            else:
                summary = {"output_files": self.state.output_files}
                context.add("summary", summary)
            
            return {
                "status": "success",
                "context": context.to_dict(),
                "output_files": summary.get("output_files", []),
                "output_directory": str(output_dir),
                "application_name": app_name
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "context": context.to_dict()
            }
    
    def _find_aaf_bundle(self) -> Optional[str]:
        """Find the aaf-bundle.json file in the project"""
        search_paths = [
            self.config.project_path,
            self.config.project_path.parent,
            Path("/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/genai-chatbot-2")
        ]
        
        for path in search_paths:
            aaf_file = path / "aaf-bundle.json"
            if aaf_file.exists():
                return str(aaf_file)
        
        return None


async def run_threatforest(project_path: str, **kwargs) -> Dict[str, Any]:
    """Main entry point for running ThreatForest"""
    config = ThreatForestConfig(
        project_path=Path(project_path),
        **kwargs
    )
    
    orchestrator = ThreatForestOrchestrator(config)
    return await orchestrator.execute_workflow()
