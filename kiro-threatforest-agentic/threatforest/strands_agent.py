"""
ThreatForest Strands-based Orchestrator Agent
"""
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Mock Strands imports for testing
class Tool:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

class Agent:
    def __init__(self, name: str, description: str, tools: List[Tool]):
        self.name = name
        self.description = description
        self.tools = {tool.name: tool for tool in tools}
    
    async def use_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name in self.tools:
            tool = self.tools[tool_name]
            return await tool.execute(**params)
        else:
            raise ValueError(f"Tool {tool_name} not found")

class Context:
    def __init__(self):
        self.data = {}
    
    def add(self, key: str, value: Any):
        self.data[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        return self.data

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
    bedrock_model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    output_dir: Optional[Path] = None
    ttc_threshold: float = 0.8


class ThreatForestOrchestrator(Agent):
    """Main orchestrating agent for ThreatForest attack tree generation"""
    
    def __init__(self, config: ThreatForestConfig):
        self.config = config
        
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
    
    async def execute_workflow(self) -> Dict[str, Any]:
        """Execute the complete ThreatForest workflow"""
        context = Context()
        
        try:
            # Step 1: Setup and validation
            setup_result = await self.use_tool("setup", {
                "project_path": str(self.config.project_path),
                "aws_profile": self.config.aws_profile,
                "bedrock_model": self.config.bedrock_model
            })
            context.add("setup", setup_result)
            
            if not setup_result.get("setup_complete", False):
                return {
                    "status": "setup_failed",
                    "setup_result": setup_result,
                    "message": "Setup validation failed. Please check AWS credentials and Bedrock access."
                }
            
            # Step 2: Context analysis
            context_result = await self.use_tool("context_analysis", {
                "project_path": str(self.config.project_path)
            })
            context.add("context_files", context_result)
            
            # Step 3: Information extraction
            extraction_result = await self.use_tool("information_extraction", {
                "context_files": context_result,
                "bedrock_model": self.config.bedrock_model,
                "aws_profile": self.config.aws_profile
            })
            context.add("extracted_info", extraction_result)
            
            # Determine application name for output directory
            app_name = extraction_result.get("project_info", {}).get("application_name", "unknown_app")
            output_dir = self.config.project_path / "outputs" / app_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Step 4: Generate attack trees (High severity only)
            attack_trees = await self.use_tool("attack_tree_generator", {
                "threat_statements": extraction_result.get("threat_statements", []),
                "extracted_info": extraction_result,
                "bedrock_model": self.config.bedrock_model,
                "aws_profile": self.config.aws_profile
            })
            context.add("attack_trees", attack_trees)
            
            # Step 5: TTC mapping
            ttc_mapped_trees = await self.use_tool("ttc_mapping", {
                "attack_trees": attack_trees,
                "aaf_bundle_path": self._find_aaf_bundle()
            })
            context.add("ttc_mapped_trees", ttc_mapped_trees)
            
            # Step 6: Generate summary
            summary = await self.use_tool("summary_generator", {
                "attack_trees": ttc_mapped_trees,
                "extracted_info": extraction_result,
                "output_dir": str(output_dir)
            })
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
