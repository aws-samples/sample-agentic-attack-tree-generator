"""Base utility class for ThreatForest components using Strands framework"""
from pathlib import Path
from typing import Optional, List
from boto3 import Session
from strands import Agent
from strands.models import BedrockModel
from strands.handlers import null_callback_handler
from src.config import config


class BaseAgent:
    """Base utility class providing Strands helper methods"""
    
    def get_prompt_from_file(self, prompt_file: str) -> str:
        """
        Load prompt from markdown file
        
        Args:
            prompt_file: Filename in prompts/ directory (e.g., 'generate-attack-trees.md')
            
        Returns:
            Prompt text content
        """
        prompts_dir = Path(__file__).parent.parent.parent / "prompts"
        prompt_path = prompts_dir / prompt_file
        
        if not prompt_path.exists():
            raise FileNotFoundError(
                f"Prompt file not found: {prompt_path}"
            )
        
        with open(prompt_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def get_strands_agent(
        self, 
        prompt_file: str, 
        tools: Optional[List] = None,
        temperature: float = 0,
        model_name: Optional[str] = None
    ) -> Agent:
        """
        Create a Strands Agent with BedrockModel
        
        Args:
            prompt_file: Markdown file in prompts/ (e.g., 'generate-attack-trees.md')
            tools: Optional list of Strands tools for the agent
            temperature: Model temperature (default 0 for deterministic)
            model_name: Optional model ID override (defaults to config.yaml)
            
        Returns:
            Configured Strands Agent
        """
        model_id = model_name or config.default_bedrock_model
        profile = config.default_aws_profile
        
        # Create boto3 session with configured profile
        session = Session(profile_name=profile) if profile else Session()
        
        # Create Strands BedrockModel
        model = BedrockModel(
            model_id=model_id,
            boto_session=session,
            temperature=temperature
        )
        
        # Load system prompt from markdown file
        system_prompt = self.get_prompt_from_file(prompt_file)
        
        # Create Strands Agent
        agent = Agent(
            model=model,
            system_prompt=system_prompt,
            tools=tools or [],
            callback_handler=null_callback_handler()
        )
        
        return agent
