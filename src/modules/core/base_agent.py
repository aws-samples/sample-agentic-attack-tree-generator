"""Base utility class for ThreatForest components using Strands framework"""
from pathlib import Path
from typing import Optional, List
from strands import Agent
from strands.handlers import null_callback_handler
from src.config import config
from .models.model_factory import create_model


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
        temperature: float = 0
    ) -> Agent:
        """
        Create a Strands Agent with auto-detected model provider
        
        Args:
            prompt_file: Markdown file in prompts/ (e.g., 'generate-attack-trees.md')
            tools: Optional list of Strands tools for the agent
            temperature: Model temperature (default 0 for deterministic)
            
        Returns:
            Configured Strands Agent
        """
        # Auto-detect and create model from config.yaml
        model = create_model(config, temperature)
        
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
