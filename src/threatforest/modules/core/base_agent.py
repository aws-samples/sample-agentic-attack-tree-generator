"""Base utility class for ThreatForest components using Strands framework"""
from pathlib import Path
from typing import Optional, List
from strands import Agent
from strands.handlers import null_callback_handler
from strands.agent.conversation_manager import SummarizingConversationManager
from threatforest.config import config
from .providers.provider_factory import create_model


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
        callback_handler = None,
        use_summarization: bool = False
    ) -> Agent:
        """
        Create a Strands Agent with auto-detected model provider
        
        Args:
            prompt_file: Markdown file in prompts/ (e.g., 'generate-attack-trees.md')
            tools: Optional list of Strands tools for the agent
            temperature: Model temperature (default 0 for deterministic)
            callback_handler: Optional callback handler for tracking events
            use_summarization: Enable conversation summarization to manage long contexts
            
        Returns:
            Configured Strands Agent
        """
        # Auto-detect and create model from config.yaml
        model = create_model(config, temperature)
        
        # Load system prompt from markdown file
        system_prompt = self.get_prompt_from_file(prompt_file)
        
        # Use provided callback or default to null (no output)
        if callback_handler is None:
            callback_handler = null_callback_handler()
        
        # Create conversation manager if summarization is enabled
        conversation_manager = None
        if use_summarization:
            # Create a dedicated summarization agent with same model but lower temperature
            # This avoids circular dependency by creating the agent inline
            summarization_model = create_model(config, temperature=0.1)
            summarization_agent = Agent(model=summarization_model)
            
            # Create conversation manager with summarization agent
            conversation_manager = SummarizingConversationManager(
                summary_ratio=0.4,  # Keep 40% of conversation length
                preserve_recent_messages=1,  # Always keep last 8 messages
                summarization_agent=summarization_agent
            )
        
        # Create Strands Agent with optional conversation manager
        agent = Agent(
            model=model,
            system_prompt=system_prompt,
            tools=tools or [],
            callback_handler=callback_handler,
            conversation_manager=conversation_manager
        )
        
        return agent
