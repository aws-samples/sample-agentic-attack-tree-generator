"""Anthropic model wrapper"""
import os
from dotenv import load_dotenv
from strands.models.anthropic import AnthropicModel

# Load environment variables from .env
load_dotenv()


def create_anthropic_model(config, temperature: float = 0):
    """
    Create Anthropic model from config
    
    Args:
        config: Config object with anthropic settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured AnthropicModel
    """
    anthropic_config = config.anthropic
    
    # Get API key from environment
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment variables")
    
    # Create Anthropic model
    model = AnthropicModel(
        client_args={"api_key": api_key},
        model_id=anthropic_config['model_id'],
        max_tokens=4096,  # Reasonable default
        params={"temperature": temperature}
    )
    
    return model
