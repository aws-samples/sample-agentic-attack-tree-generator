"""LiteLLM model wrapper"""
import os
from dotenv import load_dotenv
from strands.models.litellm import LiteLLMModel

# Load environment variables from .env
load_dotenv()


def create_litellm_model(config, temperature: float = 0):
    """
    Create LiteLLM model from config
    
    Args:
        config: Config object with litellm settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured LiteLLMModel
    """
    litellm_config = config.litellm
    
    # Get API key from environment
    api_key = os.getenv('LITELLM_API_KEY')
    if not api_key:
        raise ValueError("LITELLM_API_KEY not found in environment variables")
    
    # Create LiteLLM model
    model = LiteLLMModel(
        client_args={"api_key": api_key},
        model_id=litellm_config['model_id'],
        params={
            "max_tokens": 4096,
            "temperature": temperature
        }
    )
    
    return model
