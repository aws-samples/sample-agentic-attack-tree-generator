"""OpenAI model wrapper"""
import os
from dotenv import load_dotenv
from strands.models.openai import OpenAIModel

# Load environment variables from .env
load_dotenv()


def create_openai_model(config, temperature: float = 0):
    """
    Create OpenAI model from config
    
    Args:
        config: Config object with openai settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured OpenAIModel
    """
    openai_config = config.openai
    
    # Get API key from environment
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY not found in environment variables")
    
    # Create OpenAI model
    model = OpenAIModel(
        client_args={"api_key": api_key},
        model_id=openai_config['model_id'],
        params={
            "max_tokens": 4096,
            "temperature": temperature
        }
    )
    
    return model
