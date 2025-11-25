"""LlamaAPI model wrapper"""
import os
from dotenv import load_dotenv
from strands.models.llamaapi import LlamaAPIModel

# Load environment variables from .env
load_dotenv()


def create_llamaapi_model(config, temperature: float = 0):
    """
    Create LlamaAPI model from config
    
    Args:
        config: Config object with llamaapi settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured LlamaAPIModel
    """
    llamaapi_config = config.llamaapi
    
    # Get API key from environment
    api_key = os.getenv('LLAMAAPI_API_KEY')
    if not api_key:
        raise ValueError("LLAMAAPI_API_KEY not found in environment variables")
    
    # Create LlamaAPI model
    model = LlamaAPIModel(
        client_args={"api_key": api_key},
        model_id=llamaapi_config['model_id']
    )
    
    return model
