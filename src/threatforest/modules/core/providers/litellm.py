"""LiteLLM model wrapper"""
from strands.models.litellm import LiteLLMModel
from threatforest.modules.utils.env_manager import EnvManager


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
    
    # Get API key from environment using EnvManager
    env_manager = EnvManager()
    api_key = env_manager.get_value('LITELLM_API_KEY')
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
