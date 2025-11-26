"""Google Gemini model wrapper"""
from strands.models.gemini import GeminiModel
from threatforest.modules.utils.env_manager import EnvManager


def create_gemini_model(config, temperature: float = 0):
    """
    Create Gemini model from config
    
    Args:
        config: Config object with gemini settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured GeminiModel
    """
    gemini_config = config.gemini
    
    # Get API key from environment using EnvManager
    env_manager = EnvManager()
    api_key = env_manager.get_value('GEMINI_API_KEY')
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables")
    
    # Create Gemini model
    model = GeminiModel(
        client_args={"api_key": api_key},
        model_id=gemini_config['model_id'],
        params={
            "temperature": temperature
        }
    )
    
    return model
