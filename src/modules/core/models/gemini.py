"""Google Gemini model wrapper"""
import os
from dotenv import load_dotenv
from strands.models.gemini import GeminiModel

# Load environment variables from .env
load_dotenv()


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
    
    # Get API key from environment
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables")
    
    # Create Gemini model
    model = GeminiModel(
        client_args={"api_key": api_key},
        model_id=gemini_config['model_id'],
        params={
            "temperature": temperature,
            "max_output_tokens": 8192,
            "top_p": 0.95,
            "top_k": 40
        }
    )
    
    return model
