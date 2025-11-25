"""Ollama model wrapper"""
from strands.models.ollama import OllamaModel


def create_ollama_model(config, temperature: float = 0):
    """
    Create Ollama model from config
    
    Args:
        config: Config object with ollama settings
        temperature: Model temperature (default 0)
        
    Returns:
        Configured OllamaModel
    """
    ollama_config = config.ollama
    
    # Create Ollama model (local, no API key needed)
    model = OllamaModel(
        host=ollama_config.get('host', 'http://localhost:11434'),
        model_id=ollama_config['model_id']
    )
    
    return model
