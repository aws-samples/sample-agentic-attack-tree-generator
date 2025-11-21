"""Model factory for auto-detecting and creating configured model"""


def create_model(config, temperature: float = 0):
    """
    Auto-detect configured provider and create appropriate model
    
    Args:
        config: Config object with model settings
        temperature: Model temperature (default 0 for deterministic)
        
    Returns:
        Configured Strands model instance
        
    Raises:
        ValueError: If no provider is configured or provider is unknown
    """
    # Check for each provider configuration (first non-None wins)
    
    if hasattr(config, 'bedrock') and config.bedrock:
        from .bedrock import create_bedrock_model
        return create_bedrock_model(config, temperature)
    
    elif hasattr(config, 'anthropic') and config.anthropic:
        from .anthropic import create_anthropic_model
        return create_anthropic_model(config, temperature)
    
    elif hasattr(config, 'openai') and config.openai:
        from .openai import create_openai_model
        return create_openai_model(config, temperature)
    
    elif hasattr(config, 'gemini') and config.gemini:
        from .gemini import create_gemini_model
        return create_gemini_model(config, temperature)
    
    elif hasattr(config, 'ollama') and config.ollama:
        from .ollama import create_ollama_model
        return create_ollama_model(config, temperature)
    
    elif hasattr(config, 'litellm') and config.litellm:
        from .litellm import create_litellm_model
        return create_litellm_model(config, temperature)
    
    elif hasattr(config, 'llamaapi') and config.llamaapi:
        from .llamaapi import create_llamaapi_model
        return create_llamaapi_model(config, temperature)
    
    elif hasattr(config, 'sagemaker') and config.sagemaker:
        from .sagemaker import create_sagemaker_model
        return create_sagemaker_model(config, temperature)
    
    else:
        raise ValueError(
            "No model provider configured. Please uncomment one provider section in config.yaml"
        )
