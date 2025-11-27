"""Model factory for auto-detecting and creating configured model"""
from threatforest.modules.utils.logger import ThreatForestLogger

logger = ThreatForestLogger.get_logger('ModelFactory')

# Module-level cache to prevent repetitive logging
_provider_detected = False


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
    global _provider_detected
    
    # Only log detection once per session
    if not _provider_detected:
        logger.debug("🔍 Detecting model provider...")
        logger.debug(f"  Bedrock config: {config.bedrock if hasattr(config, 'bedrock') else 'None'}")
        logger.debug(f"  Anthropic config: {config.anthropic if hasattr(config, 'anthropic') else 'None'}")
        logger.debug(f"  OpenAI config: {config.openai if hasattr(config, 'openai') else 'None'}")
        logger.debug(f"  Gemini config: {config.gemini if hasattr(config, 'gemini') else 'None'}")
        logger.debug(f"  Ollama config: {config.ollama if hasattr(config, 'ollama') else 'None'}")
        _provider_detected = True
    
    if hasattr(config, 'bedrock') and config.bedrock and config.bedrock.get('model_id'):
        logger.info(f"✅ Using Bedrock: {config.bedrock['model_id']}")
        from .bedrock import create_bedrock_model
        return create_bedrock_model(config, temperature)
    
    elif hasattr(config, 'anthropic') and config.anthropic and config.anthropic.get('model_id'):
        logger.info(f"✅ Using Anthropic: {config.anthropic['model_id']}")
        from .anthropic import create_anthropic_model
        return create_anthropic_model(config, temperature)
    
    elif hasattr(config, 'openai') and config.openai and config.openai.get('model_id'):
        logger.info(f"✅ Using OpenAI: {config.openai['model_id']}")
        from .openai import create_openai_model
        return create_openai_model(config, temperature)
    
    elif hasattr(config, 'gemini') and config.gemini and config.gemini.get('model_id'):
        logger.info(f"✅ Using Gemini: {config.gemini['model_id']}")
        from .gemini import create_gemini_model
        return create_gemini_model(config, temperature)
    
    elif hasattr(config, 'ollama') and config.ollama and (config.ollama.get('model_id') or config.ollama.get('host')):
        logger.info(f"✅ Using Ollama: {config.ollama.get('model_id', 'local')}")
        from .ollama import create_ollama_model
        return create_ollama_model(config, temperature)
    
    elif hasattr(config, 'litellm') and config.litellm and config.litellm.get('model_id'):
        logger.info(f"✅ Using LiteLLM: {config.litellm['model_id']}")
        from .litellm import create_litellm_model
        return create_litellm_model(config, temperature)
    
    elif hasattr(config, 'llamaapi') and config.llamaapi and config.llamaapi.get('model_id'):
        logger.info(f"✅ Using LlamaAPI: {config.llamaapi['model_id']}")
        from .llamaapi import create_llamaapi_model
        return create_llamaapi_model(config, temperature)
    
    elif hasattr(config, 'sagemaker') and config.sagemaker and config.sagemaker.get('endpoint_name'):
        logger.info(f"✅ Using SageMaker: {config.sagemaker['endpoint_name']}")
        from .sagemaker import create_sagemaker_model
        return create_sagemaker_model(config, temperature)
    
    else:
        logger.error("❌ No model provider configured!")
        raise ValueError(
            "No model provider configured. Please uncomment one provider section in config.yaml"
        )
