"""
LLM client with retry logic and multiple provider support.
"""

import time
import random
import json
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .config import LLMConfig
from .exceptions import LLMError, ConfigurationError
from .utils import get_logger


@dataclass
class LLMResponse:
    """Response from LLM API call."""
    content: str
    usage: Dict[str, Any]
    model: str
    provider: str
    response_time: float


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response from prompt."""
        pass
    
    @abstractmethod
    def validate_config(self, config: LLMConfig) -> None:
        """Validate provider-specific configuration."""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        try:
            import openai
            self.client = openai.OpenAI(api_key=config.api_key)
        except ImportError:
            raise ConfigurationError("OpenAI package not installed. Run: pip install openai")
    
    def validate_config(self, config: LLMConfig) -> None:
        """Validate OpenAI configuration."""
        if not config.api_key:
            raise ConfigurationError("OpenAI API key is required")
        
        valid_models = [
            "gpt-4", "gpt-4-turbo", "gpt-4-turbo-preview",
            "gpt-3.5-turbo", "gpt-3.5-turbo-16k"
        ]
        
        if config.model not in valid_models:
            self.logger.warning(f"Model {config.model} may not be supported by OpenAI")
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response using OpenAI API."""
        start_time = time.time()
        
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                timeout=self.config.timeout,
                **kwargs
            )
            
            response_time = time.time() - start_time
            
            return LLMResponse(
                content=response.choices[0].message.content,
                usage=response.usage.model_dump() if response.usage else {},
                model=response.model,
                provider="openai",
                response_time=response_time
            )
            
        except Exception as e:
            raise LLMError(f"OpenAI API error: {e}")


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=config.api_key)
        except ImportError:
            raise ConfigurationError("Anthropic package not installed. Run: pip install anthropic")
    
    def validate_config(self, config: LLMConfig) -> None:
        """Validate Anthropic configuration."""
        if not config.api_key:
            raise ConfigurationError("Anthropic API key is required")
        
        valid_models = [
            "claude-3-opus-20240229", "claude-3-sonnet-20240229", 
            "claude-3-haiku-20240307", "claude-2.1", "claude-2.0"
        ]
        
        if config.model not in valid_models:
            self.logger.warning(f"Model {config.model} may not be supported by Anthropic")
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response using Anthropic API."""
        start_time = time.time()
        
        try:
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}],
                timeout=self.config.timeout,
                **kwargs
            )
            
            response_time = time.time() - start_time
            
            return LLMResponse(
                content=response.content[0].text,
                usage=response.usage.__dict__ if hasattr(response, 'usage') else {},
                model=response.model,
                provider="anthropic",
                response_time=response_time
            )
            
        except Exception as e:
            raise LLMError(f"Anthropic API error: {e}")


class BedrockProvider(LLMProvider):
    """AWS Bedrock provider for Claude and other models."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        try:
            import boto3
            from botocore.config import Config
            
            # Configure boto3 client
            boto_config = Config(
                region_name=config.region,
                retries={'max_attempts': config.max_retries}
            )
            
            # Create session with credentials if provided
            session_kwargs = {}
            if config.aws_access_key_id:
                session_kwargs['aws_access_key_id'] = config.aws_access_key_id
            if config.aws_secret_access_key:
                session_kwargs['aws_secret_access_key'] = config.aws_secret_access_key
            if config.aws_session_token:
                session_kwargs['aws_session_token'] = config.aws_session_token
            
            if session_kwargs:
                session = boto3.Session(**session_kwargs)
                self.client = session.client('bedrock-runtime', config=boto_config)
            else:
                # Use default credentials (profile, IAM role, etc.)
                self.client = boto3.client('bedrock-runtime', region_name=config.region, config=boto_config)
                
        except ImportError:
            raise ConfigurationError("Boto3 package not installed. Run: pip install boto3")
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Bedrock client: {e}")
    
    def validate_config(self, config: LLMConfig) -> None:
        """Validate Bedrock configuration."""
        valid_models = [
            "anthropic.claude-3-opus-20240229-v1:0",
            "anthropic.claude-3-sonnet-20240229-v1:0", 
            "anthropic.claude-3-haiku-20240307-v1:0",
            "anthropic.claude-v2:1",
            "anthropic.claude-v2",
            "anthropic.claude-instant-v1",
            "amazon.titan-text-express-v1",
            "amazon.titan-text-lite-v1",
            "ai21.j2-ultra-v1",
            "ai21.j2-mid-v1",
            "cohere.command-text-v14",
            "meta.llama2-13b-chat-v1",
            "meta.llama2-70b-chat-v1"
        ]
        
        if config.model not in valid_models:
            self.logger.warning(f"Model {config.model} may not be supported by Bedrock")
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response using Bedrock."""
        start_time = time.time()
        
        try:
            # Prepare request body based on model type
            if self.config.model.startswith("anthropic.claude"):
                body = {
                    "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                    "max_tokens_to_sample": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "top_p": 0.9,
                    "stop_sequences": ["\n\nHuman:"]
                }
            elif self.config.model.startswith("amazon.titan"):
                body = {
                    "inputText": prompt,
                    "textGenerationConfig": {
                        "maxTokenCount": self.config.max_tokens,
                        "temperature": self.config.temperature,
                        "topP": 0.9,
                        "stopSequences": []
                    }
                }
            elif self.config.model.startswith("ai21.j2"):
                body = {
                    "prompt": prompt,
                    "maxTokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "topP": 0.9
                }
            elif self.config.model.startswith("cohere.command"):
                body = {
                    "prompt": prompt,
                    "max_tokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "p": 0.9
                }
            elif self.config.model.startswith("meta.llama"):
                body = {
                    "prompt": prompt,
                    "max_gen_len": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "top_p": 0.9
                }
            else:
                # Default format for Claude
                body = {
                    "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                    "max_tokens_to_sample": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "top_p": 0.9,
                    "stop_sequences": ["\n\nHuman:"]
                }
            
            # Make API call
            response = self.client.invoke_model(
                modelId=self.config.model,
                body=json.dumps(body),
                contentType='application/json',
                accept='application/json'
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            response_time = time.time() - start_time
            
            # Extract content based on model type
            if self.config.model.startswith("anthropic.claude"):
                content = response_body.get('completion', '')
            elif self.config.model.startswith("amazon.titan"):
                results = response_body.get('results', [])
                content = results[0].get('outputText', '') if results else ''
            elif self.config.model.startswith("ai21.j2"):
                completions = response_body.get('completions', [])
                content = completions[0].get('data', {}).get('text', '') if completions else ''
            elif self.config.model.startswith("cohere.command"):
                generations = response_body.get('generations', [])
                content = generations[0].get('text', '') if generations else ''
            elif self.config.model.startswith("meta.llama"):
                content = response_body.get('generation', '')
            else:
                content = response_body.get('completion', response_body.get('outputText', ''))
            
            # Extract usage information
            usage = {}
            if 'usage' in response_body:
                usage = response_body['usage']
            elif 'amazon-bedrock-invocationMetrics' in response.get('ResponseMetadata', {}).get('HTTPHeaders', {}):
                metrics = response['ResponseMetadata']['HTTPHeaders']['amazon-bedrock-invocationMetrics']
                usage = json.loads(metrics) if isinstance(metrics, str) else metrics
            
            return LLMResponse(
                content=content.strip(),
                usage=usage,
                model=self.config.model,
                provider="bedrock",
                response_time=response_time
            )
            
        except Exception as e:
            raise LLMError(f"Bedrock API error: {e}")


class LLMClient:
    """Main LLM client with retry logic and provider abstraction."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Initialize provider
        self.provider = self._create_provider(config)
        self.provider.validate_config(config)
        
        self.logger.info(f"Initialized LLM client: {config.provider} with model {config.model}")
    
    def _create_provider(self, config: LLMConfig) -> LLMProvider:
        """Create appropriate provider based on configuration."""
        if config.provider == "openai":
            return OpenAIProvider(config)
        elif config.provider == "anthropic":
            return AnthropicProvider(config)
        elif config.provider == "bedrock":
            return BedrockProvider(config)
        else:
            raise ConfigurationError(f"Unsupported LLM provider: {config.provider}")
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate response with retry logic.
        
        Args:
            prompt: Input prompt for the LLM
            **kwargs: Additional parameters for the provider
            
        Returns:
            LLMResponse object
        """
        last_error = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                if attempt > 0:
                    # Exponential backoff with jitter
                    delay = (2 ** attempt) + random.uniform(0, 1)
                    self.logger.info(f"Retrying LLM call in {delay:.2f} seconds (attempt {attempt + 1})")
                    time.sleep(delay)
                
                response = self.provider.generate(prompt, **kwargs)
                
                if attempt > 0:
                    self.logger.info(f"LLM call succeeded on attempt {attempt + 1}")
                
                return response
                
            except LLMError as e:
                last_error = e
                self.logger.warning(f"LLM call failed (attempt {attempt + 1}): {e}")
                
                # Don't retry on certain errors
                if "invalid_api_key" in str(e).lower() or "unauthorized" in str(e).lower():
                    break
                
                if attempt == self.config.max_retries:
                    break
        
        # All retries failed
        raise LLMError(f"LLM call failed after {self.config.max_retries + 1} attempts. Last error: {last_error}")
    
    def validate_response(self, response: LLMResponse, expected_format: Optional[str] = None) -> bool:
        """
        Validate LLM response format and content.
        
        Args:
            response: LLM response to validate
            expected_format: Expected format (json, markdown, mermaid, etc.)
            
        Returns:
            True if response is valid
        """
        if not response.content or not response.content.strip():
            self.logger.warning("LLM response is empty")
            return False
        
        if expected_format == "json":
            try:
                import json
                json.loads(response.content)
                return True
            except json.JSONDecodeError:
                self.logger.warning("LLM response is not valid JSON")
                return False
        
        elif expected_format == "mermaid":
            # Basic Mermaid validation
            content = response.content.strip()
            if not content.startswith("graph") and not content.startswith("flowchart"):
                self.logger.warning("LLM response does not appear to be a Mermaid diagram")
                return False
        
        return True
    
    def create_extraction_prompt(self, context: str, extraction_type: str) -> str:
        """
        Create structured prompt for information extraction.
        
        Args:
            context: Context content to analyze
            extraction_type: Type of extraction (app_info, threats, etc.)
            
        Returns:
            Formatted prompt string
        """
        if extraction_type == "app_info":
            return f"""
Analyze the following application context and extract key information in JSON format.

Context:
{context}

Please extract the following information and return it as a JSON object:
{{
    "name": "Application name",
    "description": "Brief description of the application",
    "technologies": ["list", "of", "technologies", "used"],
    "programming_languages": ["list", "of", "programming", "languages"],
    "sector": "Industry sector (e.g., finance, healthcare, e-commerce)",
    "security_objectives": ["Confidentiality", "Integrity", "Availability"],
    "additional_context": {{
        "deployment_model": "cloud/on-premise/hybrid",
        "user_base": "internal/external/mixed",
        "data_sensitivity": "high/medium/low"
    }}
}}

Focus on extracting concrete information mentioned in the context. If information is not available, use empty strings or arrays.
"""
        
        elif extraction_type == "threats":
            return f"""
Analyze the following content and extract threat statements with their severity levels.

Content:
{context}

Please extract threat statements and return them as a JSON array:
[
    {{
        "id": "unique_identifier",
        "title": "Threat title",
        "description": "Detailed threat description",
        "severity": "high|medium|low",
        "category": "threat category",
        "impact": "potential impact",
        "likelihood": "likelihood assessment"
    }}
]

Only extract threats that have clear severity indicators. Focus on high-severity threats.
"""
        
        else:
            raise ValueError(f"Unknown extraction type: {extraction_type}")
    
    def create_attack_tree_prompt(self, threat: Dict[str, Any], app_context: str) -> str:
        """
        Create prompt for attack tree generation.
        
        Args:
            threat: Threat statement dictionary
            app_context: Application context information
            
        Returns:
            Formatted prompt for attack tree generation
        """
        return f"""
Generate an attack tree in Mermaid format for the following threat:

Threat: {threat.get('title', 'Unknown')}
Description: {threat.get('description', 'No description')}
Severity: {threat.get('severity', 'unknown')}

Application Context:
{app_context}

Create a Mermaid flowchart diagram using this exact format:

## Structure Requirements:
- Use `graph TD` (top-down direction)
- Node format: `node_id["descriptive text"]`
- Connection format: `parent --> child`
- Include all relationships from the attack path

## Node Classification:
- **Facts**: Initial conditions, vulnerabilities, or starting points
- **Attacks**: Malicious actions, exploits, or threat vectors  
- **Mitigations**: Security controls, defenses, or countermeasures
- **Goals**: Ultimate objectives or outcomes (what attackers achieve)

## Output Format:
1. Start with: ```mermaid
2. Begin with: graph TD
3. Define nodes and connections
4. End with color coding:

```
classDef attack fill:#ffcccc
classDef mitigation fill:#ccffcc  
classDef goal fill:#ffcc99
classDef fact fill:#ccccff

class node1,node2 attack
class node3,node4 mitigation
class node5 goal
class node6 fact
```

Generate a comprehensive attack tree that shows realistic attack paths for this threat.
"""