# Ollama Local Model Support Implementation Plan

## Overview
Add support for Ollama as a local LLM provider alongside AWS Bedrock, giving users choice between cloud and local inference.

## Architecture Changes

### 1. Provider Abstraction Layer

**File:** `src/modules/core/llm_provider.py` (NEW)

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum

class LLMProvider(Enum):
    BEDROCK = "bedrock"
    OLLAMA = "ollama"

class BaseLLMProvider(ABC):
    @abstractmethod
    async def invoke(self, prompt: str, system: str = "", **kwargs) -> str:
        pass
    
    @abstractmethod
    async def invoke_with_images(self, prompt: str, images: List[str], **kwargs) -> str:
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        pass
    
    @abstractmethod
    def get_available_models(self) -> List[str]:
        pass
```

**File:** `src/modules/core/bedrock_provider.py` (REFACTOR)
- Extract existing Bedrock logic from tools
- Implement `BaseLLMProvider` interface
- Keep existing boto3 client initialization

**File:** `src/modules/core/ollama_provider.py` (NEW)
- Implement `BaseLLMProvider` interface
- Use `ollama` Python package
- Handle local model management
- Support vision models for image analysis

### 2. Configuration Updates

**File:** `src/modules/core/config.py`

Add fields:
```python
@dataclass
class ThreatForestConfig:
    # ... existing fields ...
    llm_provider: LLMProvider = LLMProvider.BEDROCK
    ollama_model: Optional[str] = None
    ollama_host: str = "http://localhost:11434"
    bedrock_model: Optional[str] = None
    aws_profile: Optional[str] = None
```

**File:** `src/wizard.py`

Add provider selection step:
```python
# Step 1: Provider Selection (NEW)
provider = SelectInput(
    prompt="Select LLM Provider:",
    options=["AWS Bedrock", "Ollama (Local)"]
).run()

if provider == "AWS Bedrock":
    # Existing AWS profile + model selection
    pass
elif provider == "Ollama (Local)":
    # Ollama model selection
    pass
```

### 3. Tool Updates

**Files to Update:**
- `src/modules/tools/information_extraction_tool.py`
- `src/modules/tools/attack_tree_generator_tool.py`
- `src/modules/tools/summary_generator_tool.py`

**Changes:**
```python
class InformationExtractionTool(Tool):
    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm_provider = llm_provider
        # Remove direct bedrock client
    
    async def execute(self, ...):
        response = await self.llm_provider.invoke(
            prompt=prompt,
            system=system_prompt
        )
```

### 4. Agent Integration

**File:** `src/strands_agent.py`

```python
class ThreatForestAgent(Agent):
    def __init__(self, config: ThreatForestConfig):
        # Initialize provider based on config
        if config.llm_provider == LLMProvider.BEDROCK:
            self.llm_provider = BedrockProvider(
                model=config.bedrock_model,
                profile=config.aws_profile
            )
        else:
            self.llm_provider = OllamaProvider(
                model=config.ollama_model,
                host=config.ollama_host
            )
        
        # Pass provider to tools
        self.tools = [
            InformationExtractionTool(self.llm_provider),
            AttackTreeGeneratorTool(self.llm_provider),
            SummaryGeneratorTool(self.llm_provider)
        ]
```

## UI Changes

### 1. Provider Selection Component

**File:** `ui/src/components/ProviderSelector.tsx` (NEW)

```typescript
interface ProviderOption {
  id: 'bedrock' | 'ollama';
  name: string;
  description: string;
  icon: string;
}

export const ProviderSelector: React.FC<Props> = ({ onSelect }) => {
  const providers: ProviderOption[] = [
    {
      id: 'bedrock',
      name: 'AWS Bedrock',
      description: 'Cloud-based models (requires AWS credentials)',
      icon: '☁️'
    },
    {
      id: 'ollama',
      name: 'Ollama',
      description: 'Local models (requires Ollama running)',
      icon: '🖥️'
    }
  ];
  
  return (
    <SelectInput
      items={providers}
      onSelect={onSelect}
    />
  );
};
```

### 2. Ollama Model Selector

**File:** `ui/src/components/OllamaModelSelector.tsx` (NEW)

```typescript
export const OllamaModelSelector: React.FC<Props> = ({ onSelect }) => {
  const [models, setModels] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // Fetch available models from Ollama
    fetchOllamaModels().then(setModels);
  }, []);
  
  return (
    <Box flexDirection="column">
      <Text>Available Ollama Models:</Text>
      {loading ? (
        <Spinner />
      ) : (
        <SelectInput items={models} onSelect={onSelect} />
      )}
      <Text dimColor>
        Don't see your model? Run: ollama pull llama3.2
      </Text>
    </Box>
  );
};
```

### 3. Configuration Screen Updates

**File:** `ui/src/screens/ConfigurationScreen.tsx`

Add provider selection as first step:
```typescript
const [step, setStep] = useState<'provider' | 'bedrock' | 'ollama' | 'project'>('provider');

switch(step) {
  case 'provider':
    return <ProviderSelector onSelect={handleProviderSelect} />;
  case 'bedrock':
    return <BedrockConfiguration onComplete={...} />;
  case 'ollama':
    return <OllamaConfiguration onComplete={...} />;
  case 'project':
    return <ProjectConfiguration onComplete={...} />;
}
```

### 4. Workflow State Updates

**File:** `ui/src/hooks/useWorkflow.ts`

```typescript
export interface WorkflowConfig {
  projectPath: string;
  provider: 'bedrock' | 'ollama';
  bedrockModel?: string;
  awsProfile?: string;
  ollamaModel?: string;
  ollamaHost?: string;
  enableCache: boolean;
}
```

## Dependencies

### Python
```toml
# pyproject.toml
[tool.poetry.dependencies]
ollama = "^0.3.0"  # Official Ollama Python client
```

### TypeScript
```json
// ui/package.json
{
  "dependencies": {
    "axios": "^1.6.0"  // For Ollama API calls
  }
}
```

## Implementation Phases

### Phase 1: Backend Foundation (2-3 days)
1. Create provider abstraction layer
2. Implement Ollama provider
3. Refactor Bedrock provider
4. Update configuration system
5. Add provider validation

### Phase 2: Tool Integration (1-2 days)
1. Update information extraction tool
2. Update attack tree generator tool
3. Update summary generator tool
4. Add provider to agent initialization
5. Test with both providers

### Phase 3: UI Components (2-3 days)
1. Create provider selector component
2. Create Ollama model selector
3. Update configuration screen flow
4. Add Ollama connection validation
5. Update workflow executor

### Phase 4: Testing & Documentation (1-2 days)
1. Test Bedrock provider (regression)
2. Test Ollama provider (new)
3. Test provider switching
4. Update user documentation
5. Add troubleshooting guide

## Validation & Error Handling

### Ollama Connection Check
```python
async def validate_ollama_connection(host: str) -> bool:
    try:
        response = await ollama.list()
        return True
    except Exception as e:
        logger.error(f"Ollama not available: {e}")
        return False
```

### Model Availability Check
```python
async def validate_ollama_model(model: str) -> bool:
    models = await ollama.list()
    return model in [m['name'] for m in models['models']]
```

### UI Validation
- Check Ollama service running before showing models
- Show helpful error if Ollama not installed
- Provide installation instructions
- Validate model supports vision (for image analysis)

## Configuration Examples

### Bedrock Configuration
```yaml
llm_provider: bedrock
bedrock_model: anthropic.claude-3-5-sonnet-20241022-v2:0
aws_profile: default
```

### Ollama Configuration
```yaml
llm_provider: ollama
ollama_model: llama3.2
ollama_host: http://localhost:11434
```

## Migration Strategy

### Backward Compatibility
- Default to Bedrock if no provider specified
- Auto-detect provider from existing config
- Migrate old configs to new format

### Config Migration
```python
def migrate_config(old_config: dict) -> dict:
    if 'llm_provider' not in old_config:
        old_config['llm_provider'] = 'bedrock'
        old_config['bedrock_model'] = old_config.pop('model', None)
    return old_config
```

## Performance Considerations

### Ollama Optimizations
- Use streaming for long responses
- Implement request batching where possible
- Cache model responses (existing cache system)
- Monitor local resource usage

### Provider Comparison
| Feature | Bedrock | Ollama |
|---------|---------|--------|
| Speed | Network dependent | Local (faster) |
| Cost | Pay per token | Free (local compute) |
| Models | Latest Claude | Open source models |
| Setup | AWS credentials | Local installation |
| Offline | No | Yes |

## Testing Strategy

### Unit Tests
- Provider interface compliance
- Model validation
- Configuration parsing
- Error handling

### Integration Tests
- End-to-end with Bedrock
- End-to-end with Ollama
- Provider switching
- Model fallback

### Manual Testing
- Wizard flow with both providers
- Resume workflow with different providers
- Error scenarios (Ollama down, wrong model)
- Performance comparison

## Documentation Updates

### User Documentation
- Installation guide for Ollama
- Provider selection guide
- Model recommendations
- Troubleshooting common issues

### Developer Documentation
- Provider interface specification
- Adding new providers
- Testing with mock providers
- Performance benchmarking

## Future Enhancements

### Phase 2 Features
- Support for additional providers (OpenAI, Anthropic Direct)
- Model performance benchmarking
- Automatic provider selection based on task
- Hybrid mode (use different providers for different tools)
- Cost tracking and comparison

### Advanced Features
- Model fine-tuning support
- Custom prompt templates per provider
- Provider-specific optimizations
- Multi-model ensemble
- Automatic model selection based on task complexity

## Risk Mitigation

### Risks
1. Ollama model quality varies
2. Local resource constraints
3. Breaking changes to existing Bedrock integration
4. UI complexity increase

### Mitigations
1. Document recommended models, add quality warnings
2. Add resource monitoring, provide guidance
3. Comprehensive regression testing, feature flags
4. Progressive disclosure, sensible defaults

## Success Metrics

- Both providers work without regression
- Wizard flow intuitive for both options
- Performance acceptable for Ollama
- Documentation clear and complete
- User can switch providers easily
