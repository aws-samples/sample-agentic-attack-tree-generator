# Strands Migration Plan

## Overview
This document outlines the plan to migrate all ThreatForest tools from direct Bedrock API calls to using the Strands framework.

## BaseAgent Implementation ✅

**Location:** `src/modules/core/base_agent.py`

Provides two key methods:

### 1. `get_prompt_from_file(prompt_file)`
Loads prompts from markdown files in `src/prompts/`

### 2. `get_strands_agent(prompt_file, tools, temperature, model_name)`
Creates a fully configured Strands Agent with:
- BedrockModel (from config.yaml)
- System prompt (from markdown file)
- Optional tools
- Null callback handler

## Tools to Migrate

### 1. AttackTreeGeneratorTool ⚠️ HIGH PRIORITY
**File:** `src/modules/tools/attack_tree_generator_tool.py`

**Current Approach:**
```python
from ..core.bedrock_invoker import BedrockInvoker

invoker = BedrockInvoker()
generated_content = await invoker.invoke_with_retry(
    model_id=bedrock_model,
    prompt=prompt,
    aws_profile=aws_profile
)
```

**Strands Approach:**
```python
from ..core import BaseAgent

class AttackTreeGeneratorTool(BaseAgent, Tool):
    def run(self, threat, project_info):
        # Create Strands agent
        agent = self.get_strands_agent('generate-attack-trees.md')
        
        # Build task-specific user prompt
        user_prompt = self._build_user_prompt(threat, project_info)
        
        # Run agent
        response = agent.run(user_prompt)
        
        return response
```

**Prompt File:** `generate-attack-trees.md`

---

### 2. InformationExtractionTool ⚠️ HIGH PRIORITY
**File:** `src/modules/tools/information_extraction_tool.py`

**Current Approach:**
```python
import boto3

bedrock = boto3.client('bedrock-runtime')
body = {"messages": [...]}
response = bedrock.invoke_model(modelId=model_id, body=json.dumps(body))
result = json.loads(response['body'].read())
```

**Strands Approach:**
```python
class InformationExtractionTool(BaseAgent, Tool):
    def run(self, context_files):
        agent = self.get_strands_agent('context-extraction.md')
        
        user_prompt = f"Analyze these files:\n{context_files}"
        response = agent.run(user_prompt)
        
        return response
```

**Prompt File:** `context-extraction.md`

---

### 3. ContextAnalysisTool
**File:** `src/modules/tools/context_analysis_tool.py`

**Current Approach:**
```python
bedrock = boto3.client('bedrock-runtime')
response = bedrock.invoke_model(modelId=model_id, ...)
```

**Strands Approach:**
```python
class ContextAnalysisTool(BaseAgent, Tool):
    def run(self, project_path):
        agent = self.get_strands_agent('project-analysis.md')
        
        user_prompt = f"Analyze project at: {project_path}"
        response = agent.run(user_prompt)
        
        return response
```

**Prompt File:** `project-analysis.md`

---

### 4. SetupTool
**File:** `src/modules/tools/setup_tool.py`

**Current Approach:**
```python
bedrock = boto3.client('bedrock-runtime')  
response = bedrock.invoke_model(modelId=model_id, ...)
```

**Strands Approach:**
```python
class SetupTool(BaseAgent, Tool):
    def run(self, config_data):
        # Validation likely doesn't need LLM
        # But if it does:
        agent = self.get_strands_agent('setup-validation.md')
        response = agent.run(validation_prompt)
        return response
```

---

## Migration Benefits

### ✅ What Strands Provides:
1. **Automatic Retry Logic** - Built into Agent.run()
2. **Rate Limiting** - Managed by Strands
3. **Error Handling** - Consistent across all tools
4. **Session Pooling** - Efficient connection reuse
5. **Callback Hooks** - For progress tracking
6. **Tool Integration** - Can pass Strands tools to agents

### ❌ What We Remove:
1. BedrockInvoker (replaced by Strands)
2. Manual boto3 client creation
3. Custom retry logic
4. Manual error handling
5. Direct API calls

---

## Implementation Order

### Phase 1: Core Infrastructure ✅
- [x] Create BaseAgent class
- [x] Add to core module exports

### Phase 2: Tool Refactoring
- [ ] AttackTreeGeneratorTool (most complex, highest impact)
- [ ] InformationExtractionTool (multiple Bedrock calls)
- [ ] ContextAnalysisTool (single call)
- [ ] SetupTool (validation only)

### Phase 3: Cleanup
- [ ] Deprecate BedrockInvoker
- [ ] Remove unused bedrock_client code
- [ ] Update documentation

---

## Testing Strategy

After each tool migration:
1. Run tool independently
2. Run full workflow
3. Verify output matches previous implementation
4. Check error handling works

---

## Notes

- System prompts loaded from existing `.md` files
- BaseAgent handles all Strands boilerplate
- Tools just inherit and use `get_strands_agent()`
- Config.yaml drives model selection
- Neptune account validation still in TTCMappingTool
