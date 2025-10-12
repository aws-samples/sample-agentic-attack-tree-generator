# ThreatForest Efficiency Improvements - October 13th

## Overview
This document identifies efficiency improvements for the ThreatForest codebase while maintaining exact functionality and outputs. All changes are non-breaking and focus on performance, maintainability, and code quality.

---

## 1. Bedrock Client Connection Pooling

### Current Issue
**Impact:** High | **Effort:** Low | **Priority:** 1

Each tool creates new boto3 sessions and Bedrock clients for every invocation:
- `information_extraction_tool.py`: 5 separate client creations
- `attack_tree_generator_tool.py`: 1 client per threat
- `ttc_mapping_tool.py`: 2 separate client creations
- `setup_tool.py`: 3 separate client creations

**Problem:**
- Creates 10+ redundant connections per workflow
- Each connection has TCP handshake overhead (~100-200ms)
- No connection reuse across tools
- Wastes memory with duplicate client objects

### Solution
Use existing `BedrockClientManager` singleton across all tools.

**Files to Update:**
- `src/modules/tools/information_extraction_tool.py`
- `src/modules/tools/attack_tree_generator_tool.py`
- `src/modules/tools/ttc_mapping_tool.py`
- `src/modules/tools/setup_tool.py`

**Implementation:**
```python
# Replace all instances of:
session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
bedrock = session.client('bedrock-runtime', region_name='us-east-1')

# With:
from ..core.bedrock_client import BedrockClientManager
bedrock = BedrockClientManager().get_client(profile_name=aws_profile, region_name='us-east-1')
```

**Expected Improvement:**
- Reduce connection overhead by 80-90%
- Save ~1-2 seconds per workflow
- Reduce memory footprint by ~50MB

---

## 2. Duplicate Bedrock Invocation Logic

### Current Issue
**Impact:** Medium | **Effort:** Medium | **Priority:** 2

Each tool implements its own Bedrock invocation with retry logic:
- Duplicate error handling (ThrottlingException, ModelTimeoutException)
- Duplicate exponential backoff implementation
- Duplicate JSON parsing and validation
- Inconsistent retry strategies across tools

**Problem:**
- ~200 lines of duplicate code across 4 tools
- Inconsistent error handling
- Harder to maintain and update
- Risk of divergent behavior

### Solution
Create centralized `BedrockInvoker` utility class.

**New File:** `src/modules/core/bedrock_invoker.py`

```python
class BedrockInvoker:
    """Centralized Bedrock invocation with retry logic and error handling"""
    
    def __init__(self, client, rate_limit_delay=2.5, max_retries=3):
        self.client = client
        self.rate_limit_delay = rate_limit_delay
        self.max_retries = max_retries
        self.base_backoff = 2
    
    async def invoke_with_retry(
        self, 
        model_id: str,
        messages: List[Dict],
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """Invoke Bedrock with automatic retry and error handling"""
        # Centralized implementation
        pass
    
    async def invoke_with_images(
        self,
        model_id: str,
        prompt: str,
        images: List[str],
        system: str = ""
    ) -> str:
        """Invoke Bedrock with image support"""
        pass
```

**Expected Improvement:**
- Remove ~200 lines of duplicate code
- Consistent error handling across all tools
- Single place to optimize retry logic
- Easier to add new features (streaming, caching)

---

## 3. Prompt Template Management

### Current Issue
**Impact:** Low | **Effort:** Low | **Priority:** 3

Prompts are hardcoded strings scattered throughout tool files:
- Long multi-line strings in method bodies
- Difficult to version and test
- Hard to optimize without code changes
- No prompt reuse across tools

**Problem:**
- Prompts mixed with business logic
- Can't A/B test prompts easily
- Difficult to maintain consistency
- No prompt versioning

### Existing Prompts Directory

**Location:** `src/prompts/`

**Existing prompt files:**
1. `generate-attack-trees.md` (4.2KB) - Attack tree generation prompt
2. `mermaid-prompt.md` (1KB) - Mermaid diagram formatting
3. `mitigations.md` (1.2KB) - Mitigation recommendations
4. `ttc-mapping.md` (967B) - MITRE ATT&CK TTC mapping

### Current Prompt Locations

#### Attack Tree Generator Tool
**File:** `src/modules/tools/attack_tree_generator_tool.py`

**Status:** ✅ Correctly externalized
- **Line 415-515**: `_build_attack_tree_prompt()` method
- **Line 467**: Loads from `src/prompts/generate-attack-trees.md` ✅
- **Line 476**: Falls back to hardcoded prompt if file not found
- **Path resolution:** `Path(__file__).parent.parent.parent / "prompts" / "generate-attack-trees.md"`

**Current behavior:** Successfully loads external prompt from `src/prompts/`.

#### Information Extraction Tool
**File:** `src/modules/tools/information_extraction_tool.py`

**All hardcoded prompts:**
1. **Line 971**: `_extract_project_info()` - Project analysis prompt
   - "You are a cybersecurity expert analyzing an application..."
   - Extracts: technologies, architecture, security objectives

2. **Line 1362**: `_generate_threats_from_existing_content()` - Existing content analysis
   - "You are a cybersecurity expert analyzing existing threat model documentation..."
   - Converts unstructured threats to structured format

3. **Line 1422**: `_generate_threats_with_bedrock()` - New threat generation
   - "You are a cybersecurity expert analyzing an application for threat modeling..."
   - Generates new threats from scratch

4. **Line 1730**: `_parse_and_fix_threats()` - Threat format fixing
   - "You are a cybersecurity expert. I have a threat model document..."
   - Fixes incorrectly formatted threats

5. **Line 1865**: `_parse_mixed_threats()` - Mixed format handling
   - "You are a cybersecurity expert. I have a threat model document with mixed formats..."
   - Handles partially correct threat formats

#### TTC Mapping Tool
**File:** `src/modules/tools/ttc_mapping_tool.py`

**All hardcoded prompts:**
1. **Line 274**: `_build_mapping_prompt()` - Attack step mapping
   - "You are a cybersecurity expert. Map these attack steps to MITRE ATT&CK techniques..."
   - Maps individual attack steps to techniques

2. **Line 407**: `_map_attack_tree_to_ttc()` - Full tree mapping
   - "You are a cybersecurity expert. Analyze this attack tree and map each step..."
   - Maps entire attack tree to MITRE framework

#### Summary Generator Tool
**File:** `src/modules/tools/summary_generator_tool.py`

**Status:** No LLM prompts (generates summaries from structured data)

### Solution
Extract remaining prompts to `src/prompts/` directory (matching attack tree generator pattern).

**Target Directory:** `src/prompts/` (already exists)

**New prompt files to create:**
```
src/prompts/
├── generate-attack-trees.md          # ✅ Already exists
├── mermaid-prompt.md                 # ✅ Already exists  
├── mitigations.md                    # ✅ Already exists
├── ttc-mapping.md                    # ✅ Already exists
├── project-analysis.md               # NEW - Line 971 from information_extraction
├── threat-generation-existing.md     # NEW - Line 1362 from information_extraction
├── threat-generation-new.md          # NEW - Line 1422 from information_extraction
├── threat-format-fixing.md           # NEW - Line 1730 from information_extraction
└── threat-mixed-format.md            # NEW - Line 1865 from information_extraction
```

**Standardized Prompt Loader Pattern:**

All tools should use the same pattern as `attack_tree_generator_tool.py`:

```python
def _load_prompt_template(self, prompt_name: str) -> str:
    """Load prompt from src/prompts/ directory"""
    prompt_file = Path(__file__).parent.parent.parent / "prompts" / f"{prompt_name}.md"
    try:
        with open(prompt_file, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        self.logger.error(f"Prompt file not found: {prompt_file}")
        raise
```

**Migration Example:**

```python
# BEFORE (information_extraction_tool.py line 971):
prompt = f"""You are a cybersecurity expert analyzing an application. Extract key information from the provided content including text documents and architecture diagrams.

## Context Files:
{context_content}

## Instructions:
Extract the following information in JSON format:
..."""

# AFTER:
prompt_template = self._load_prompt_template("project-analysis")
prompt = f"{prompt_template}\n\n## Context Files:\n{context_content}"
```

**Files to Update:**
1. `src/modules/tools/attack_tree_generator_tool.py` - ✅ Already using `src/prompts/`
2. `src/modules/tools/information_extraction_tool.py` - Add `_load_prompt_template()` method, extract 5 prompts
3. `src/modules/tools/ttc_mapping_tool.py` - Add `_load_prompt_template()` method, use existing `ttc-mapping.md`

**Implementation Steps:**

1. **Create 5 new prompt files in `src/prompts/`:**
   - Extract hardcoded prompts from `information_extraction_tool.py` lines 971, 1362, 1422, 1730, 1865
   - Save as markdown files with clear structure

2. **Add `_load_prompt_template()` to `information_extraction_tool.py`:**
   ```python
   def _load_prompt_template(self, prompt_name: str) -> str:
       """Load prompt from src/prompts/ directory"""
       prompt_file = Path(__file__).parent.parent.parent / "prompts" / f"{prompt_name}.md"
       try:
           with open(prompt_file, 'r', encoding='utf-8') as f:
               return f.read()
       except FileNotFoundError:
           self.logger.error(f"Prompt file not found: {prompt_file}")
           raise
   ```

3. **Update `ttc_mapping_tool.py` to use existing `ttc-mapping.md`:**
   - Add same `_load_prompt_template()` method
   - Replace hardcoded prompts at lines 274 and 407
   - Use existing `src/prompts/ttc-mapping.md` file

**Expected Improvement:**
- Cleaner code separation
- Easier prompt optimization
- Enable prompt versioning
- Facilitate A/B testing
- Single source of truth for prompts
- Easier collaboration on prompt engineering

---

## 4. Async/Await Optimization

### Current Issue
**Impact:** Medium | **Effort:** Medium | **Priority:** 4

Mixed sync/async patterns causing inefficiencies:
- `asyncio.sleep()` used for rate limiting (blocks event loop)
- Sequential Bedrock calls that could be parallel
- Sync file I/O in async methods
- No concurrent processing of independent threats

**Problem:**
- Underutilized async capabilities
- Unnecessary blocking operations
- Slower than necessary execution
- Event loop not fully leveraged

### Solution
Optimize async patterns and add concurrency where safe.

**Changes:**

1. **Replace sleep-based rate limiting with semaphore:**
```python
class RateLimiter:
    def __init__(self, calls_per_second: float):
        self.semaphore = asyncio.Semaphore(int(calls_per_second))
        self.delay = 1.0 / calls_per_second
    
    async def acquire(self):
        async with self.semaphore:
            await asyncio.sleep(self.delay)
```

2. **Parallel threat processing (where safe):**
```python
# In attack_tree_generator_tool.py
async def _process_threats_parallel(self, threats, max_concurrent=3):
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_with_limit(threat):
        async with semaphore:
            return await self._generate_single_tree(threat)
    
    results = await asyncio.gather(
        *[process_with_limit(t) for t in threats],
        return_exceptions=True
    )
    return results
```

3. **Async file I/O:**
```python
import aiofiles

async def _save_state_async(self, state_data, output_dir):
    async with aiofiles.open(state_file, 'w') as f:
        await f.write(json.dumps(state_data, indent=2))
```

**Expected Improvement:**
- 20-30% faster execution for multi-threat workflows
- Better resource utilization
- More responsive progress updates
- Reduced blocking operations

---

## 5. JSON Parsing and Validation

### Current Issue
**Impact:** Low | **Effort:** Low | **Priority:** 5

Repeated JSON parsing patterns with inconsistent error handling:
- Manual JSON extraction from responses
- Duplicate validation logic
- Inconsistent error messages
- No schema validation

**Problem:**
- Fragile parsing code
- Inconsistent error handling
- Hard to debug parsing failures
- No type safety

### Solution
Create centralized JSON utilities with schema validation.

**New File:** `src/modules/utils/json_utils.py`

```python
from typing import TypeVar, Type, Optional
from pydantic import BaseModel, ValidationError

T = TypeVar('T', bound=BaseModel)

class JSONParser:
    """Centralized JSON parsing with validation"""
    
    @staticmethod
    def extract_from_response(response: Dict, content_key: str = "content") -> str:
        """Extract JSON from Bedrock response"""
        pass
    
    @staticmethod
    def parse_with_schema(json_str: str, schema: Type[T]) -> T:
        """Parse and validate JSON against Pydantic schema"""
        pass
    
    @staticmethod
    def safe_parse(json_str: str, default: Optional[Dict] = None) -> Dict:
        """Parse JSON with fallback to default"""
        pass
```

**Define Schemas:**
```python
# src/modules/schemas/threat_schema.py
from pydantic import BaseModel, Field

class ThreatStatement(BaseModel):
    id: str
    category: str
    severity: str
    priority: Optional[str]
    threat_statement: str
    threat_source: Optional[str]
    prerequisites: Optional[str]
    threat_action: Optional[str]
    threat_impact: Optional[str]
```

**Expected Improvement:**
- Type-safe JSON handling
- Better error messages
- Consistent validation
- Easier debugging

---

## 6. Code Duplication Reduction

### Current Issue
**Impact:** Low | **Effort:** Medium | **Priority:** 10

Significant code duplication across tools:
- Similar validation logic in multiple tools
- Duplicate file handling code
- Repeated state management patterns
- Common utility functions duplicated

**Problem:**
- Harder to maintain
- Inconsistent behavior
- Bug fixes need multiple updates
- Increased codebase size

### Solution
Extract common patterns to shared utilities.

**New Files:**

1. **`src/modules/utils/validation.py`**
```python
class Validator:
    @staticmethod
    def validate_threat_statement(threat: Dict) -> bool:
        """Common threat validation logic"""
        pass
    
    @staticmethod
    def validate_project_path(path: str) -> bool:
        """Common path validation"""
        pass
```

2. **`src/modules/utils/file_handler.py`**
```python
class FileHandler:
    @staticmethod
    async def read_json(path: Path) -> Dict:
        """Common JSON file reading"""
        pass
    
    @staticmethod
    async def write_json(path: Path, data: Dict):
        """Common JSON file writing"""
        pass
```

3. **`src/modules/utils/state_helper.py`**
```python
class StateHelper:
    @staticmethod
    def merge_states(state1: Dict, state2: Dict) -> Dict:
        """Common state merging logic"""
        pass
```

**Expected Improvement:**
- Reduce codebase by ~500 lines
- Consistent behavior across tools
- Easier maintenance
- Single source of truth

---

## 7. Pydantic v2 Migration Verification

### Current Issue
**Impact:** Low | **Effort:** Low | **Priority:** 11

Project specifies Pydantic v2 (`pydantic>=2.0.0`) but may not be using all v2 features optimally.

**Current Status:**
- `pyproject.toml`: `pydantic>=2.0.0` ✅
- Using Pydantic v2 imports: `BaseModel`, `Field`, `field_validator`, `model_validator` ✅
- Models in use: `ThreatForestState`, `ProgressEvent`, validation schemas ✅

**Potential Issues:**
- May be using v1 compatibility patterns
- Not leveraging v2 performance improvements
- Missing v2-specific features (computed fields, serialization modes)

### Solution
Audit and optimize Pydantic v2 usage.

**Files to Review:**
1. `src/modules/core/state.py` - State models
2. `src/modules/core/progress_events.py` - Event models
3. `src/modules/core/validation.py` - Input validation schemas

**V2 Optimizations to Apply:**

1. **Use `model_dump()` instead of `dict()`:**
```python
# V1 style (deprecated)
state_dict = state.dict()

# V2 style
state_dict = state.model_dump()
```

2. **Use `model_validate()` for parsing:**
```python
# V2 style
state = ThreatForestState.model_validate(data)
```

3. **Leverage computed fields:**
```python
from pydantic import computed_field

class ThreatForestState(BaseModel):
    started_at: datetime
    last_updated: datetime
    
    @computed_field
    @property
    def duration_seconds(self) -> float:
        return (self.last_updated - self.started_at).total_seconds()
```

4. **Use serialization modes:**
```python
# Exclude None values
state.model_dump(exclude_none=True)

# JSON serialization
state.model_dump_json()
```

**Expected Improvement:**
- 20-30% faster validation
- Better type safety
- Cleaner serialization
- Reduced memory usage

---

## 8. Bedrock SDK Update

### Current Issue
**Impact:** Medium | **Effort:** Low | **Priority:** 12

Using older boto3/botocore versions that may lack latest Bedrock features.

**Current Versions:**
- `boto3>=1.34.0` (released ~Jan 2024)
- `botocore>=1.34.0`

**Latest Features Missing:**
- Bedrock Converse API (unified interface)
- Improved streaming support
- Better error messages
- Cross-region inference improvements
- New model support (Claude 3.7, etc.)

### Solution
Update to latest Bedrock SDK and adopt new APIs.

**Update Dependencies:**
```toml
# pyproject.toml
[tool.poetry.dependencies]
boto3 = "^1.35.0"  # Latest stable
botocore = "^1.35.0"
```

**Adopt Converse API:**

```python
# OLD: invoke_model
response = bedrock.invoke_model(
    modelId=model_id,
    body=json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}]
    })
)
response_body = json.loads(response['body'].read())
content = response_body['content'][0]['text']

# NEW: converse (unified API)
response = bedrock.converse(
    modelId=model_id,
    messages=[{"role": "user", "content": [{"text": prompt}]}],
    inferenceConfig={
        "maxTokens": 4096,
        "temperature": 0.7
    }
)
content = response['output']['message']['content'][0]['text']
```

**Benefits:**
- Unified API across all models
- Better error handling
- Simplified code
- Future-proof
- Support for latest models

**Files to Update:**
1. `src/modules/tools/information_extraction_tool.py` - 5 Bedrock calls
2. `src/modules/tools/attack_tree_generator_tool.py` - 1 Bedrock call
3. `src/modules/tools/ttc_mapping_tool.py` - 2 Bedrock calls
4. `src/modules/core/bedrock_client.py` - Client configuration

**Migration Strategy:**
1. Update dependencies
2. Create wrapper for Converse API
3. Migrate one tool at a time
4. Test thoroughly
5. Remove old invoke_model code

**Expected Improvement:**
- Cleaner code (30% less boilerplate)
- Better error messages
- Support for latest models
- Improved reliability

---

## Dependencies and Interactions Between Improvements

### Critical Dependencies

#### Priority 8 (Bedrock SDK) → Priority 1 (Client Pooling)
**Impact:** High - Must coordinate changes

**Issue:**
- Bedrock SDK update changes API from `invoke_model` to `converse`
- Client pooling implementation must support both APIs during migration
- Connection pooling configuration may need adjustment for Converse API

**Solution:**
```python
class BedrockClientManager:
    def get_client(self, profile_name: Optional[str] = None, region_name: str = "us-west-2"):
        # Same pooling logic works for both APIs
        # Converse API uses same bedrock-runtime client
        client = session.client('bedrock-runtime', region_name=region_name, config=config)
        return client
```

**Recommendation:** 
- Implement Priority 1 (Client Pooling) first with current API
- Then update to Priority 8 (SDK Update) - pooling remains unchanged
- Client pooling is API-agnostic (works with both `invoke_model` and `converse`)

---

#### Priority 8 (Bedrock SDK) → Priority 2 (Duplicate Invocation Logic)
**Impact:** High - Simplifies implementation

**Issue:**
- Duplicate invocation logic currently handles `invoke_model` API
- Bedrock SDK update to Converse API changes invocation pattern
- Centralizing before SDK update means updating in one place

**Solution:**
- Implement Priority 2 first (centralize invocation logic)
- Then update Priority 8 (SDK) - only update centralized code
- Avoids updating 10+ scattered invocation points

**Recommendation:**
- Priority 2 BEFORE Priority 8
- Creates single update point for API migration

---

#### Priority 7 (Pydantic v2) → Priority 5 (JSON Parsing)
**Impact:** Medium - Complementary improvements

**Issue:**
- JSON parsing can leverage Pydantic v2 validation
- Pydantic v2 has better JSON serialization
- Both improve type safety

**Solution:**
```python
# Priority 11: Verify using v2 patterns
state.model_dump_json()  # V2 serialization

# Priority 5: Use Pydantic for JSON validation
class ThreatStatement(BaseModel):
    id: str
    severity: str
    
threat = ThreatStatement.model_validate_json(json_str)  # V2 parsing
```

**Recommendation:**
- Can be done in parallel
- Priority 7 verification enables Priority 5 schemas

---

#### Priority 3 (Prompt Templates) → Priority 2 (Invocation Logic)
**Impact:** Low - Independent changes

**Issue:**
- Prompt templates are just strings passed to invocation logic
- No API dependency between them

**Solution:**
- Completely independent
- Can be done in any order or parallel

**Recommendation:**
- Parallel implementation safe

---

### Recommended Implementation Order

#### Phase 1A: Foundation (Day 1 Morning)
**Order matters:**
1. Priority 1: Bedrock Client Pooling (foundation for all Bedrock calls)
2. Priority 2: Duplicate Invocation Logic (centralize before SDK change)
3. Priority 7: Pydantic v2 Verification (enables better validation)

**Rationale:** Sets up infrastructure before API changes

#### Phase 1B: Updates (Day 1 Afternoon)
**Order matters:**
4. Priority 8: Bedrock SDK Update (now only updates centralized code)

**Rationale:** API changes done after centralization

#### Phase 2: Enhancements (Day 2)
**Can be parallel:**
- Priority 3: Prompt Template Management
- Priority 5: JSON Parsing & Validation
- Priority 6: Code Duplication

**Rationale:** Independent improvements

---

### Interaction Matrix

| From → To | Priority 1 | Priority 2 | Priority 3 | Priority 7 | Priority 8 |
|-----------|-----------|-----------|-----------|-------------|-------------|
| **Priority 1** (Client Pool) | - | ✅ Enables | ⚪ None | ⚪ None | ⚪ None |
| **Priority 2** (Invocation) | ⚪ None | - | ⚪ None | ⚪ None | ✅ Simplifies |
| **Priority 3** (Prompts) | ⚪ None | ⚪ None | - | ⚪ None | ⚪ None |
| **Priority 7** (Pydantic) | ⚪ None | ⚪ None | ⚪ None | - | ⚪ None |
| **Priority 8** (SDK) | ⚠️ Must coordinate | ⚠️ Easier after | ⚪ None | ⚪ None | - |

**Legend:**
- ✅ Enables/Simplifies - Do first item before second
- ⚠️ Must coordinate - Changes affect each other
- ⚪ None - Independent, any order

---

### Risk Mitigation for Dependencies

#### Risk 1: SDK Update Breaks Client Pooling
**Likelihood:** Low  
**Impact:** Medium

**Mitigation:**
- Client pooling uses `boto3.Session.client()` - unchanged in SDK update
- Converse API uses same `bedrock-runtime` client
- Connection pooling config (max_pool_connections) unchanged
- Test pooling after SDK update

**Validation:**
```python
# After SDK update, verify pooling still works
manager = BedrockClientManager()
client1 = manager.get_client()
client2 = manager.get_client()
assert client1 is client2  # Same cached client
```

---

#### Risk 2: Centralized Invocation Harder to Update for New API
**Likelihood:** Low  
**Impact:** Low

**Mitigation:**
- Centralized code is EASIER to update (one place vs 10+)
- Can support both APIs during transition:

```python
class BedrockInvoker:
    async def invoke(self, use_converse: bool = True):
        if use_converse:
            return await self._invoke_converse()
        else:
            return await self._invoke_model()
```

---

#### Risk 3: Pydantic v2 Changes Break Existing Code
**Likelihood:** Very Low  
**Impact:** Low

**Mitigation:**
- Already using Pydantic v2 (`pydantic>=2.0.0`)
- Just optimizing usage, not upgrading
- V2 is backward compatible with most V1 patterns
- Changes are additive (use new features)

---

### Updated Phase 1 Implementation Plan

**Day 1 Morning (3-4 hours):**
1. Priority 1: Bedrock Client Pooling
   - Update all tools to use `BedrockClientManager`
   - Test connection reuse
   
2. Priority 2: Duplicate Invocation Logic
   - Create `BedrockInvoker` class
   - Migrate one tool as proof of concept
   - Test retry logic

**Day 1 Afternoon (3-4 hours):**
3. Priority 11: Pydantic v2 Verification
   - Audit current usage
   - Apply v2 optimizations
   - Test serialization

4. Priority 12: Bedrock SDK Update
   - Update dependencies
   - Migrate `BedrockInvoker` to Converse API
   - Test all tools (benefit from centralization)

**Day 2 (3-4 hours):**
5. Priority 3: Prompt Template Management
6. Priority 5: JSON Parsing & Validation
7. Priority 6: Code Duplication Reduction

**Total:** 9-10 hours over 2 days

---

## Comprehensive Testing Strategy

### Pre-Implementation Baseline

**Before ANY changes, establish baseline:**

1. **Run full test suite:**
```bash
cd tests/
python3 test_complete_workflow.py
python3 test_full_workflow.py
python3 test_bedrock_integration.py
```

2. **Capture baseline metrics:**
```bash
# Run with timing
time python3 threatforest.py --project /path/to/test-project

# Capture outputs
cp -r output/ baseline_output/
md5sum baseline_output/* > baseline_checksums.txt
```

3. **Document current behavior:**
- Total execution time
- Memory usage (use `time -v` on Linux or Activity Monitor on macOS)
- Number of Bedrock API calls
- Output file checksums
- Log file for comparison

---

### Per-Priority Testing Protocol

**For EACH priority implementation, follow this protocol:**

#### Step 1: Impact Analysis (BEFORE coding)

**Identify all affected files:**
```bash
# Example for Priority 1 (Bedrock Client Pooling)
grep -r "boto3.Session\|bedrock-runtime" src/ --include="*.py"
grep -r "bedrock.*client" src/ --include="*.py"
```

**Create impact checklist:**
- [ ] List all files that import boto3
- [ ] List all files that create Bedrock clients
- [ ] List all files that call affected functions
- [ ] Identify all test files that need updates
- [ ] Check for indirect dependencies (imports of imports)

#### Step 2: Implementation with Validation

**After each file change:**
```bash
# 1. Syntax validation
python3 -m py_compile src/modules/tools/modified_file.py

# 2. Import validation
python3 -c "from src.modules.tools.modified_file import *"

# 3. Check for broken imports in dependent files
grep -r "from.*modified_file import\|import.*modified_file" src/ --include="*.py"
```

#### Step 3: Unit Testing

**Test the specific change:**
```python
# Example: Test client pooling
def test_bedrock_client_pooling():
    from src.modules.core.bedrock_client import BedrockClientManager
    
    manager = BedrockClientManager()
    client1 = manager.get_client(profile_name="default")
    client2 = manager.get_client(profile_name="default")
    
    # Verify same instance (pooling works)
    assert client1 is client2
    assert manager.get_active_connections() == 1
    
    # Verify different profile creates new client
    client3 = manager.get_client(profile_name="other")
    assert client3 is not client1
    assert manager.get_active_connections() == 2
```

#### Step 4: Integration Testing

**Test with real workflow:**
```bash
# Run on small test project
python3 threatforest.py --project tests/fixtures/small-project/

# Verify outputs match baseline
diff -r output/ baseline_output/
md5sum output/* > new_checksums.txt
diff baseline_checksums.txt new_checksums.txt
```

#### Step 5: Regression Testing

**Verify no functionality broken:**
```bash
# Run all existing tests
python3 -m pytest tests/ -v

# Run specific integration tests
python3 tests/test_complete_workflow.py
python3 tests/test_bedrock_integration.py
```

#### Step 6: Performance Validation

**Measure improvement:**
```bash
# Time the workflow
time python3 threatforest.py --project /path/to/test-project

# Compare to baseline
# Should be faster or same (never slower)
```

---

### Priority-Specific Testing

#### Priority 1: Bedrock Client Pooling

**Files to Check:**
```bash
# Find all boto3 usage
grep -r "boto3.Session\|boto3.client" src/ --include="*.py" -l

# Expected files:
# - src/modules/tools/information_extraction_tool.py
# - src/modules/tools/attack_tree_generator_tool.py
# - src/modules/tools/ttc_mapping_tool.py
# - src/modules/tools/setup_tool.py
# - src/wizard.py
```

**Impact Analysis:**
- [ ] All tools creating Bedrock clients
- [ ] Wizard AWS validation
- [ ] Setup tool validation
- [ ] Any cached client references

**Tests:**
```python
def test_client_pooling_reuse():
    """Verify clients are reused"""
    pass

def test_client_pooling_different_profiles():
    """Verify different profiles get different clients"""
    pass

def test_client_pooling_thread_safety():
    """Verify pooling works with async/threading"""
    pass
```

**Validation:**
- [ ] All tools still connect to Bedrock
- [ ] AWS profile selection works
- [ ] Connection count reduced (check logs)
- [ ] No connection errors

---

#### Priority 2: Duplicate Invocation Logic

**Files to Check:**
```bash
# Find all invoke_model calls
grep -r "invoke_model\|bedrock.invoke" src/ --include="*.py" -n

# Expected locations:
# - information_extraction_tool.py: lines 1005, 1467, 1723, 1858
# - attack_tree_generator_tool.py: line 280
# - ttc_mapping_tool.py: lines 237, 431
```

**Impact Analysis:**
- [ ] All Bedrock invocation points
- [ ] Retry logic in each tool
- [ ] Error handling patterns
- [ ] Rate limiting implementations
- [ ] Response parsing logic

**Tests:**
```python
def test_centralized_invocation():
    """Verify centralized invocation works"""
    pass

def test_retry_logic():
    """Verify retry on throttling"""
    pass

def test_error_handling():
    """Verify proper error propagation"""
    pass

def test_rate_limiting():
    """Verify rate limiting between calls"""
    pass
```

**Validation:**
- [ ] All tools still invoke Bedrock successfully
- [ ] Retry logic works consistently
- [ ] Error messages unchanged
- [ ] Rate limiting still effective

---

#### Priority 3: Prompt Template Management

**Files to Check:**
```bash
# Find all hardcoded prompts
grep -r "You are.*expert\|f\"\"\"You are" src/modules/tools/ --include="*.py" -n

# Expected files:
# - information_extraction_tool.py: 5 prompts
# - ttc_mapping_tool.py: 2 prompts
```

**Impact Analysis:**
- [ ] All prompt strings in tools
- [ ] Prompt variable substitution
- [ ] File path resolution
- [ ] Fallback behavior if file missing

**Tests:**
```python
def test_prompt_loading():
    """Verify prompts load from files"""
    pass

def test_prompt_fallback():
    """Verify fallback if file missing"""
    pass

def test_prompt_variable_substitution():
    """Verify variables replaced correctly"""
    pass
```

**Validation:**
- [ ] All prompts load successfully
- [ ] Generated outputs identical to baseline
- [ ] No prompt-related errors
- [ ] File paths resolve correctly

---

#### Priority 11: Pydantic v2 Verification

**Files to Check:**
```bash
# Find all Pydantic usage
grep -r "BaseModel\|\.dict()\|\.parse_obj" src/ --include="*.py" -n

# Expected files:
# - src/modules/core/state.py
# - src/modules/core/progress_events.py
# - src/modules/core/validation.py
```

**Impact Analysis:**
- [ ] All Pydantic models
- [ ] Serialization calls (`.dict()` → `.model_dump()`)
- [ ] Parsing calls (`.parse_obj()` → `.model_validate()`)
- [ ] JSON serialization
- [ ] State management

**Tests:**
```python
def test_model_serialization():
    """Verify model_dump() works"""
    state = ThreatForestState(...)
    data = state.model_dump()
    assert isinstance(data, dict)

def test_model_deserialization():
    """Verify model_validate() works"""
    data = {...}
    state = ThreatForestState.model_validate(data)
    assert state.project_path == data['project_path']

def test_json_serialization():
    """Verify JSON serialization"""
    state = ThreatForestState(...)
    json_str = state.model_dump_json()
    assert isinstance(json_str, str)
```

**Validation:**
- [ ] State serialization works
- [ ] State deserialization works
- [ ] Resume functionality intact
- [ ] No Pydantic deprecation warnings

---

#### Priority 12: Bedrock SDK Update

**Files to Check:**
```bash
# Find all invoke_model usage (will change to converse)
grep -r "invoke_model" src/ --include="*.py" -n

# Find all response parsing
grep -r "response\['body'\]\.read()\|response_body\['content'\]" src/ --include="*.py" -n
```

**Impact Analysis:**
- [ ] All Bedrock API calls
- [ ] Response parsing logic
- [ ] Error handling (error codes may change)
- [ ] Model ID format (ARN handling)
- [ ] Request body structure
- [ ] Response body structure

**Tests:**
```python
def test_converse_api():
    """Verify Converse API works"""
    pass

def test_response_parsing():
    """Verify response parsing with new API"""
    pass

def test_error_handling():
    """Verify error handling with new API"""
    pass

def test_model_id_handling():
    """Verify model ID/ARN handling"""
    pass
```

**Validation:**
- [ ] All Bedrock calls succeed
- [ ] Response parsing works
- [ ] Error messages clear
- [ ] Model selection works
- [ ] Cross-region inference works

---

### Cross-Priority Integration Testing

**After completing multiple priorities, test interactions:**

#### Test 1: Client Pooling + SDK Update
```python
def test_pooling_with_converse_api():
    """Verify pooling works with Converse API"""
    manager = BedrockClientManager()
    client = manager.get_client()
    
    # Use Converse API
    response = client.converse(...)
    assert response is not None
    
    # Verify client reused
    client2 = manager.get_client()
    assert client is client2
```

#### Test 2: Centralized Invocation + SDK Update
```python
def test_centralized_invocation_with_converse():
    """Verify centralized invoker uses Converse API"""
    invoker = BedrockInvoker(client)
    response = await invoker.invoke(...)
    assert 'output' in response
```

#### Test 3: Pydantic v2 + JSON Parsing
```python
def test_pydantic_json_parsing():
    """Verify Pydantic v2 JSON parsing"""
    json_str = '{"id": "T1", "severity": "High"}'
    threat = ThreatStatement.model_validate_json(json_str)
    assert threat.id == "T1"
```

---

### Full Workflow Regression Test

**After ALL changes, run complete end-to-end workflow:**

#### Test Projects

**Test Project 1: Simple Threat Model**
- **Location:** `/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/kiro-threatforest-agentic/examples/hcls-example`
- **Type:** Simple threat model (markdown/JSON format)
- **Purpose:** Validate basic threat parsing and attack tree generation

**Test Project 2: ThreatComposer**
- **Location:** `/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/kiro-threatforest-agentic/examples/genai-chatbot`
- **Type:** ThreatComposer format (.tc.json)
- **Purpose:** Validate ThreatComposer parsing, metadata extraction, structured fields

#### AWS Profile Configuration

**Required Profile:** `dicorteg+zetaworkload-test-Admin`

Verify profile exists:
```bash
aws configure list-profiles | grep "dicorteg+zetaworkload-test-Admin"
```

#### End-to-End Test Script

Create `comprehensive_e2e_test.sh`:

```bash
#!/bin/bash
# comprehensive_e2e_test.sh

set -e

echo "=== ThreatForest End-to-End Regression Test ==="
echo "Started: $(date)"

PROFILE="dicorteg+zetaworkload-test-Admin"
TEST_DIR="test_outputs"
mkdir -p "$TEST_DIR"

# Test 1: Simple Threat Model
echo ""
echo "Test 1: Simple Threat Model (hcls-example)"
PROJECT="/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/kiro-threatforest-agentic/examples/hcls-example"

python3 threatforest.py \
  --project "$PROJECT" \
  --aws-profile "$PROFILE" \
  --bedrock-model "us.anthropic.claude-sonnet-4-20250514-v1:0" \
  2>&1 | tee "$TEST_DIR/hcls_test.log"

if grep -i "error\|exception\|failed" "$TEST_DIR/hcls_test.log" | grep -v "No errors"; then
    echo "❌ FAIL: Errors in hcls-example"
    exit 1
fi
echo "✅ PASS: hcls-example"
cp -r output "$TEST_DIR/hcls_output"

# Test 2: ThreatComposer
echo ""
echo "Test 2: ThreatComposer (genai-chatbot)"
PROJECT="/Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/kiro-threatforest-agentic/examples/genai-chatbot"
rm -rf output

python3 threatforest.py \
  --project "$PROJECT" \
  --aws-profile "$PROFILE" \
  --bedrock-model "us.anthropic.claude-sonnet-4-20250514-v1:0" \
  2>&1 | tee "$TEST_DIR/genai_test.log"

if grep -i "error\|exception\|failed" "$TEST_DIR/genai_test.log" | grep -v "No errors"; then
    echo "❌ FAIL: Errors in genai-chatbot"
    exit 1
fi
echo "✅ PASS: genai-chatbot"
cp -r output "$TEST_DIR/genai_output"

# Syntax Check
echo ""
echo "Syntax Validation"
find src/modules/tools -name "*.py" -exec python3 -m py_compile {} \;
echo "✅ PASS: No syntax errors"

# Log Analysis
echo ""
echo "Log Analysis"
if grep -i "deprecat" "$TEST_DIR"/*.log; then
    echo "⚠️  WARNING: Deprecation warnings"
fi
if grep -i "boto3\|botocore" "$TEST_DIR"/*.log | grep -i "error"; then
    echo "❌ FAIL: Boto3 errors"
    exit 1
fi
echo "✅ PASS: Log analysis complete"

echo ""
echo "All tests passed!"
echo "Completed: $(date)"
```

#### Manual Verification

After running tests, verify:

**For hcls-example:**
- [ ] Attack trees generated
- [ ] Summary report complete
- [ ] JSON export valid
- [ ] No errors in logs

**For genai-chatbot:**
- [ ] ThreatComposer parsed
- [ ] Structured fields extracted
- [ ] Metadata extracted
- [ ] Priority mapped correctly

**Log Review:**
- [ ] No syntax errors
- [ ] No import errors
- [ ] No Pydantic warnings
- [ ] No boto3 errors
- [ ] Bedrock calls successful

#### Running the Test

```bash
chmod +x comprehensive_e2e_test.sh
./comprehensive_e2e_test.sh
```

---

### Rollback Criteria

**Immediately rollback if ANY of these occur:**

1. **Output Differences:**
   - Generated attack trees differ from baseline
   - Summary reports have different content
   - JSON exports have different structure

2. **Functionality Broken:**
   - Workflow fails to complete
   - Any tool throws unexpected errors
   - Resume functionality broken

3. **Performance Regression:**
   - Execution time >5% slower than baseline
   - Memory usage significantly increased
   - More Bedrock API calls than before

4. **Test Failures:**
   - Any existing test fails
   - Integration tests fail
   - Regression tests show differences

---

### Rollback Procedure

```bash
# 1. Revert changes
git revert <commit-hash>

# 2. Verify baseline restored
python3 tests/test_complete_workflow.py

# 3. Document issue
echo "Rollback reason: <description>" >> rollback_log.txt

# 4. Re-run baseline tests
./comprehensive_test.sh
```

---

## Detailed Implementation Order (Day-by-Day)

### Day 1: Foundation & Core Changes

#### Morning Session (9:00 AM - 12:00 PM)

**Priority 1: Bedrock Client Pooling (1.5 hours)**

1. **Impact Analysis (15 min):**
   ```bash
   grep -r "boto3.Session\|boto3.client.*bedrock" src/ --include="*.py" -l > affected_files.txt
   cat affected_files.txt  # Review all affected files
   ```

2. **Implementation (45 min):**
   - Verify `BedrockClientManager` exists and works
   - Update `information_extraction_tool.py` (5 locations)
   - Update `attack_tree_generator_tool.py` (1 location)
   - Update `ttc_mapping_tool.py` (2 locations)
   - Update `setup_tool.py` (3 locations)

3. **Testing (30 min):**
   ```bash
   # Syntax check all modified files
   python3 -m py_compile src/modules/tools/*.py
   
   # Test client pooling
   python3 -c "from src.modules.core.bedrock_client import BedrockClientManager; m = BedrockClientManager(); c1 = m.get_client(); c2 = m.get_client(); assert c1 is c2"
   
   # Run integration test
   python3 tests/test_bedrock_integration.py
   ```

**Priority 2: Centralize Invocation Logic (1.5 hours)**

1. **Impact Analysis (15 min):**
   ```bash
   grep -rn "invoke_model\|bedrock.invoke" src/ --include="*.py" > invocation_points.txt
   wc -l invocation_points.txt  # Count invocation points
   ```

2. **Implementation (60 min):**
   - Create `src/modules/core/bedrock_invoker.py`
   - Migrate `information_extraction_tool.py` first (proof of concept)
   - Test thoroughly before migrating others
   - Migrate remaining tools

3. **Testing (15 min):**
   ```bash
   # Test centralized invoker
   python3 tests/test_bedrock_integration.py
   
   # Verify retry logic
   # (manually trigger throttling or use mock)
   ```

#### Afternoon Session (1:00 PM - 5:00 PM)

**Priority 7: Pydantic v2 Verification (1 hour)**

1. **Impact Analysis (15 min):**
   ```bash
   grep -rn "\.dict()\|\.parse_obj\|\.json()" src/ --include="*.py"
   ```

2. **Implementation (30 min):**
   - Update `state.py`: `.dict()` → `.model_dump()`
   - Update `progress_events.py`: same changes
   - Update `validation.py`: `.parse_obj()` → `.model_validate()`
   - Add computed fields where beneficial

3. **Testing (15 min):**
   ```bash
   # Test state serialization
   python3 -c "from src.modules.core.state import ThreatForestState; s = ThreatForestState(project_path='/test', bedrock_model='test'); print(s.model_dump())"
   
   # Run workflow to test state management
   python3 tests/test_complete_workflow.py
   ```

**Priority 8: Bedrock SDK Update (2 hours)**

1. **Impact Analysis (20 min):**
   ```bash
   # Check current SDK version
   pip show boto3 botocore
   
   # Find all invoke_model calls (should be centralized now)
   grep -rn "invoke_model" src/ --include="*.py"
   ```

2. **Update Dependencies (10 min):**
   ```bash
   # Update pyproject.toml
   # boto3 = "^1.35.0"
   # botocore = "^1.35.0"
   
   poetry update boto3 botocore
   # OR
   pip install --upgrade boto3 botocore
   ```

3. **Implementation (60 min):**
   - Update `BedrockInvoker` to use Converse API
   - Support both APIs during transition (feature flag)
   - Test with one tool first
   - Migrate all tools

4. **Testing (30 min):**
   ```bash
   # Test Converse API
   python3 tests/test_bedrock_integration.py
   
   # Run full workflow
   python3 threatforest.py --project tests/fixtures/small-project/
   
   # Compare outputs
   diff -r output/ baseline_output/
   ```

**End of Day 1: Regression Testing (1 hour)**

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run comprehensive workflow test
./comprehensive_test.sh

# Compare performance
time python3 threatforest.py --project /path/to/test-project
# Should be faster than baseline
```

---

### Day 2: Enhancements & Code Quality

#### Morning Session (9:00 AM - 12:00 PM)

**Priority 3: Prompt Template Management (1.5 hours)**

1. **Impact Analysis (15 min):**
   ```bash
   grep -rn 'f"""You are' src/modules/tools/ --include="*.py"
   ```

2. **Implementation (60 min):**
   - Create 5 new prompt files in `src/prompts/`
   - Add `_load_prompt_template()` to `information_extraction_tool.py`
   - Update `ttc_mapping_tool.py` to use existing `ttc-mapping.md`

3. **Testing (15 min):**
   ```bash
   # Verify prompts load
   python3 -c "from pathlib import Path; p = Path('src/prompts/project-analysis.md'); assert p.exists()"
   
   # Run workflow
   python3 threatforest.py --project tests/fixtures/small-project/
   
   # Outputs should be identical
   diff -r output/ baseline_output/
   ```

**Priority 5: JSON Parsing & Validation (1.5 hours)**

1. **Impact Analysis (15 min):**
   ```bash
   grep -rn "json.loads\|json.dumps" src/ --include="*.py" | wc -l
   ```

2. **Implementation (60 min):**
   - Create `src/modules/utils/json_utils.py`
   - Create Pydantic schemas in `src/modules/schemas/`
   - Update parsing in tools

3. **Testing (15 min):**
   ```bash
   # Test JSON parsing
   python3 tests/test_extraction.py
   
   # Run workflow
   python3 threatforest.py --project tests/fixtures/small-project/
   ```

#### Afternoon Session (1:00 PM - 3:00 PM)

**Priority 6: Code Duplication Reduction (1 hour)**

1. **Impact Analysis (15 min):**
   ```bash
   # Find duplicate patterns
   grep -r "validate.*path\|read.*json\|write.*json" src/ --include="*.py"
   ```

2. **Implementation (30 min):**
   - Create utility modules in `src/modules/utils/`
   - Extract common validation logic
   - Extract common file handling

3. **Testing (15 min):**
   ```bash
   # Run all tests
   python3 -m pytest tests/ -v
   ```

**Final Regression Testing (1 hour)**

```bash
# Run complete test suite
./comprehensive_test.sh

# Performance comparison
echo "Baseline time:" && cat baseline_time.txt
echo "New time:" && time python3 threatforest.py --project /path/to/test-project

# Output validation
diff -r output/ baseline_output/ || echo "Outputs differ - investigate"

# Checksum validation
md5sum output/* > new_checksums.txt
diff baseline_checksums.txt new_checksums.txt || echo "Checksums differ - investigate"
```

---

## Implementation Priority Matrix

| Priority | Improvement | Impact | Effort | ROI |
|----------|------------|--------|--------|-----|
| 1 | Bedrock Client Pooling | High | Low | Very High |
| 2 | Duplicate Invocation Logic | Medium | Medium | High |
| 3 | Prompt Template Management | Low | Low | Medium |
| 4 | Async/Await Optimization | Medium | Medium | High |
| 5 | JSON Parsing & Validation | Low | Low | Medium |
| 6 | Code Duplication | Low | Medium | Low |
| 7 | Pydantic v2 Verification | Low | Low | Medium |
| 8 | Bedrock SDK Update | Medium | Low | High |

---

## Implementation Phases

### Phase 1: Foundation & Core (Day 1)
- Priority 1: Bedrock Client Pooling
- Priority 2: Duplicate Invocation Logic
- Priority 7: Pydantic v2 Verification
- Priority 8: Bedrock SDK Update

**Expected Impact:** 25-30% performance improvement, latest SDK features

### Phase 2: Enhancements (Day 2)
- Priority 3: Prompt Template Management
- Priority 5: JSON Parsing & Validation
- Priority 6: Code Duplication

**Expected Impact:** Better maintainability, cleaner code

### Phase 3: Advanced Optimizations (Future)
- Priority 4: Async/Await Optimization

**Expected Impact:** 20-30% faster execution for multi-threat workflows

### Phase 2: Core Improvements (2-3 days)
- Priority 2: Duplicate Invocation Logic
- Priority 5: JSON Parsing & Validation
- Priority 6: Code Duplication

**Expected Impact:** Better maintainability, cleaner code

### Phase 3: Advanced Optimizations (3-4 days)
- Priority 4: Async/Await Optimization

**Expected Impact:** 20-30% faster execution for multi-threat workflows

### Phase 4: Polish (1-2 days)
- Priority 3: Prompt Template Management
- Documentation updates
- Testing and validation

**Expected Impact:** Better developer experience

---

## Testing Strategy

### Regression Testing
- Run full workflow with existing test projects
- Compare outputs byte-by-byte
- Verify all existing functionality preserved
- Check performance metrics

### Performance Testing
- Measure execution time before/after
- Monitor memory usage
- Track Bedrock API call counts
- Measure connection overhead

### Integration Testing
- Test with various project sizes
- Test error scenarios
- Test resume functionality
- Test with different AWS profiles

---

## Success Metrics

### Performance Metrics
- [ ] 25-30% reduction in total execution time
- [ ] 80% reduction in connection overhead
- [ ] Consistent Bedrock API call patterns

### Code Quality Metrics
- [ ] 500+ lines of code removed (duplication)
- [ ] 100% test coverage maintained
- [ ] Zero breaking changes
- [ ] All outputs identical to current version

### Maintainability Metrics
- [ ] Single source of truth for Bedrock invocation
- [ ] Centralized prompt management
- [ ] Consistent error handling
- [ ] Improved code documentation

---

## Risk Mitigation

### Risks
1. Breaking existing functionality
2. Introducing new bugs
3. Performance regressions
4. Compatibility issues

### Mitigations
1. Comprehensive regression testing
2. Feature flags for new code paths
3. Gradual rollout per phase
4. Maintain backward compatibility
5. Extensive logging during transition

---

## Rollback Plan

Each phase should be:
1. Implemented in feature branch
2. Tested independently
3. Merged with feature flag
4. Monitored in production
5. Rolled back if issues detected

**Rollback triggers:**
- Any output differences
- Performance degradation >5%
- New errors or exceptions
- User-reported issues

---

## Future Considerations

### Post-October 13th Improvements
- Distributed execution support
- Multi-region Bedrock support
- Advanced caching strategies
- Machine learning model optimization
- Real-time progress streaming
- WebSocket-based UI updates
- Bedrock streaming responses
- Multi-model ensemble support

### Technical Debt Addressed
- ✅ Pydantic v2 verification (Priority 11)
- ✅ Latest Bedrock SDK (Priority 12)
- Improve type hints coverage
- Add comprehensive docstrings
- Modernize async patterns
