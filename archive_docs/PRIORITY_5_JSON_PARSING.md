# Priority 5: JSON Parsing and Validation

**Date:** October 13, 2025  
**Priority:** 5 (Low Impact, Low Effort)  
**Estimated Time:** 2 hours  
**Status:** 📋 Ready to Implement

---

## Executive Summary

Centralize JSON parsing logic and add Pydantic schema validation to improve type safety, error handling, and code maintainability. Currently, JSON parsing is scattered across tools with duplicate error handling and no schema validation.

**Key Benefits:**
- Type-safe JSON handling with Pydantic schemas
- Better error messages for debugging
- Consistent validation across all tools
- Reduced duplicate code (~50 lines)
- Easier to maintain and extend

---

## Why We Should Do This

### Current Problems

#### 1. Duplicate JSON Parsing Logic
**Location:** Scattered across 3 tools  
**Occurrences:** 15 `json.loads()`, 6 `json.dumps()`, 5 `JSONDecodeError` handlers

**Example from `information_extraction_tool.py` (lines 1301-1338):**
```python
def _parse_json_response(self, content: str) -> Dict[str, Any]:
    """Parse JSON response with markdown code block handling"""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Remove markdown code block markers
        cleaned_content = content.strip()
        if cleaned_content.startswith('```'):
            lines = cleaned_content.split('\n')
            lines = lines[1:]  # Remove first line
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]  # Remove last line
            cleaned_content = '\n'.join(lines).strip()
        
        try:
            return json.loads(cleaned_content)
        except json.JSONDecodeError:
            # Find JSON structure manually
            json_start = cleaned_content.find('{')
            if json_start == -1:
                raise ValueError("No JSON structure found")
            
            # Find matching closing brace (15 more lines...)
            brace_count = 0
            json_end = json_start
            for i, char in enumerate(cleaned_content[json_start:], json_start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
            
            json_str = cleaned_content[json_start:json_end]
            return json.loads(json_str)
```

**Problem:** This 38-line parsing logic is duplicated in multiple places with slight variations.

#### 2. No Schema Validation
**Current State:** JSON is parsed as `Dict[str, Any]` with no type checking

**Example:**
```python
# Current: No validation
project_info = json.loads(content)
# What if 'application_name' is missing? Runtime error later!
app_name = project_info['application_name']  # KeyError possible

# Current: No type checking
threat_data = json.loads(response)
# What if 'priority' is "high" instead of "High"? Silent bug!
priority = threat_data['priority']
```

**Problem:** Errors discovered at runtime, not at parse time. Hard to debug.

#### 3. Inconsistent Error Handling
**Variations found:**
- Some tools catch `JSONDecodeError` and retry
- Some tools catch and return error dict
- Some tools catch and raise ValueError
- Some tools don't catch at all

**Example from `context_analysis_tool.py`:**
```python
try:
    extracted = json.loads(json_data)
except:  # Bare except - catches everything!
    pass
```

**Problem:** Inconsistent behavior makes debugging difficult.

#### 4. Poor Error Messages
**Current:**
```
JSONDecodeError: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
```

**Problem:** Doesn't tell you WHAT was expected or WHERE in the workflow it failed.

---

## What This Will Improve

### 1. Type Safety with Pydantic Schemas

**Before (no validation):**
```python
threat_data = json.loads(response)
# Hope it has the right fields!
threat_id = threat_data['id']  # KeyError if missing
priority = threat_data['priority']  # Could be any value
```

**After (with Pydantic):**
```python
threat = ThreatStatement.model_validate_json(response)
# Guaranteed to have all required fields
threat_id = threat.id  # Type: str
priority = threat.priority  # Type: Literal["High", "Medium", "Low"]
```

**Benefits:**
- ✅ Compile-time type checking (IDE autocomplete)
- ✅ Runtime validation (catches bad data immediately)
- ✅ Clear error messages (tells you exactly what's wrong)
- ✅ Self-documenting code (schema shows expected structure)

### 2. Centralized Parsing Logic

**Before (38 lines per tool):**
```python
# information_extraction_tool.py: 38 lines
def _parse_json_response(self, content: str) -> Dict[str, Any]:
    # Duplicate markdown handling
    # Duplicate brace matching
    # Duplicate error handling

# attack_tree_generator_tool.py: Similar 30 lines
def _extract_json(self, content: str) -> Dict:
    # Same logic, slightly different

# ttc_mapping_tool.py: Similar 25 lines
def _parse_response(self, text: str) -> Dict:
    # Same logic again
```

**After (1 utility class):**
```python
# All tools use:
from modules.utils.json_utils import JSONParser

data = JSONParser.extract_from_bedrock_response(response)
threat = JSONParser.parse_with_schema(data, ThreatStatement)
```

**Benefits:**
- ✅ ~50 lines of duplicate code removed
- ✅ Single place to fix bugs
- ✅ Consistent behavior across all tools
- ✅ Easier to add new parsing features

### 3. Better Error Messages

**Before:**
```
JSONDecodeError: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
```

**After:**
```
ValidationError: ThreatStatement validation failed
  - Field 'priority': Value 'high' not in allowed values ['High', 'Medium', 'Low']
  - Field 'id': Field required but missing
  - Context: Parsing threat from Bedrock response in information_extraction_tool
  - Raw content (first 200 chars): {"threat_statement": "...", "priority": "high"}
```

**Benefits:**
- ✅ Tells you WHAT field is wrong
- ✅ Tells you WHY it's wrong
- ✅ Tells you WHERE it happened
- ✅ Shows you the actual data

### 4. Easier Debugging

**Before:**
```python
# Debugging requires adding print statements
threat_data = json.loads(response)
print(f"DEBUG: {threat_data}")  # Manual debugging
```

**After:**
```python
# Pydantic automatically logs validation errors
threat = ThreatStatement.model_validate_json(response)
# If validation fails, you get full details automatically
```

**Benefits:**
- ✅ Automatic validation logging
- ✅ Clear error context
- ✅ No manual debugging needed

---

## Main Changes Required

### 1. Create JSON Utility Module

**New File:** `src/modules/utils/json_utils.py` (~80 lines)

```python
"""Centralized JSON parsing utilities with Pydantic validation"""
from typing import TypeVar, Type, Optional, Dict, Any
from pydantic import BaseModel, ValidationError
import json
import re

T = TypeVar('T', bound=BaseModel)

class JSONParser:
    """Centralized JSON parsing with validation"""
    
    @staticmethod
    def extract_from_bedrock_response(response: Dict[str, Any]) -> str:
        """Extract JSON text from Bedrock response"""
        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
    
    @staticmethod
    def parse_with_schema(json_str: str, schema: Type[T]) -> T:
        """Parse and validate JSON against Pydantic schema"""
        # Remove markdown code blocks
        cleaned = JSONParser._clean_markdown(json_str)
        
        try:
            return schema.model_validate_json(cleaned)
        except ValidationError as e:
            raise ValueError(f"{schema.__name__} validation failed: {e}")
    
    @staticmethod
    def safe_parse(json_str: str, default: Optional[Dict] = None) -> Dict:
        """Parse JSON with fallback to default"""
        try:
            cleaned = JSONParser._clean_markdown(json_str)
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return default or {}
    
    @staticmethod
    def _clean_markdown(content: str) -> str:
        """Remove markdown code blocks and extract JSON"""
        content = content.strip()
        
        # Remove ```json or ``` markers
        if content.startswith('```'):
            lines = content.split('\n')
            lines = lines[1:]  # Remove first line
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]  # Remove last line
            content = '\n'.join(lines).strip()
        
        # Extract JSON structure if embedded in text
        if not content.startswith('{'):
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                content = json_match.group(0)
        
        return content
```

**Effort:** 1 hour

### 2. Create Pydantic Schemas

**New File:** `src/modules/schemas/threat_schema.py` (~100 lines)

```python
"""Pydantic schemas for threat model data structures"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field

class ThreatStatement(BaseModel):
    """Schema for a threat statement"""
    id: str = Field(..., description="Threat ID (e.g., T001)")
    statement: str = Field(..., description="Full threat statement")
    category: str = Field(..., description="Threat category")
    priority: Literal["High", "Medium", "Low"] = Field(..., description="Threat priority")
    
    # Optional structured fields
    threatSource: Optional[str] = Field(None, description="Threat source")
    prerequisites: Optional[str] = Field(None, description="Prerequisites")
    threatAction: Optional[str] = Field(None, description="Threat action")
    threatImpact: Optional[str] = Field(None, description="Threat impact")
    impactedGoal: Optional[str] = Field(None, description="Impacted security goal")
    impactedAssets: Optional[str] = Field(None, description="Impacted assets")
    
    class Config:
        extra = "allow"  # Allow additional fields from LLM

class ProjectInfo(BaseModel):
    """Schema for project information"""
    application_name: str = Field(..., description="Application name")
    sector: Optional[str] = Field(None, description="Industry sector")
    architecture_type: Optional[str] = Field(None, description="Architecture pattern")
    deployment_environment: Optional[str] = Field(None, description="Deployment type")
    technologies: List[str] = Field(default_factory=list, description="Technologies used")
    
    class Config:
        extra = "allow"

class AttackTree(BaseModel):
    """Schema for attack tree"""
    threat_id: str = Field(..., description="Associated threat ID")
    threat_statement: str = Field(..., description="Threat statement")
    mermaid_code: str = Field(..., description="Mermaid diagram code")
    
    class Config:
        extra = "allow"
```

**Effort:** 30 minutes

### 3. Update Tools to Use New Utilities

**Files to Update:**
1. `information_extraction_tool.py` - Replace `_parse_json_response()` method
2. `attack_tree_generator_tool.py` - Replace JSON parsing
3. `ttc_mapping_tool.py` - Replace JSON parsing
4. `context_analysis_tool.py` - Replace JSON parsing

**Example Update (information_extraction_tool.py):**

**Before (38 lines):**
```python
def _parse_json_response(self, content: str) -> Dict[str, Any]:
    """Parse JSON response with markdown code block handling"""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # 35 more lines of duplicate logic...
```

**After (3 lines):**
```python
from modules.utils.json_utils import JSONParser
from modules.schemas.threat_schema import ProjectInfo

project_info = JSONParser.parse_with_schema(content, ProjectInfo)
```

**Effort:** 30 minutes (all 4 tools)

---

## Downstream Impacts

### ✅ Positive Impacts

#### 1. Better Error Detection
**Impact:** Catch data issues earlier in the workflow

**Example:**
```python
# Before: Error discovered when generating attack tree (later)
threat_data = json.loads(response)  # No validation
# ... 100 lines later ...
priority = threat_data['priority']  # KeyError!

# After: Error discovered immediately at parse time
threat = ThreatStatement.model_validate_json(response)
# ValidationError raised immediately if 'priority' missing
```

**Benefit:** Faster debugging, clearer error messages

#### 2. IDE Support
**Impact:** Better developer experience with autocomplete

**Example:**
```python
# Before: No autocomplete, no type hints
threat_data = json.loads(response)
threat_data['']  # IDE shows nothing

# After: Full autocomplete and type checking
threat = ThreatStatement.model_validate_json(response)
threat.  # IDE shows: id, statement, category, priority, etc.
```

**Benefit:** Fewer typos, faster development

#### 3. Self-Documenting Code
**Impact:** Schemas serve as documentation

**Example:**
```python
# Before: What fields does project_info have?
project_info = json.loads(content)  # Unknown structure

# After: Check the schema to see all fields
class ProjectInfo(BaseModel):
    application_name: str  # Required
    sector: Optional[str]  # Optional
    technologies: List[str]  # List of strings
```

**Benefit:** Easier onboarding, clearer expectations

#### 4. Consistent Validation
**Impact:** All tools validate the same way

**Before:**
- Tool A: Allows "high" or "High" for priority
- Tool B: Only allows "High"
- Tool C: Doesn't validate at all

**After:**
- All tools: Only allow "High", "Medium", "Low" (enforced by schema)

**Benefit:** Consistent behavior, fewer bugs

### ⚠️ Potential Risks (Mitigated)

#### Risk 1: Stricter Validation May Reject Valid Data
**Scenario:** LLM returns slightly different format than expected

**Mitigation:**
```python
class ThreatStatement(BaseModel):
    # ... required fields ...
    
    class Config:
        extra = "allow"  # Allow additional fields from LLM
```

**Result:** Schema accepts extra fields, only validates required ones

#### Risk 2: Performance Overhead from Validation
**Scenario:** Pydantic validation adds processing time

**Analysis:**
- Pydantic v2 is highly optimized (Rust core)
- Validation adds ~1-2ms per object
- Current workflow: 30-40 threats = 30-80ms total
- Total workflow time: 80-95 seconds
- Overhead: <0.1% of total time

**Result:** Negligible performance impact

#### Risk 3: Breaking Changes to Existing Code
**Scenario:** Changing from Dict to Pydantic models breaks code

**Mitigation:**
```python
# Pydantic models can be used as dicts
threat = ThreatStatement.model_validate_json(response)
threat_dict = threat.model_dump()  # Convert back to dict if needed

# Or access fields directly
threat.id  # Works
threat['id']  # Also works (Pydantic supports both)
```

**Result:** Backward compatible, no breaking changes

---

## Implementation Plan

### Phase 1: Create Utilities (1 hour)

**Step 1.1: Create JSONParser utility (30 min)**
- Create `src/modules/utils/json_utils.py`
- Implement `extract_from_bedrock_response()`
- Implement `parse_with_schema()`
- Implement `safe_parse()`
- Implement `_clean_markdown()` helper

**Step 1.2: Create Pydantic schemas (30 min)**
- Create `src/modules/schemas/threat_schema.py`
- Define `ThreatStatement` schema
- Define `ProjectInfo` schema
- Define `AttackTree` schema
- Add validation rules and field descriptions

### Phase 2: Update Tools (30 min)

**Step 2.1: Update information_extraction_tool.py (15 min)**
- Import `JSONParser` and schemas
- Replace `_parse_json_response()` with `JSONParser.parse_with_schema()`
- Update `_extract_project_info()` to use `ProjectInfo` schema
- Update threat parsing to use `ThreatStatement` schema

**Step 2.2: Update other tools (15 min)**
- Update `attack_tree_generator_tool.py` - Use `AttackTree` schema
- Update `ttc_mapping_tool.py` - Use `JSONParser.safe_parse()`
- Update `context_analysis_tool.py` - Use `JSONParser.safe_parse()`

### Phase 3: Testing (30 min)

**Step 3.1: Unit tests (15 min)**
```python
def test_json_parser_with_markdown():
    content = "```json\n{\"id\": \"T001\"}\n```"
    result = JSONParser.safe_parse(content)
    assert result['id'] == 'T001'

def test_threat_schema_validation():
    data = {"id": "T001", "statement": "...", "category": "...", "priority": "High"}
    threat = ThreatStatement.model_validate(data)
    assert threat.priority == "High"

def test_threat_schema_rejects_invalid():
    data = {"id": "T001", "priority": "invalid"}  # Missing required fields
    with pytest.raises(ValidationError):
        ThreatStatement.model_validate(data)
```

**Step 3.2: Integration test (15 min)**
```bash
# Run E2E test
cd tests/
python3 run_e2e_test.py

# Verify outputs unchanged
diff -r output/ baseline_output/
```

---

## Success Metrics

### Code Quality
- [ ] ~50 lines of duplicate JSON parsing removed
- [ ] 100% type coverage for JSON data structures
- [ ] All JSON parsing uses centralized utilities
- [ ] All Bedrock responses validated with schemas

### Error Handling
- [ ] Clear validation error messages
- [ ] Errors caught at parse time (not runtime)
- [ ] Consistent error handling across all tools

### Testing
- [ ] All E2E tests passing
- [ ] No functionality regression
- [ ] Same outputs as before
- [ ] Performance overhead <0.1%

---

## Testing Strategy

### Pre-Implementation Baseline
```bash
# Capture baseline
cd tests/
python3 run_e2e_test.py > baseline_output.txt
cp -r test_outputs/hcls-example baseline_outputs/
```

### Post-Implementation Validation
```bash
# Run E2E test
python3 run_e2e_test.py > new_output.txt

# Compare outputs
diff baseline_output.txt new_output.txt
diff -r baseline_outputs/ test_outputs/hcls-example/

# Verify JSON structure unchanged
python3 -c "
import json
baseline = json.load(open('baseline_outputs/threat_model.json'))
new = json.load(open('test_outputs/hcls-example/threat_model.json'))
assert len(baseline['threat_statements']) == len(new['threat_statements'])
print('✅ Output structure unchanged')
"
```

### Error Handling Tests
```python
# Test invalid priority
def test_invalid_priority():
    data = {"id": "T001", "statement": "...", "category": "...", "priority": "critical"}
    with pytest.raises(ValidationError) as exc:
        ThreatStatement.model_validate(data)
    assert "priority" in str(exc.value)
    assert "High" in str(exc.value)  # Shows valid options

# Test missing required field
def test_missing_field():
    data = {"id": "T001"}  # Missing statement, category, priority
    with pytest.raises(ValidationError) as exc:
        ThreatStatement.model_validate(data)
    assert "statement" in str(exc.value)
    assert "required" in str(exc.value).lower()
```

---

## Rollback Plan

**Rollback Triggers:**
- Any E2E test fails
- Output structure changes
- Performance degradation >1%
- Validation errors on valid data

**Rollback Procedure:**
```bash
# Revert changes
git revert <commit-hash>

# Verify baseline restored
python3 tests/run_e2e_test.py
diff -r output/ baseline_output/  # Should be identical
```

---

## Dependencies

### Prerequisites
- ✅ Pydantic v2 already installed (`pydantic>=2.0.0`)
- ✅ Existing validation patterns in `src/modules/core/validation.py`
- ✅ JSON parsing already used throughout codebase

### No Blocking Dependencies
- Can be implemented independently
- Does not depend on other priorities
- Does not block other priorities

---

## Conclusion

**Recommendation:** IMPLEMENT

**Rationale:**
- Low effort (2 hours)
- High value (type safety, better errors, less duplicate code)
- Low risk (backward compatible, easy to rollback)
- Improves developer experience significantly
- Makes codebase more maintainable

**Next Steps:**
1. Review and approve this document
2. Create feature branch: `feature/priority-5-json-parsing`
3. Implement Phase 1 (utilities and schemas)
4. Implement Phase 2 (update tools)
5. Run Phase 3 (testing)
6. Merge to main if all tests pass

**Estimated Total Time:** 2 hours  
**Expected Completion:** Same day implementation
