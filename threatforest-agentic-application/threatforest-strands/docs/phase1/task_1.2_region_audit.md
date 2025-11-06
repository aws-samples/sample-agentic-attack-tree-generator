# Task 1.2: Audit Hardcoded Regions

**Status**: ✅ Complete  
**Date**: October 22, 2025

## Objective

Identify all hardcoded AWS region names in the codebase.

## Analysis Results

### Hardcoded Regions Found (15 locations)

#### Core Modules (3 locations)

**1. src/modules/core/bedrock_client.py:26**
```python
region_name: str = "us-west-2"
```
**Impact**: High - Default region for Bedrock client manager

**2. src/modules/core/bedrock_service.py:14**
```python
region_name: str = "us-west-2"
```
**Impact**: High - Default region for Bedrock service

**3. src/modules/core/bedrock_invoker.py:93,109**
```python
bedrock = BedrockClientManager().get_client(profile_name=aws_profile, region_name='us-east-1')
model_id = f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}"
```
**Impact**: High - Hardcoded in ARN construction

#### Tools (9 locations)

**4. src/modules/tools/setup_tool.py:139,163**
```python
bedrock = BedrockClientManager().get_client(profile_name=profile, region_name='us-east-1')
bedrock = BedrockClientManager().get_client(profile_name=aws_profile, region_name='us-east-1')
```
**Impact**: Medium - Setup tool validation

**5. src/modules/tools/context_analysis_tool.py:456**
```python
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
```
**Impact**: High - Direct boto3 client creation

**6. src/modules/tools/information_extraction_tool.py:128,996,1408,1663,1740**
```python
model_id = f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}"
bedrock = BedrockClientManager().get_client(profile_name=aws_profile, region_name='us-east-1')
bedrock = BedrockClientManager().get_client(region_name='us-east-1')
```
**Impact**: High - Multiple hardcoded references

**7. src/modules/tools/ttc_mapping_tool.py:231,384**
```python
bedrock = BedrockClientManager().get_client(profile_name=aws_profile, region_name='us-east-1')
```
**Impact**: Medium - TTC mapping tool

#### Configuration (1 location)

**8. src/config.py:84**
```python
return self.get('aws.default_region', 'us-east-1')
```
**Impact**: Medium - Fallback default region

## Summary

**Total Hardcoded Regions**: 15 locations  
**Regions Used**: 2 (us-east-1: 13, us-west-2: 2)  
**Files Affected**: 8 files  
**Primary Issue**: us-east-1 hardcoded in 13 locations

## Impact Analysis

### High Impact (9 locations)
- Core Bedrock clients (3)
- Information extraction tool (5)
- Context analysis tool (1)

### Medium Impact (6 locations)
- Setup tool (2)
- TTC mapping tool (2)
- Config fallback (1)
- Bedrock invoker (1)

## Recommendations

1. Create `RegionResolver` utility in `src/modules/core/region_resolver.py`
2. Implement AWS credential chain inspection to extract region
3. Add fallback logic: profile region → env var → config default
4. Update all Bedrock client instantiations to use resolver
5. Remove all hardcoded region parameters

## Next Steps

- Task 1.4: Create centralized configuration with RegionResolver
- Task 1.6: Refactor all region references
