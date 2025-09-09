# Attack Tree Generation Solution Plan

## Overview
Generate deciduous YAML attack trees from threat composer outputs using a single comprehensive prompt for Amazon Q Developer.

## Input Analysis

### 1. Threat Statements (from sample-app/chatbot-solution-threatstatements.json)
**Format**: JSON with structured threat objects
**Key Fields**:
- `threatSource`: Maps to [threat actor]
- `prerequisites`: Maps to [prerequisites] 
- `threatAction`: Maps to [threat action]
- `threatImpact`: Maps to [threat impact]
- `impactedAssets`: Maps to [impacted asset]
- `impactedGoal`: Maps to [property] (confidentiality, integrity, availability)

**Example Syntax**: "A external threat actor with can issue strategic queries to an LLM API can harvest sufficient responses, which leads to replicating model functionality through distillation, resulting in reduced confidentiality of proprietary LLM algorithms and training data"

### 2. Data Flow Diagram
**Format**: PNG image file (Dataflow Diagram.png)
**Usage**: Context for understanding system architecture and attack paths

### 3. TTC Techniques
**Format**: Static HTML files
**Files**:
- `Techniques - Threat Technique Catalog for AWS (TTC).html` (234KB - detailed techniques)
- `Threat Technique Catalog Matrix - Threat Technique Catalog for AWS (TTC).html` (97KB - matrix view)
- `AWS Services - Threat Technique Catalog for AWS (TTC).html` (92KB - service-specific)

### 4. Deciduous Examples
**Format**: YAML files with consistent structure
**Key Structure Elements**:
- `title`: Descriptive title
- `facts`: Initial conditions/prerequisites
- `attacks`: Attack steps with dependencies
- `mitigations`: Defensive measures (to be excluded from our output)
- `goals`: Final objectives
- `filter`: Path filtering options

## Solution Architecture

### Single Prompt Strategy
**Target Platform**: Amazon Q Developer
**Approach**: Comprehensive prompt that processes all inputs and generates both outputs in one execution

### Prompt Components:

#### 1. Context Setting
- Role definition as security analyst
- Task explanation: Generate attack trees from threat statements
- Output format requirements

#### 2. Input Processing Instructions
- Parse threat composer JSON structure
- Extract threat actor, prerequisites, actions, impacts, and assets
- Reference data flow diagram for system context
- Map to relevant TTC techniques

#### 3. Attack Tree Generation Rules
- **Starting Point**: [threat actor] with [prerequisites] as initial facts
- **Objective**: [threat impact] as goals
- **Structure**: Follow deciduous YAML format
- **Dependencies**: Create logical attack paths using `from:` relationships
- **Exclusions**: No mitigations in attack tree structure

#### 4. TTC Integration Strategy
- Match threat actions to relevant TTC techniques
- Use TTC technique names as attack step identifiers
- Incorporate TTC context for realistic attack paths

#### 5. Mitigation Generation Rules
- Generate separate CSV output
- One mitigation per attack step minimum
- Categories: Detective, Preventative
- Based on security best practices
- Reference TTC recommendations where applicable

## Expected Outputs

### 1. Deciduous YAML Attack Tree
**Filename**: `{threat-id}-attack-tree.yaml`
**Structure**:
```yaml
title: Attack Tree for [Threat Description]

facts:
- [threat_actor_with_prerequisites]: [Description]
  from:
  - reality: Initial condition

attacks:
- [attack_step_1]: [TTC Technique or Action]
  from:
  - [prerequisite_step]
- [attack_step_2]: [Next technique]
  from:
  - [attack_step_1]

goals:
- [threat_impact_objective]: [Final impact description]
  from:
  - [final_attack_step]

filter:
- [threat_impact_objective]
```

### 2. Mitigations CSV
**Filename**: `{threat-id}-mitigations.csv`
**Structure**:
```csv
Attack Step,Mitigation,Type,Description,TTC Reference
[attack_step_1],[mitigation_name],Preventative,[detailed_description],[ttc_id]
[attack_step_2],[mitigation_name],Detective,[detailed_description],[ttc_id]
```

## Implementation Steps

### Phase 1: Prompt Development
1. Create comprehensive prompt template
2. Include all input processing logic
3. Define output formatting requirements
4. Add TTC technique mapping instructions

### Phase 2: Testing & Refinement
1. Test with sample threat statements
2. Validate deciduous YAML structure
3. Verify mitigation CSV generation
4. Refine prompt based on output quality

### Phase 3: Documentation
1. Create final MD file with prompt
2. Include usage instructions
3. Document input requirements
4. Provide example outputs

## Technical Considerations

### Prompt Engineering Best Practices
- Clear role definition and context
- Structured input processing instructions
- Explicit output format requirements
- Error handling for malformed inputs
- Consistent naming conventions

### Amazon Q Developer Optimization
- Single comprehensive prompt approach
- Clear section delineation
- Explicit output file naming
- JSON and YAML format handling
- CSV generation capabilities

### Quality Assurance
- Validate YAML syntax
- Ensure logical attack flow
- Verify mitigation relevance
- Check TTC technique accuracy
- Confirm deciduous format compliance

## Success Criteria
1. ✅ Single prompt generates both required outputs
2. ✅ Attack trees follow deciduous YAML structure
3. ✅ Starting point uses threat actor + prerequisites
4. ✅ Goals reflect threat impact objectives
5. ✅ No mitigations included in attack tree
6. ✅ Separate CSV with comprehensive mitigations
7. ✅ TTC techniques properly integrated
8. ✅ Outputs are syntactically valid

## Next Steps
1. Develop the comprehensive prompt based on this plan
2. Create the final MD file for execution
3. Test with sample inputs
4. Iterate and refine based on results
