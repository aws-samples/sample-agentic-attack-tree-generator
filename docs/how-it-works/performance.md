# Performance Guide

This guide explains ThreatForest's performance characteristics and how to optimize analysis speed and quality.

## Analysis Duration

### Time Breakdown by Project Size

=== "Small Project (1-3 threats)"
    | Phase | Duration | Notes |
    |-------|----------|-------|
    | Setup & Validation | 5-10s | One-time initialization |
    | Context Analysis | 10-20s | File discovery |
    | Information Extraction | 20-40s | Document analysis |
    | Attack Tree Generation | 90-180s | 30-60s per threat |
    | TTP Enrichment | 30-60s | 10-20s per threat |
    | Mitigation Mapping | 15-30s | 5-10s per threat |
    | Report Generation | 10-20s | Dashboard creation |
    
    **Total: 5-10 minutes**

=== "Medium Project (4-8 threats)"
    | Phase | Duration | Notes |
    |-------|----------|-------|
    | Setup & Validation | 5-10s | One-time initialization |
    | Context Analysis | 15-30s | More files to scan |
    | Information Extraction | 30-60s | Larger documentation |
    | Attack Tree Generation | 180-480s | 30-60s per threat |
    | TTP Enrichment | 60-160s | 10-20s per threat |
    | Mitigation Mapping | 30-80s | 5-10s per threat |
    | Report Generation | 15-30s | Larger dashboard |
    
    **Total: 10-20 minutes**

=== "Large Project (9+ threats)"
    | Phase | Duration | Notes |
    |-------|----------|-------|
    | Setup & Validation | 10-15s | One-time initialization |
    | Context Analysis | 20-40s | Many files to scan |
    | Information Extraction | 40-80s | Extensive documentation |
    | Attack Tree Generation | 360-720s | 30-60s per threat |
    | TTP Enrichment | 120-240s | 10-20s per threat |
    | Mitigation Mapping | 60-120s | 5-10s per threat |
    | Report Generation | 20-40s | Complex dashboard |
    
    **Total: 20-40 minutes**

## Factors Affecting Speed

### Threat Complexity

**Number of Attack Paths:**

- Simple threats (1-2 paths): 30-40s per threat
- Moderate threats (3-5 paths): 40-60s per threat
- Complex threats (6+ paths): 60-120s per threat

**Step Detail Level:**

- Basic steps (3-5 per path): Faster processing
- Detailed steps (6-10 per path): Moderate processing
- Comprehensive steps (10+ per path): Slower processing

**Component Interactions:**

- Single component: Faster analysis
- Multiple components: Moderate analysis
- Complex interactions: Slower analysis

### Model Selection

| Model | Speed | Quality | Best For |
|-------|-------|---------|----------|
| Claude 3 Haiku | ⚡⚡⚡ Fast | ⭐⭐ Good | Development, iteration |
| Claude 3.5 Sonnet | ⚡⚡ Balanced | ⭐⭐⭐ Excellent | Production use |
| Claude 3 Opus | ⚡ Slow | ⭐⭐⭐⭐ Best | Critical systems |

**Recommendation:** Use Claude 3.5 Sonnet for balanced speed and quality.

### Network Latency

**AWS Bedrock API Calls:**

- Low latency (<50ms): Minimal impact
- Medium latency (50-200ms): Moderate impact
- High latency (>200ms): Significant impact

**MITRE ATT&CK Database Queries:**

- Local cache: Instant
- First query: 1-2s (downloads data)
- Subsequent queries: <100ms

**Embedding Calculations:**

- First run: 30-60s (model download)
- Cached: <1s per calculation

### Project Size

**Documentation Volume:**

- Small (<10 files): 10-20s analysis
- Medium (10-50 files): 20-40s analysis
- Large (>50 files): 40-80s analysis

**Number of Diagrams:**

- 0-2 diagrams: Minimal impact
- 3-5 diagrams: Moderate impact
- 6+ diagrams: Significant impact

**Architecture Complexity:**

- Simple (1-3 components): Fast
- Moderate (4-10 components): Medium
- Complex (10+ components): Slow

## Optimization Strategies

### Choose the Right Model

!!! tip "Model Selection Strategy"
    **Development Phase:**
    ```yaml
    bedrock:
      model_id: "anthropic.claude-3-haiku-20240307-v1:0"
    ```
    Fast iteration for testing and refinement.
    
    **Production Phase:**
    ```yaml
    bedrock:
      model_id: "anthropic.claude-3-5-sonnet-20240620-v1:0"
    ```
    Balanced speed and quality for real analysis.
    
    **Critical Systems:**
    ```yaml
    bedrock:
      model_id: "anthropic.claude-3-opus-20240229-v1:0"
    ```
    Highest quality for sensitive applications.

### Optimize Input Files

**Reduce Documentation:**

- Focus on security-relevant docs
- Remove redundant files
- Consolidate related documents

**Optimize Diagrams:**

- Use vector formats (SVG, Mermaid) over raster (PNG, JPG)
- Keep diagrams focused and clear
- Avoid overly complex visualizations

**Prioritize Threats:**

- Focus on High-priority threats first
- Use ThreatComposer priority levels
- Skip Low-priority threats for initial analysis

### Use Incremental Analysis

**Process Threats in Batches:**
```bash
# Analyze high-priority threats first
threatforest --priority high

# Then analyze medium-priority threats
threatforest --priority medium --resume
```

**Resume Interrupted Analysis:**
```bash
# ThreatForest automatically detects existing state
threatforest  # Will offer to resume from last checkpoint
```

### Leverage Caching

**First Run Optimization:**

```bash
# Pre-download models and data
threatforest --setup-only

# Then run actual analysis
threatforest
```

**Reuse Embeddings:**

- Embeddings are cached after first calculation
- Subsequent runs use cached embeddings
- Significantly faster TTP enrichment

## Performance Monitoring

### Progress Indicators

ThreatForest provides real-time progress updates:

```
⏱️ Estimated Time Remaining: 3 minutes

Progress: [████████████░░░░░░░░] 60%

Current Phase: Attack Tree Generation (4/7)
Processing: T003 - Authentication Bypass
Completed: 3 threats
Remaining: 2 threats
```

### Performance Metrics

**After Analysis Completion:**
```
📊 Performance Summary

Total Duration: 12 minutes 34 seconds
Threats Analyzed: 5
Average Time per Threat: 2 minutes 30 seconds

Phase Breakdown:
- Setup & Validation: 8s
- Context Analysis: 15s
- Information Extraction: 35s
- Attack Tree Generation: 625s (5 threats × 125s avg)
- TTP Enrichment: 75s
- Mitigation Mapping: 40s
- Report Generation: 18s
```

## Troubleshooting Performance Issues

### Slow Analysis

!!! warning "Analysis Taking Too Long?"
    **Check these factors:**
    
    1. **Model Selection** - Using Claude 3 Opus? Switch to Sonnet
    2. **Network Latency** - High latency to AWS? Check connection
    3. **Project Size** - Too many files? Focus on relevant docs
    4. **Threat Complexity** - Very complex threats? Expected behavior

### First Run Delays

!!! info "First Run Taking 5+ Minutes?"
    **This is normal!** First run downloads:
    
    - sentence-transformers models (~500MB)
    - PyTorch library (~1GB)
    - MITRE ATT&CK data (~50MB)
    
    **Subsequent runs are much faster** (seconds instead of minutes).

### Memory Issues

!!! danger "Out of Memory Errors?"
    **Solutions:**
    
    1. Reduce Batch Size - Process fewer threats at once
    2. Close Other Applications - Free up system memory
    3. Use Smaller Model - Switch to Claude 3 Haiku
    4. Increase System Memory - Upgrade RAM if possible

## Benchmarks

### Real-World Performance

Based on actual ThreatForest usage:

| Project Type | Threats | Files | Duration | Model |
|--------------|---------|-------|----------|-------|
| Web App | 3 | 15 | 8 min | Sonnet |
| Microservices | 7 | 42 | 18 min | Sonnet |
| IoT Platform | 5 | 28 | 12 min | Sonnet |
| Healthcare System | 10 | 65 | 32 min | Opus |
| E-Commerce | 4 | 22 | 10 min | Sonnet |

### Model Comparison

Same project (5 threats, 30 files) with different models:

| Model | Duration | Quality Score | Cost |
|-------|----------|---------------|------|
| Claude 3 Haiku | 7 min | 7.5/10 | $ |
| Claude 3.5 Sonnet | 12 min | 9/10 | $$ |
| Claude 3 Opus | 25 min | 9.5/10 | $$$$ |

**Recommendation:** Claude 3.5 Sonnet offers the best balance.

## Next Steps

<div class="grid cards" markdown>

-   📊 __Workflow Phases__

    ---

    Understand each phase in detail

    [→ Phases](phases.md)

-   🏗️ __Architecture__

    ---

    Learn about system design

    [→ Architecture](../architecture/overview.md)

-   📖 __User Guide__

    ---

    Optimize your workflow

    [→ User Guide](../user-guide/index.md)

</div>
