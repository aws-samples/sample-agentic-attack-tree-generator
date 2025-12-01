# Running ThreatForest

This guide explains how to run ThreatForest using the interactive wizard, what happens during analysis, and how to manage your workflow.

## Launching ThreatForest

The interactive wizard is the primary way to run ThreatForest:

```bash
threatforest
```

This launches a guided interface that walks you through the entire analysis process.

## The Interactive Wizard

### Welcome Screen

When you launch ThreatForest for the first time, you'll see:

![ThreatForest Welcome Screen](../assets/images/InitialWelcomeScreenAndLaunchingThreatForest.gif)

The wizard will guide you through the initial setup and then the analysis workflow.

### Step 1: Workflow Selection

Choose your workflow mode:

**Full Analysis** (Recommended)
- Complete end-to-end threat modeling
- Analyzes your project from scratch
- Generates attack trees with MITRE ATT&CK mappings
- Includes mitigation recommendations
- Creates interactive dashboard

This is what most users need and what this guide focuses on.

### Step 2: Project Path

Enter the path to your project directory:

![Project Path Selection](../assets/images/ProjectPathSelection.gif)

**What ThreatForest Looks For:**
- ThreatComposer files (`*.tc.json`)
- Documentation (`README.md`, `ARCHITECTURE.md`)
- Architecture diagrams (PNG, PDF, Mermaid)
- Threat model files (JSON, YAML, Markdown)

### Step 3: AWS Configuration

If using AWS Bedrock, you'll be prompted for AWS details:

![AWS Configuration](../assets/images/AWSConfig.gif)

**What's Happening:**
- ThreatForest uses your AWS profile credentials
- Validates access to AWS Bedrock
- Confirms the selected model is available

### Step 4: Model Selection

Choose your AI model:

![Model Selection](../assets/images/ModelSelection.gif)

### Step 5: Confirmation

Review your settings before starting:

![Analysis Summary](../assets/images/LaunchingWizardStartWorkflow.gif)

## During Analysis

### Progress Tracking

Once analysis begins, you'll see real-time progress:

![Analysis Progress](../assets/images/AnalysisProgress.gif)

**What Each Stage Does:**

1. **Setup & Validation** - Validates configuration and project structure
2. **Context Analysis** - Discovers and categorizes project files
3. **Information Extraction** - Analyzes documentation and diagrams
4. **Attack Tree Generation** - Creates detailed attack trees for each threat
5. **TTP Enrichment** - Maps attack steps to MITRE ATT&CK techniques
6. **Mitigation Mapping** - Adds security controls and recommendations
7. **Report Generation** - Creates dashboard and analysis report

### Individual Threat Progress

For each threat being processed:

```
Processing Threat: T001 - SQL Injection in Login Form
├─ Analyzing threat context...                    ✓
├─ Generating attack paths...                     ✓
│  ├─ Path 1: Direct SQL injection               ✓
│  ├─ Path 2: Blind SQL injection                ✓
│  └─ Path 3: Second-order SQL injection         ✓
├─ Mapping MITRE ATT&CK techniques...            ✓
├─ Adding mitigation recommendations...           ✓
└─ Writing attack tree file...                    ✓

Completed in 45 seconds
```

### Estimated Time Remaining

ThreatForest shows estimated completion time:

```
⏱️ Estimated Time Remaining: 3 minutes

Based on:
- 5 threats to process
- 2 threats completed (avg 40s each)
- 3 threats remaining
```

## When Analysis Completes

### Success Message

![Analysis Complete](../assets/images/AnalysisComplete.gif)

### Next Steps

After completion, you can:

1. **View Dashboard** - Interactive HTML visualization
2. **Read Attack Trees** - Individual markdown files
3. **Export Data** - JSON file for automation
4. **Review Report** - Executive summary

**Learn More:**
- [Understanding Your Results](understanding-results.md) - Explore all outputs
- [How ThreatForest Works](../how-it-works.md) - Technical deep dive

## Handling Errors

### Network Issues

![Network Error](images/error-network.png)
*Screenshot: Network connectivity error and retry options*

### Validation Errors

![Validation Error](images/error-validation.png)
*Screenshot: Project validation error messages*

### Model Errors

![Model Error](images/error-model.png)
*Screenshot: AI model invocation error and recovery options*

## Tips for Successful Analysis

### Before Running

**✅ Do:**
- Ensure AWS credentials are configured
- Have ThreatComposer file or good documentation
- Check network connectivity
- Review prerequisites

**❌ Don't:**
- Run on empty project directories
- Skip AWS profile configuration
- Interrupt during critical stages

### During Analysis

**✅ Do:**
- Let it run to completion
- Monitor progress indicators
- Note any error messages

**❌ Don't:**
- Close terminal/IDE abruptly
- Modify project files during analysis
- Run multiple analyses simultaneously

### After Analysis

**✅ Do:**
- Review the dashboard first
- Check high-severity threats
- Verify attack trees are accurate
- Commit results to version control

**❌ Don't:**
- Delete state files prematurely
- Ignore error messages in logs
- Modify generated files manually

## Performance Expectations

### Analysis Duration

**Typical Times:**
- Small projects (1-3 threats): 5-10 minutes
- Medium projects (4-8 threats): 10-20 minutes
- Large projects (9+ threats): 20-40 minutes

**Factors Affecting Speed:**
- Number of threats
- Complexity of threats
- AI model selected (Haiku faster than Sonnet)
- Network latency to AWS

### First Run vs Subsequent Runs

**First Run:**
- Downloads AI model dependencies (~500MB)
- Initializes MITRE ATT&CK database
- Takes 2-3 minutes longer

**Subsequent Runs:**
- Uses cached dependencies
- Faster startup
- Only analysis time

## Next Steps

- **[Understanding Your Results](understanding-results.md)** - Explore generated outputs
- **[Preparing Your Project](preparing-your-project.md)** - Optimize your inputs
- **[How ThreatForest Works](../how-it-works.md)** - Learn about the internals
