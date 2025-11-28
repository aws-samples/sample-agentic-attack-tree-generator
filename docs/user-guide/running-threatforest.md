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

When you launch ThreatForest, you'll see:

```
╭─────────────────────────────────────────╮
│ ThreatForest - AI-Powered Threat       │
│ Modeling & Attack Tree Generation      │
├─────────────────────────────────────────┤
│ Version: 1.0.0                          │
│ Provider: AWS Bedrock                   │
╰─────────────────────────────────────────╯

What would you like to do?
1. Run Full Analysis
2. View Configuration
3. Exit
```

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

```
📁 Project Directory
Enter the path to your project: /Users/me/my-project

Validating project path...
✓ Project directory found
✓ Scanning for threat models and documentation...
```

**What ThreatForest Looks For:**
- ThreatComposer files (`*.tc.json`)
- Documentation (`README.md`, `ARCHITECTURE.md`)
- Architecture diagrams (PNG, PDF, Mermaid)
- Threat model files (JSON, YAML, Markdown)

### Step 3: AWS Configuration

If using AWS Bedrock, you'll be prompted for AWS details:

```
☁️ AWS Configuration

Select AWS Profile:
1. default
2. work
3. personal
4. Enter custom profile name

Choice: 1

AWS Region: us-east-1

Testing Bedrock access...
✓ Successfully connected to AWS Bedrock
✓ Model access verified
```

**What's Happening:**
- ThreatForest uses your AWS profile credentials
- Validates access to AWS Bedrock
- Confirms the selected model is available

### Step 4: Model Selection

Choose your AI model:

```
🤖 Model Selection

Available Models:
1. Claude 3.5 Sonnet (Recommended) - Balanced quality and speed
2. Claude 3 Haiku - Faster, good for iteration
3. Claude 3 Opus - Highest quality, slower

Choice: 1

✓ Model configured: anthropic.claude-3-sonnet-20240229-v1:0
```

### Step 5: Confirmation

Review your settings before starting:

```
📋 Analysis Summary

Project: /Users/me/my-project
Workflow: Full Analysis
Provider: AWS Bedrock (us-east-1)
Model: Claude 3.5 Sonnet
Threats Found: 5 (3 High, 2 Medium)

Proceed with analysis? (y/n): y
```

## During Analysis

### Progress Tracking

Once analysis begins, you'll see real-time progress:

```
🌳 ThreatForest Analysis

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45% 

Current Stage: Attack Tree Generation
Processing: T001 - SQL Injection in Login Form
Completed: 2 of 5 threats

✓ Setup & Validation (5s)
✓ Context Analysis (15s)
✓ Information Extraction (30s)
⏳ Attack Tree Generation (60s)
⏺ TTP Enrichment
⏺ Mitigation Mapping
⏺ Report Generation
```

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

```
✓ Analysis Complete!

📊 Summary:
- Threats Analyzed: 5
- Attack Trees Generated: 5
- Total Attack Paths: 15
- MITRE Techniques Mapped: 42
- Mitigations Recommended: 28

📁 Output Location:
/Users/me/my-project/threatforest/attack_trees/

Generated Files:
├── attack_trees_dashboard.html  ⭐ Interactive visualization
├── threatforest_data.json       📊 Structured data export
├── threatforest_analysis_report.md
└── attack_tree_*.md (5 files)

🌐 Open interactive dashboard? (y/n): y
```

### Next Steps

After completion, you can:

1. **View Dashboard** - Interactive HTML visualization
2. **Read Attack Trees** - Individual markdown files
3. **Export Data** - JSON file for automation
4. **Review Report** - Executive summary

**Learn More:**
- [Understanding Your Results](understanding-results.md) - Explore all outputs
- [How ThreatForest Works](../how-it-works.md) - Technical deep dive

## State Management

### Automatic Progress Saving

ThreatForest automatically saves progress after each threat:

```
💾 Progress saved: 2 of 5 threats completed
State file: .threatforest_state.json
```

**What's Saved:**
- Completed threats
- Current progress
- Configuration settings
- Timestamp information

### Resuming Interrupted Analysis

If analysis is interrupted, simply run the wizard again:

```bash
threatforest
```

ThreatForest detects existing progress:

```
🔄 Resuming Analysis

Previous session detected:
- Started: 2025-11-28 14:30:00
- Completed: 2 of 5 threats
- Last threat: T002

Resume from where you left off? (y/n): y

Resuming analysis...
Processing threat 3 of 5: T003 - XSS Attack
```

### Starting Fresh

To start a new analysis:

```
Previous analysis detected. What would you like to do?
1. Resume previous analysis
2. Start new analysis (will archive previous results)
3. Cancel

Choice: 2

✓ Previous results archived to: threatforest/archive/20251128-143000/
✓ Starting fresh analysis...
```

## Handling Errors

### Network Issues

```
❌ Error: Connection timeout

Bedrock API connection failed. This could be due to:
- Network connectivity issues
- AWS service outage
- Incorrect region configuration

Retry? (y/n): y
```

### Validation Errors

```
❌ Error: No valid inputs found

ThreatForest requires at least one of:
- ThreatComposer file (*.tc.json)
- README or documentation
- Architecture diagrams

Please add documentation to your project and try again.
```

### Model Errors

```
❌ Error: Model invocation failed

The AI model returned an error. This could be due to:
- Model throttling (too many requests)
- Model not available in region
- Insufficient permissions

Suggestions:
1. Wait a moment and retry
2. Switch to different model
3. Check IAM permissions

What would you like to do?
1. Retry with current model
2. Switch model
3. Cancel
```

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

## Common Questions

??? question "Can I run ThreatForest without the wizard?"

    The wizard is the recommended way to run ThreatForest. Command-line options are not supported in the current version.

??? question "How do I analyze multiple projects?"

    Run the wizard once for each project. ThreatForest will analyze them sequentially.

??? question "Can I cancel during analysis?"

    Yes, press `Ctrl+C` to cancel. Progress is saved automatically, so you can resume later.

??? question "What if I don't have a ThreatComposer file?"

    ThreatForest can work with just documentation and diagrams. It will analyze your architecture and identify potential threats automatically.

??? question "How do I update existing analysis?"

    Run the wizard again on the same project. You can choose to resume or start fresh.

## Next Steps

- **[Understanding Your Results](understanding-results.md)** - Explore generated outputs
- **[Preparing Your Project](preparing-your-project.md)** - Optimize your inputs
- **[How ThreatForest Works](../how-it-works.md)** - Learn about the internals
