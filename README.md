# 🌳 ThreatForest

<div align="center">

**AI-Driven Threat Modeling & Attack Tree Generation with MITRE ATT&CK Integration**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[Features](#-features) • [Quick Start](#-quick-start) • [How It Works](#-how-it-works) • [Documentation](#-documentation) • [IDE Integration](#-ide-integration) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

ThreatForest is an intelligent threat modeling platform built on the [Strands](https://github.com/awslabs/strands) agentic framework that combines AI-powered analysis with MITRE ATT&CK framework integration. It orchestrates multiple AI agents to automatically generate comprehensive attack trees from your project documentation, threat models, and architecture diagrams, transforming them into actionable security insights with detailed attack paths and mitigation strategies.

### Why ThreatForest?

- 🔄 **Strands-Powered Architecture** - Built on AWS Labs' agentic framework for reliable, orchestrated AI workflows with state management and error recovery
- 🤖 **Multi-Agent Orchestration** - Coordinates specialized AI agents for context analysis, threat extraction, attack tree generation, and mitigation mapping
- 🌳 **Attack Tree Generation** - Automatically creates detailed attack trees for identified threats with step-by-step attack paths
- 🎯 **MITRE ATT&CK Integration** - Maps attack paths to TTPs (Tactics, Techniques, and Procedures)
- 🛡️ **Mitigation Recommendations** - Provides actionable security controls and countermeasures
- 📊 **Interactive Dashboards** - Visualize threats with interactive HTML dashboards using vis-network
- 🔄 **Multi-Provider Support** - Works with AWS Bedrock, Anthropic, OpenAI, Gemini, Ollama, and more
- 🔌 **Kiro IDE Integration** - Edit ThreatComposer files and get instant attack tree generation

## ✨ Features

### Core Capabilities

- **🤖 AI-Powered Analysis** - Leverages LLMs to analyze your application and generate threat models
- **🔍 Intelligent Context Analysis** - Discovers and analyzes threat models, diagrams, and documentation using Strands `file_read` tool
- **🔄 Flexible Workflows** - Run full analysis or individual stages (generation, enrichment, mitigation) independently
- **🌳 Attack Tree Generation** - Creates detailed attack trees with multiple paths and prerequisites
- **🎯 MITRE ATT&CK Integration** - Maps attack steps to techniques using semantic similarity matching
- **🛡️ Mitigation Recommendations** - Provides actionable security controls for each identified threat
- **📊 Interactive Dashboard** - Visual network graphs with dynamic filtering and search capabilities
- **💾 State Management** - Resume interrupted workflows from checkpoints with Strands-based state persistence
- **🔒 No Data Storage** - Application details are processed locally and not stored by ThreatForest

### Supported Input Formats

- 📋 **Threat Models**: ThreatComposer (.tc), JSON, YAML, Markdown
- 🏗️ **Diagrams**: PNG, JPG, PDF, Mermaid (.mmd), Draw.io, PlantUML
- 📖 **Documentation**: Markdown, PDF, Text files

### Flexible Workflows

1. **🌳 Full Analysis** - Complete threat modeling pipeline from discovery to mitigation
2. **🎯 TTP Enrichment** - Add MITRE ATT&CK mappings to existing attack trees
3. **🛡️ Mitigation Mapping** - Add security controls to enriched trees

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- AWS Account with Bedrock access (or API keys for other providers)
- Git

### Installation

For a permanent `threatforest` command you can run from anywhere:

#### Using pipx (Recommended)

```bash
# Install pipx if you don't have it
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Install ThreatForest
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest
pipx install .

# Now run from anywhere!
threatforest
```

#### Using uv tool (Modern & Fast)

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ThreatForest globally
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest
uv tool install .

# Now run from anywhere!
threatforest
```

#### Using pip (Traditional)

```bash
# Clone and install
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest
pip install .

# Run the CLI
threatforest
```

#### For Development

Contributors working on ThreatForest code:

```bash
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# Editable install - code changes reflect immediately!
pip install -e ".[dev]"

# Now you can:
# 1. Edit code
# 2. Run threatforest
# 3. See changes instantly (no reinstall needed!)
threatforest
```

**Alternative: Using uv (Modern)**
```bash
# No install needed - always uses latest code
uv run threatforest

# Make changes and run again
uv run threatforest  # Automatically uses your edits
```

### Configuration

1. **Copy the environment template:**
   ```bash
   cp .env.example .env
   ```

2. **Configure your provider in `.env`:**
   ```bash
   # For AWS Bedrock
   AWS_PROFILE=your-profile
   AWS_REGION=us-east-1
   
   # Or for Anthropic
   ANTHROPIC_API_KEY=your-key-here
   ```

3. **Select provider in `config.yaml`:**
   ```yaml
   # AWS Bedrock (default)
   bedrock:
     enabled: true
     model_id: "anthropic.claude-3-sonnet-20240229-v1:0"
     region: "us-east-1"
   
   # Or Anthropic Direct
   # anthropic:
   #   enabled: true
   #   model_id: "claude-3-sonnet-20240229"
   ```

### Running ThreatForest

After installation, simply run:

```bash
threatforest
```

The interactive wizard will guide you through:
1. **Mode Selection** - Choose workflow option (Full/Enrich/Mitigate)
2. **Configuration** - AWS profile, model selection, project path
3. **Analysis** - Run selected workflow with progress tracking
4. **Results** - View summary and access output files

> **Note:** First run will be slower as it downloads AI model dependencies (sentence-transformers, torch). Subsequent runs are much faster.

## 🔍 How It Works

ThreatForest uses a multi-stage workflow powered by the Strands agentic framework to transform your application context into comprehensive security analysis:

```mermaid
graph TB
    Start([Start Workflow]) --> Setup[Setup & Validation]
    Setup --> Context[Context Analysis]
    Context --> Extract[Information Extraction]
    Extract --> Generate[Attack Tree Generation]
    Generate --> Enrich[TTP Enrichment]
    Enrich --> Mitigate[Mitigation Mapping]
    Mitigate --> Summary[Generate Reports]
    Summary --> End([Complete])
    
    Context -.->|Discovers| Files[Project Files<br/>• Threat Models<br/>• Documentation<br/>• Diagrams<br/>• Architecture]
    
    Extract -.->|Uses LLM| AI1[AI Analysis<br/>• Extract threats<br/>• Identify assets<br/>• Understand context]
    
    Generate -.->|Uses LLM| AI2[AI Generation<br/>• Create attack trees<br/>• Define attack paths<br/>• Assess impact]
    
    Enrich -.->|Maps to| MITRE[MITRE ATT&CK<br/>• Technique IDs<br/>• Tactics<br/>• Procedures]
    
    Mitigate -.->|Adds| Controls[Security Controls<br/>• Preventive measures<br/>• Detective controls<br/>• Response actions]
    
    Summary -.->|Creates| Output[Output Files<br/>• Attack tree markdown<br/>• Interactive dashboard<br/>• JSON export<br/>• Analysis report]
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style AI1 fill:#fff4e1
    style AI2 fill:#fff4e1
    style MITRE fill:#e1f0ff
    style Controls fill:#ffe1f0
    style Output fill:#f0e1ff
```

### Workflow Stages

1. **Setup & Validation** (5%)
   - Validates AWS credentials and Bedrock access
   - Checks project structure and permissions
   - Initializes logging and state management

2. **Context Analysis** (10-20%)
   - Discovers threat models (ThreatComposer, JSON, YAML)
   - Identifies documentation files (README, architecture docs)
   - Locates architecture diagrams (PNG, PDF, Mermaid, DrawIO)
   - Uses Strands `file_read` tool for intelligent document processing
   - Categorizes files by relevance and type

3. **Information Extraction** (20-40%)
   - Uses LLM to analyze project context
   - Extracts application details (name, technologies, architecture)
   - Identifies or generates threat statements
   - Prioritizes threats by severity (High/Medium/Low)
   - Extracts assets, data flows, and trust boundaries

4. **Attack Tree Generation** (40-70%)
   - Generates detailed attack trees for high-priority threats
   - Creates step-by-step attack paths with prerequisites
   - Assesses impact and likelihood for each path
   - Produces markdown files and Mermaid diagrams
   - Tracks progress with state management for resume capability

5. **TTP Enrichment** (70-85%)
   - Maps attack steps to MITRE ATT&CK techniques
   - Uses semantic similarity matching with embeddings
   - Adds technique IDs, tactics, and descriptions
   - Enriches attack trees with industry-standard intelligence

6. **Mitigation Mapping** (85-95%)
   - Identifies security controls for each technique
   - Provides preventive, detective, and responsive measures
   - Adds implementation guidance and best practices
   - Creates comprehensive mitigation strategies

7. **Report Generation** (95-100%)
   - Generates interactive HTML dashboard
   - Creates JSON export for programmatic access
   - Produces markdown analysis report
   - Compiles summary statistics and metrics

## 📚 Documentation

### Workflow Modes

#### 🌳 Full Analysis
Analyzes your entire project and generates complete attack trees:

**Input:**
- Project directory with documentation
- Optional threat model file
- Architecture diagrams

**Process:**
1. Analyzes project context
2. Extracts or generates threats
3. Creates attack trees for high-priority threats
4. Maps to MITRE ATT&CK techniques
5. Adds mitigation recommendations

**Output:** `<project>/threatforest/attack_trees/`

#### 🎯 TTP Enrichment  
Enriches existing attack trees with MITRE ATT&CK techniques:

**Input:** Attack trees from Full Analysis

**Process:**
1. Reads attack tree markdown files
2. Extracts attack steps
3. Maps to MITRE ATT&CK techniques using semantic similarity
4. Enriches trees with technique IDs and descriptions

**Input:** `<project>/threatforest/attack_trees/`
**Output:** `<project>/threatforest/enriched/`

#### 🛡️ Mitigation Mapping
Adds security controls to enriched trees:

**Input:** Enriched attack trees from TTP Enrichment

**Process:**
1. Reads enriched attack trees
2. Identifies applicable security controls
3. Adds mitigation strategies for each technique
4. Provides implementation guidance

**Input:** `<project>/threatforest/enriched/`
**Output:** `<project>/threatforest/mitigated/`

### Input Files

ThreatForest is flexible and works with various input combinations. Threat models are recommended but not required - ThreatForest can generate threats using AI analysis.

#### Threat Models (Recommended)

**ThreatComposer Workspace Files ⭐ RECOMMENDED**
- **Create at**: https://awslabs.github.io/threat-composer/
- **File patterns**: `*.tc`, `*ThreatComposer*.json`
- **Best for**: Comprehensive threat modeling with priorities
- **Contains**: Threat statements, priorities, application context

**How to create:**
1. Visit https://awslabs.github.io/threat-composer/
2. Create workspace with application details
3. Add threat statements with High/Medium/Low priorities
4. Export workspace as `.tc` file
5. Place in project directory

**Custom Threat Model Files**
- **Files**: `threats.json`, `security.yaml`, `threat-model.md`
- **Format**: JSON/YAML/Markdown

#### Documentation Files

ThreatForest uses the Strands framework's advanced `file_read` tool for intelligent document processing with automatic format detection, content extraction, and semantic analysis.

**README and Markdown Files**
- **Files**: `README.md`, `ARCHITECTURE.md`, `*.md`, PDF
- **Processing**: Strands `file_read` tool automatically extracts and analyzes content
- **Should include**:
  - Application description and purpose
  - Technology stack and dependencies
  - Architecture overview
  - Security considerations

**Architecture Diagrams**
- **Formats**: `*.png`, `*.pdf`, `*.jpg`, `*.jpeg`, `*.drawio`, `*.mmd`, `*.puml`
- **Should show**:
  - System components and services
  - Data flows and boundaries
  - Network topology
  - External dependencies

### Output Structure

ThreatForest creates a comprehensive output directory structure:

```
project/
└── threatforest/
    ├── attack_trees/                          # Full Analysis output
    │   ├── .threatforest_state.json          # State tracking
    │   ├── attack_tree_T001_sql_injection.md # Individual attack trees
    │   ├── attack_tree_T002_xss_attack.md
    │   ├── attack_trees_dashboard.html       # Interactive visualization
    │   ├── threatforest_data.json            # JSON export
    │   └── threatforest_analysis_report.md   # Summary report
    │
    ├── enriched/                              # TTP Enrichment output
    │   ├── enriched_attack_tree_T001.md      # TTP-enriched trees
    │   └── enriched_attack_tree_T002.md
    │
    └── mitigated/                             # Mitigation Mapping output
        ├── mitigated_enriched_attack_tree_T001.md  # With mitigations
        └── mitigated_enriched_attack_tree_T002.md
```

#### Interactive Dashboard (`attack_trees_dashboard.html`) ⭐ PRIMARY OUTPUT

The HTML dashboard is the **recommended way to review and explore your attack trees**. It provides an interactive, visual experience that makes understanding complex attack paths intuitive and engaging.

**Features:**
- **Visual Network Graph**: See all attack trees and their relationships at a glance
- **Interactive Node Exploration**: Click nodes to view detailed threat information, attack steps, and MITRE ATT&CK mappings
- **Dynamic Filtering**: Filter by threat severity, MITRE techniques, or attack complexity
- **Search Capabilities**: Quickly find specific threats or attack patterns
- **Zoom and Pan**: Navigate large attack trees with smooth controls
- **Export Options**: Save views or share with team members
- **Real-time Updates**: Automatically refreshes when new analysis completes

**Why Use the Dashboard:**
- 🎯 **Faster Analysis**: Visualize relationships between threats instantly
- 🔍 **Better Understanding**: Interactive exploration reveals attack path dependencies
- 📊 **Executive Presentations**: Professional visualizations for stakeholder reviews
- 🔗 **Connected Intelligence**: See how different threats relate to each other
- 💡 **Pattern Recognition**: Identify common attack vectors across your application

**Opening the Dashboard:**
```bash
# Automatically opens after analysis completes (Kiro integration)
# Or manually open:
open project/threatforest/attack_trees/attack_trees_dashboard.html
```

#### Other Output Files

**Attack Tree Markdown** (`attack_tree_*.md`) - Individual files for version control and detailed review
**JSON Export** (`threatforest_data.json`) - Structured data for programmatic access and tool integration
**Analysis Report** (`threatforest_analysis_report.md`) - Executive summary and statistics

## 🔌 IDE Integration

### Kiro IDE Integration

ThreatForest seamlessly integrates with [Kiro IDE](https://kiro.dev) to provide automatic threat analysis whenever you save ThreatComposer files. This enables a live threat modeling workflow where you can iterate on threats and immediately see the generated attack trees.

#### Why Use Kiro Integration?

- **⚡ Instant Feedback**: See attack trees generated within seconds of saving your threat model
- **🔄 Iterative Workflow**: Refine threats and immediately see updated analysis
- **🎯 Zero Context Switching**: Stay in your IDE while ThreatForest runs in the background
- **📊 Automatic Dashboard**: Interactive visualization updates automatically
- **💾 Version Control Friendly**: All outputs are saved in your project directory

#### Setup Instructions

##### Step 1: Install Kiro IDE

Download and install Kiro IDE from [kiro.dev](https://kiro.dev)

##### Step 2: Open Your Project in Kiro

```bash
# Open your project directory in Kiro IDE
kiro /path/to/your/project
```

##### Step 3: Create the Hook Configuration

**Option A: Using Kiro UI (Recommended)**

1. Open Kiro IDE
2. Open Command Palette (`Cmd+Shift+P` on Mac, `Ctrl+Shift+P` on Windows/Linux)
3. Search for "Open Kiro Hook UI"
4. Click "Create New Hook"
5. Fill in the following details:

   - **Name**: `ThreatForest Analysis`
   - **Description**: `Automatically analyze ThreatComposer files on save`
   - **Trigger**: Select "File Edited"
   - **File Pattern**: `**/*.tc.json`
   - **Action**: Select "Ask Agent"
   - **Prompt**: 
     ```
     execute the following script on the file that was just saved /absolute/path/to/ThreatForest/src/threatforest/modules/utils/kiro_wrapper.sh {file}
     ```
     
     **Important**: Replace `/absolute/path/to/ThreatForest` with your actual ThreatForest installation path

6. Click "Save Hook"
7. Ensure the hook is **Enabled** (toggle should be green)

**Option B: Manual Configuration**

Create a file at `.kiro/hooks/threatforest-analysis.kiro.hook` in your project:

```json
{
  "enabled": true,
  "name": "ThreatForest Analysis",
  "description": "Automatically analyze ThreatComposer files on save",
  "version": "1",
  "when": {
    "type": "fileEdited",
    "patterns": [
      "**/*.tc.json"
    ]
  },
  "then": {
    "type": "askAgent",
    "prompt": "execute the following script on the file that was just saved /absolute/path/to/ThreatForest/src/threatforest/modules/utils/kiro_wrapper.sh {file}"
  },
  "shortName": "threatforest-analysis",
  "workspaceFolderName": "your-project-name"
}
```

**Important**: Update these values:
- Replace `/absolute/path/to/ThreatForest` with your ThreatForest installation path
- Replace `your-project-name` with your actual project folder name

##### Step 4: Configure ThreatForest

Ensure your `config.yaml` has the correct settings:

```yaml
# Model configuration (required)
bedrock:
  enabled: true
  model_id: "anthropic.claude-3-sonnet-20240229-v1:0"
  region: "us-east-1"

# AWS configuration
aws:
  default_profile: "default"
  default_region: "us-east-1"

# Kiro integration (optional - for additional features)
kiro_integration:
  enabled: true
  auto_run_on_save: true
```

##### Step 5: Test the Integration

1. Open a ThreatComposer file (`.tc.json`) in Kiro IDE
2. Make a change (e.g., add a new threat or update priority)
3. Save the file (`Cmd+S` or `Ctrl+S`)
4. Watch Kiro's agent panel - you should see:
   ```
   ✓ Using virtual environment: venv
   ThreatForest Kiro Hook
   🔍 ThreatForest Analysis Triggered
   📁 File: your-file.tc.json
   🚀 Starting ThreatForest analysis...
   ```
5. Wait for completion (typically 60-120 seconds)
6. Check output directory: `your-project/threatforest/attack_trees/`

#### Workflow Example

Here's a typical workflow using Kiro integration:

```bash
# 1. Create or edit threat model in ThreatComposer
# Visit https://awslabs.github.io/threat-composer/
# Export as MyApp.tc.json

# 2. Open project in Kiro IDE
kiro /path/to/my-project

# 3. Copy ThreatComposer file to project
cp ~/Downloads/MyApp.tc.json /path/to/my-project/

# 4. Open file in Kiro and make edits
# - Add new threats
# - Update priorities
# - Refine descriptions

# 5. Save file (Cmd+S)
# ThreatForest automatically runs!

# 6. View results
open my-project/threatforest/attack_trees/attack_trees_dashboard.html
```

#### Troubleshooting Kiro Integration

##### Hook Not Triggering

**Check hook is enabled:**
```bash
# View hook status in Kiro
# Open Command Palette → "List Agent Hooks"
```

**Verify file pattern matches:**
- Hook pattern: `**/*.tc.json`
- Your file must end with `.tc.json`
- Try renaming: `threats.json` → `threats.tc.json`

**Check Kiro logs:**
```bash
# View Kiro output panel
# Look for hook execution messages
```

##### Script Path Issues

**Error: "Script not found"**

Solution: Use absolute path in hook configuration:
```json
{
  "prompt": "execute the following script on the file that was just saved /Users/yourname/ThreatForest/src/threatforest/modules/utils/kiro_wrapper.sh {file}"
}
```

**Find your ThreatForest path:**
```bash
cd /path/to/ThreatForest
pwd
# Copy this absolute path
```

##### Virtual Environment Issues

**Error: "venv not found"**

Solution: Ensure virtual environment exists:
```bash
cd /path/to/ThreatForest
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The wrapper script automatically activates the venv, but it must exist first.

##### AWS Credentials Issues

**Error: "Bedrock access failed"**

Solution: Configure AWS credentials:
```bash
# Set AWS profile
export AWS_PROFILE=default

# Or configure credentials
aws configure

# Test Bedrock access
aws bedrock list-foundation-models --region us-east-1
```

##### Permission Issues

**Error: "Permission denied"**

Solution: Make wrapper script executable:
```bash
chmod +x /path/to/ThreatForest/src/threatforest/modules/utils/kiro_wrapper.sh
```

#### Benefits Summary

| Feature | Without Kiro | With Kiro Integration |
|---------|--------------|----------------------|
| **Trigger** | Manual CLI command | Automatic on save |
| **Feedback** | Terminal output | IDE notifications |
| **Context Switching** | Leave IDE to run CLI | Stay in IDE |
| **Iteration Speed** | Slow (manual steps) | Fast (instant) |
| **Dashboard Access** | Manual open | Auto-generated |
| **Version Control** | Manual commit | Automatic tracking |

## 🔒 Data Privacy Considerations

### What Data is Sent to LLM Providers

When you run ThreatForest, the following data is sent to your chosen LLM provider (AWS Bedrock, Anthropic, OpenAI, etc.):

- **Application details**: Name, description, technology stack
- **Architecture information**: System components, data flows, trust boundaries
- **Threat statements**: Identified threats and their descriptions
- **Documentation content**: README files, architecture documents
- **Diagram descriptions**: Analysis of uploaded architecture diagrams

### What This Means

- **OpenAI, Anthropic, Google, etc.** may log this data per their privacy policies
- **AWS Bedrock** follows AWS data handling policies
- **Local models (Ollama)** keep all data on your machine

### Best Practices

1. **For Demonstrations**: Use generic or fictional system details
2. **For Sensitive Systems**: 
   - Use local models (Ollama)
   - Use providers with stricter privacy guarantees
   - Sanitize system descriptions before input
3. **Review Policies**: Check your LLM provider's data retention and privacy policies
4. **Consider Compliance**: Ensure your usage meets organizational data handling requirements

### Local Deployment Options

For maximum privacy, ThreatForest supports local LLM deployment:

```yaml
# config.yaml
ollama:
  enabled: true
  base_url: "http://localhost:11434"
  model_id: "llama3:70b"
```

## 🔧 Advanced Usage

### Command Line Options

```bash
# Full workflow with specific project
threatforest --project-path /path/to/project

# TTP enrichment only
threatforest --mode enrich \
  --input-dir ./threatforest/attack_trees \
  --output-dir ./threatforest/enriched

# Mitigation mapping only
threatforest --mode mitigate \
  --input-dir ./threatforest/enriched \
  --output-dir ./threatforest/mitigated
```

### Multiple AI Provider Support

ThreatForest supports multiple AI providers:

- **AWS Bedrock** (Claude, Llama, etc.)
- **Anthropic** (Claude 3/4)
- **OpenAI** (GPT-4, GPT-4o)
- **Google Gemini**
- **Ollama** (Local LLMs)
- **LiteLLM** (Multi-provider proxy)
- **LlamaAPI**
- **AWS SageMaker** (Custom endpoints)

Configure your preferred provider in `config.yaml`.

### Configuration

ThreatForest uses a YAML configuration file for settings:

```yaml
# Model Provider Configuration
bedrock:
  enabled: true
  model_id: "anthropic.claude-3-sonnet-20240229-v1:0"
  region: "us-east-1"

# Alternative: Anthropic Direct
anthropic:
  enabled: false
  model_id: "claude-3-sonnet-20240229"
  api_key: "${ANTHROPIC_API_KEY}"

# Alternative: OpenAI
openai:
  enabled: false
  model_id: "gpt-4-turbo-preview"
  api_key: "${OPENAI_API_KEY}"

# Alternative: Local Ollama
ollama:
  enabled: false
  base_url: "http://localhost:11434"
  model_id: "llama3:70b"

# Embeddings Configuration
embeddings:
  model: "cisco-ai/SecureBERT2.0-biencoder"
  graph_file: "data/graphs/mitre_attack_graph.json"
  ttc_threshold: 0.3

# AWS Configuration
aws:
  default_profile: "default"
  default_region: "us-east-1"
```

## 🛠️ Troubleshooting

### Common Issues

#### "No threat models found"
**Solution**: Add a ThreatComposer export or create `threats.json` in your project directory. ThreatForest can also generate threats from documentation alone.

#### "Bedrock access failed"
**Solution**: 
1. Check AWS credentials: `aws sts get-caller-identity`
2. Verify Bedrock permissions in us-east-1
3. Request Bedrock model access in AWS Console

#### "externally-managed-environment"
**Solution**: Always use virtual environment or pipx/uv:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Virtual Environment Issues
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Getting Help

- Check AWS credentials: `aws configure list`
- Test Bedrock access: `aws bedrock list-foundation-models --region us-east-1`
- Review logs: `./output/threatforest.log`
- Open an issue: https://github.com/YOUR-ORG/ThreatForest/issues

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Format code
black src/
isort src/

# Run security scans
bandit -r src/
```

## 🔒 Security

ThreatForest follows security best practices:

- ✅ No data storage - all processing is ephemeral
- ✅ Automated security scanning (Bandit, Semgrep, ASH)
- ✅ Dependency vulnerability monitoring (Dependabot)
- ✅ Regular security audits
- ✅ Secure credential handling

**Security Report**: See [SECURITY.md](SECURITY.md) for our security policy.

**Reporting Issues**: Found a security issue? Please report it responsibly via GitHub Security Advisories.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **AWS Labs Strands** - Powerful agentic framework for orchestrating AI workflows
- **AWS ThreatComposer** - Excellent threat modeling tool and inspiration
- **MITRE ATT&CK** - Comprehensive threat intelligence framework
- **STRIDE GPT** - Inspiration for AI-powered threat modeling
- **AWS Bedrock** - Powerful LLM infrastructure
- **vis-network** - Interactive graph visualization

---

**Ready to start?** Follow the [Quick Start](#-quick-start) guide and run your first threat analysis!

For questions, issues, or feature requests, please visit our [GitHub repository](https://github.com/YOUR-ORG/ThreatForest).
