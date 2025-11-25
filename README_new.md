# 🌳 ThreatForest

<div align="center">

**AI-Driven Threat Modeling & Attack Tree Generation with MITRE ATT&CK Integration**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-examples) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

ThreatForest is an intelligent threat modeling platform that combines AI-powered analysis with MITRE ATT&CK framework integration. It automatically generates comprehensive attack trees from your project documentation, threat models, and architecture diagrams.

### Why ThreatForest?

- 🤖 **AI-Powered Analysis** - Leverages large language models to understand your application
- 🌳 **Attack Tree Generation** - Automatically creates detailed attack trees for identified threats
- 🎯 **MITRE ATT&CK Integration** - Maps attack paths to TTC (Tactics, Techniques, and Common Knowledge) 
- 🛡️ **Mitigation Recommendations** - Provides actionable security controls
- 📊 **Interactive Dashboards** - Visualize threats and attack paths
- 🔄 **Multi-Provider Support** - Works with AWS Bedrock, Anthropic, OpenAI, Gemini, Ollama, and more

## ✨ Features

### Core Capabilities

- **Intelligent Context Analysis** - Discovers and analyzes threat models, diagrams, and documentation
- **Automated Threat Extraction** - Identifies and categorizes security threats using AI
- **Attack Tree Generation** - Creates detailed attack trees with multiple paths and prerequisites
- **TTC Technique Mapping** - Maps attacks to MITRE ATT&CK techniques with similarity scoring
- **Mitigation Mapping** - Recommends security controls for each identified technique
- **Visual Dashboards** - Interactive HTML dashboards with network graphs

### Supported Input Formats

- 📋 **Threat Models**: ThreatComposer (.tc), JSON, YAML, Markdown
- 🏗️ **Diagrams**: PNG, JPG, PDF, Mermaid (.mmd), Draw.io, PlantUML
- 📖 **Documentation**: Markdown, Text files

### Flexible Workflows

1. **🌳 Full Analysis** - Complete threat modeling pipeline
2. **🎯 TTC Enrichment** - Add MITRE ATT&CK mappings to existing trees
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
     model_id: "us.anthropic.claude-haiku-4-5-20251001-v1:0"
   
   # Or Anthropic Direct
   # anthropic:
   #   model_id: "claude-sonnet-4-20250514"
   ```

### Running ThreatForest

After installation, simply run:

```bash
threatforest
```

The interactive wizard will guide you through:
1. Select your workflow mode
2. Specify your project path
3. Optionally provide a threat model file
4. Let ThreatForest analyze and generate attack trees!

> **Note:** First run will be slower as it downloads AI model dependencies (sentence-transformers, torch). Subsequent runs are much faster.

## 📚 Documentation

### Workflow Modes

#### 🌳 Full Analysis
Analyzes your entire project and generates attack trees:
- Discovers threat models, diagrams, and documentation
- Extracts threats using AI (or from existing threat models)
- Generates attack trees for high-priority threats
- **Output**: `<project>/threatforest/attack_trees/`

#### 🎯 TTC Enrichment  
Enriches existing attack trees with MITRE ATT&CK techniques:
- Maps attack paths to TTC techniques
- Adds technique IDs and descriptions
- **Input**: `<project>/threatforest/attack_trees/`
- **Output**: `<project>/threatforest/enriched/`

#### 🛡️ Mitigation Mapping
Adds security controls to enriched trees:
- Recommends mitigations for each technique
- Provides actionable security recommendations
- **Input**: `<project>/threatforest/enriched/`
- **Output**: `<project>/threatforest/mitigated/`

### Creating Threat Models

#### Option 1: ThreatComposer (Recommended)

1. Visit [AWS ThreatComposer](https://awslabs.github.io/threat-composer/)
2. Create a workspace with your application details
3. Add threat statements with priorities (High/Medium/Low)
4. Export workspace as `.tc` file
5. Place in your project directory

#### Option 2: Custom JSON Format

```json
{
  "application_info": {
    "name": "My Application",
    "technologies": ["Node.js", "PostgreSQL", "AWS"]
  },
  "threats": [
    {
      "id": "T001",
      "statement": "Attacker could perform SQL injection",
      "priority": "high",
      "category": "injection"
    }
  ]
}
```

### Project Structure

```
your-project/
├── README.md
├── architecture-diagram.png
├── ThreatComposer_Workspace.tc      # Optional threat model
└── threatforest/                    # Generated by ThreatForest
    ├── attack_trees/
    │   ├── attack_tree_T001.md
    │   ├── attack_trees_dashboard.html
    │   └── ...
    ├── enriched/
    │   └── enriched_attack_tree_T001.md
    └── mitigated/
        └── mitigated_enriched_attack_tree_T001.md
```

## 🎨 Examples

### Example Output

```markdown
# Attack Tree: T001 - SQL Injection

## 🎯 Threat Statement
Attacker exploits SQL injection vulnerability to access sensitive customer data

## 🌳 Attack Tree

### Path 1: Direct SQL Injection
1. Identify vulnerable input field
2. Craft malicious SQL payload
3. Bypass input validation
4. Extract database contents

### Path 2: Blind SQL Injection
1. Test for SQL injection vulnerability
2. Use time-based techniques
3. Extract data character by character
4. Exfiltrate sensitive information

## 🎯 MITRE ATT&CK Mappings
- **T1190** - Exploit Public-Facing Application
- **T1213** - Data from Information Repositories

## 🛡️ Recommended Mitigations
- Input validation and sanitization
- Parameterized queries
- Least privilege database access
- Web Application Firewall (WAF)
```

## 🔧 Advanced Usage

### Command Line Options

```bash
# Full workflow with specific project
threatforest --project-path /path/to/project

# TTC enrichment only
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

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/YOUR-ORG/ThreatForest.git
cd ThreatForest

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/
isort src/
```

## 🔒 Security

Found a security vulnerability? Please see our [Security Policy](SECURITY.md) for responsible disclosure.

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) for the threat intelligence framework
- [AWS ThreatComposer](https://awslabs.github.io/threat-composer/) for threat modeling capabilities
- [Strands](https://strandsagents.com/) for the agent framework

## 📞 Support

- 📖 [Documentation](https://github.com/YOUR-ORG/ThreatForest#readme)
- 🐛 [Issue Tracker](https://github.com/YOUR-ORG/ThreatForest/issues)
- 💬 [Discussions](https://github.com/YOUR-ORG/ThreatForest/discussions)
