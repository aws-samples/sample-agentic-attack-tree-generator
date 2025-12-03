# 🌳 ThreatForest

<div align="center">

<img src="docs/assets/threatforest-logo.png" alt="ThreatForest Logo" width="200"/>

**AI-Driven Threat Modeling & Attack Tree Generation with MITRE ATT&CK Integration**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[Documentation](https://aws-samples.github.io/sample-agentic-attack-tree-generator) • [Getting Started](#-quick-start) • [Examples](sample-applications/) • [Contributing](CONTRIBUTING.md)

</div>

---

## 🎯 Overview

ThreatForest is an AI-powered threat modeling platform built on AWS Labs' [Strands](https://github.com/awslabs/strands) framework. It automatically generates comprehensive attack trees from your project documentation and threat models, mapping them to MITRE ATT&CK techniques with actionable mitigation strategies.

**Key Features:**

- 🤖 Autonomous AI agents explore and analyze your project
- 🌳 Generate detailed attack trees with multiple attack paths
- 🎯 Automatic MITRE ATT&CK technique mapping
- 📊 Interactive HTML dashboards for visualization
- 🔄 Seamless IDE integration with Kiro

📖 **[Read Full Documentation](https://aws-samples.github.io/sample-agentic-attack-tree-generator)**

## 🚀 Quick Start

```bash
# Install with pipx (recommended)
pipx install git+https://github.com/aws-samples/sample-agentic-attack-tree-generator.git

# Run the interactive wizard
threatforest
```

**Prerequisites:** Python 3.11+, AWS Bedrock access (or other LLM provider)

📚 **[Complete Installation Guide](docs/getting-started/index.md)**

## 📊 What You Get

```
project/threatforest/attack_trees/
├── attack_trees_dashboard.html          # Interactive visualization ⭐
├── attack_tree_T001_sql_injection.md   # Individual attack trees
├── threatforest_data.json               # Structured data export
└── threatforest_analysis_report.md      # Executive summary
```

🎨 **[Explore Example Outputs](docs/examples)** | 📊 **[Understanding Results](docs/user-guide/understanding-results.md)**

## 📚 Documentation

### Core Guides

- **[Getting Started](docs/getting-started/index.md)** - Installation and first analysis
- **[Preparing Your Project](docs/user-guide/preparing-your-project.md)** - Input files and best practices
- **[Running ThreatForest](docs/user-guide/running-threatforest.md)** - Using the interactive wizard
- **[Understanding Results](docs/user-guide/understanding-results.md)** - Exploring outputs and dashboards
- **[How It Works](docs/how-it-works/index.md)** - Technical deep dive

### Workflow Modes

ThreatForest supports three workflow modes:

1. **🌳 Full Analysis** - Complete threat analysis from project documentation
2. **🎯 TTP Enrichment** - Add MITRE ATT&CK mappings to existing attack trees
3. **🛡️ Mitigation Mapping** - Add security controls and implementation guidance

**[Learn More About Workflows](docs/how-it-works/phases.md)**

### Input Files

ThreatForest works with various input combinations:

- **ThreatComposer Files** (`.tc.json`) - ⭐ Recommended, create at [threat-composer](https://awslabs.github.io/threat-composer/)
- **Documentation** - README, architecture docs, diagrams (PNG, PDF, Mermaid, etc.)
- **Custom Threat Models** - JSON, YAML, or Markdown formats

**Note:** Threat models are recommended but not required - ThreatForest can generate threats using AI analysis.

**[Input Files Guide](docs/user-guide/preparing-your-project.md)**

## 🔌 IDE Integration

### Kiro IDE Integration

ThreatForest integrates with [Kiro IDE](https://kiro.dev) for automatic threat analysis on file save:

- ⚡ Instant feedback when saving ThreatComposer files
- 🔄 Iterative workflow without context switching
- 📊 Automatic dashboard updates
- 💾 Version control friendly

**[Setup Kiro Integration](docs/getting-started/index.md#kiro-ide-integration)**

## 🔒 Data Privacy

ThreatForest sends application details, architecture information, and threat statements to your chosen LLM provider. Consider:

- **AWS Bedrock** - Enterprise data handling policies
- **Ollama** - Complete privacy (local deployment)
- **Other Providers** - Review their data retention policies

For maximum privacy, use local models with Ollama.

**[Data Privacy Guide](docs/getting-started/index.md#data-privacy-considerations)**

## 🔧 Advanced Usage

### Multiple AI Provider Support

ThreatForest supports:

- AWS Bedrock (Claude, Llama, etc.)
- Anthropic (Claude 3/4)
- OpenAI (GPT-4, GPT-4o)
- Google Gemini
- Ollama (Local LLMs)
- LiteLLM, LlamaAPI, AWS SageMaker

**[Multi-Provider Configuration](docs/advanced/multi-provider.md)**

## 🛠️ Troubleshooting

Common issues and solutions:

- **"No threat models found"** - Add ThreatComposer file or documentation (ThreatForest can generate threats)
- **"Bedrock access failed"** - Check AWS credentials and permissions
- **"externally-managed-environment"** - Use virtual environment or pipx
- **Slow first run** - Normal! Downloads models (~500MB) and libraries

**[Full Troubleshooting Guide](docs/faq.md#troubleshooting)**

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 🔒 Security

ThreatForest follows security best practices:

- ✅ No data storage - all processing is ephemeral
- ✅ Automated security scanning (Bandit, Semgrep, ASH)
- ✅ Dependency vulnerability monitoring (Dependabot)
- ✅ Regular security audits
- ✅ Secure credential handling

**Security Report:** See [SECURITY.md](SECURITY.md) for our security policy.

**Reporting Issues:** Found a security issue? Please report it responsibly via GitHub Security Advisories.

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

For questions, issues, or feature requests, please visit our [GitHub repository](https://github.com/aws-samples/sample-agentic-attack-tree-generator).
